#!/usr/bin/env python3
"""
Log to Sketch-ADV Binary Converter

Converts detector .log files to SKAV .bin format (528 bytes per record)
so they can be used with the sketch_adv_model training pipeline.

Parses 64 features from each detection window:
  - 14 global sketch features (Ring Buffer + OctoSketch multi-scale)
  - 48 per-protocol features (4 metrics x 12 protocols) from [SKETCH-ADV PER-PROTOCOL FEATURES]
  - 2 packet size features (avg_packet_size, packet_size_variance)

If the log does NOT contain [SKETCH-ADV PER-PROTOCOL FEATURES], those 50 features are set to 0.

Binary output format (528 bytes, little-endian):
  uint32  magic          = 0x534B4156 ("SKAV")
  uint32  version        = 1
  uint64  timestamp_ns   = window_index * 5_000_000_000 (5s per window)
  double[14]  global sketch features
  double[12]  pps_proto[12]
  double[12]  heavy_hitters_proto[12]
  double[12]  ip_concentration_proto[12]
  double[12]  ratio_vs_total_proto[12]
  double      avg_packet_size
  double      packet_size_variance

Usage:
    python3 log_to_sketch_bin.py \
        --input-dir /local/dpdk_100g/mira/ml_system/datasets/raw_logs/2 \
        --output-dir /local/dpdk_100g/mira/ml_system/datasets/sketches \
        --pattern "mixed_traffic_run*.log"

    python3 log_to_sketch_bin.py \
        --input /local/dpdk_100g/mira/ml_system/datasets/raw_logs/2/mixed_traffic_run1.log \
        --output /local/dpdk_100g/mira/ml_system/datasets/sketches/mixed_sketch_adv_run1.bin
"""

import argparse
import glob
import math
import re
import struct
import sys
from pathlib import Path

# Binary format constants (must match bin_to_csv.py / C struct)
RECORD_MAGIC = 0x534B4156  # "SKAV"
RECORD_VERSION = 1
RECORD_SIZE = 528
RECORD_FMT = '<IIQ64d'
assert struct.calcsize(RECORD_FMT) == RECORD_SIZE

WINDOW_INTERVAL_NS = 5_000_000_000  # 5 seconds per detection window

# Protocol order (must match C code and feature_groups.py)
PROTOCOLS = [
    'dns', 'ntp', 'snmp', 'ssdp', 'portmap', 'netbios',
    'ldap', 'mssql', 'tftp', 'syn', 'http', 'udp_other',
]

# Display name -> feature name mapping for log parsing
PROTO_DISPLAY_MAP = {
    'DNS':       'dns',
    'NTP':       'ntp',
    'SNMP':      'snmp',
    'SSDP':      'ssdp',
    'PortMap':   'portmap',
    'NetBIOS':   'netbios',
    'LDAP':      'ldap',
    'MSSQL':     'mssql',
    'TFTP':      'tftp',
    'SYN':       'syn',
    'HTTP':      'http',
    'UDP-Other': 'udp_other',
}

MIXED_MIN_SHARE = 0.10


def extract_global_sketch_features(window_text):
    """Extract 14 global sketch features from a detection window.

    Returns list of 14 floats in the order matching the binary format,
    or None if the window is invalid.
    """

    # Check window is valid
    match = re.search(r'Total packets:\s+(\d+)', window_text)
    if not match:
        return None

    features = {}

    # --- Ring Buffer temporal features (5) ---
    m = re.search(r'Delta PPS \(250ms\):\s+([+-]?[\d.]+)', window_text)
    features['delta_pps_5w'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Delta PPS \(500ms\):\s+([+-]?[\d.]+)', window_text)
    features['delta_pps_10w'] = float(m.group(1)) if m else 0.0

    m = re.search(r'PPS Variance:\s+([\d.]+)', window_text)
    features['pps_variance'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Running baseline \(ML\):\s+([\d.]+) pps', window_text)
    features['pps_baseline'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Ratio vs Baseline:\s+([\d.]+)x', window_text)
    features['ratio_vs_baseline'] = float(m.group(1)) if m else 1.0

    # --- OctoSketch multi-scale features (9) ---
    m = re.search(r'Top IP \(50ms\):\s+([\d.]+) pps', window_text)
    features['top_ip_pps_50ms'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Top IP \(1s\):\s+([\d.]+) pps', window_text)
    features['top_ip_pps_1s'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Top IP \(1min\):\s+([\d.]+) pps', window_text)
    features['top_ip_pps_1min'] = float(m.group(1)) if m else 0.0

    m = re.search(r'Burst Ratio \(50ms/1min\):\s+([\d.]+)x', window_text)
    features['ratio_50ms_1min'] = float(m.group(1)) if m else 1.0

    m = re.search(r'Heavy-hitters detected:\s+(\d+)', window_text)
    features['num_heavy_hitters'] = float(int(m.group(1))) if m else 0.0

    m = re.search(r'IP Concentration:\s+([\d.]+)%', window_text)
    features['ip_concentration'] = float(m.group(1)) / 100.0 if m else 0.0

    # new_ips_ratio and attack_entropy: derived from DPI counters
    # Extract DPI counters for derivation
    ntp_monlist = _extract_int(r'Monlist queries:\s+(\d+)', window_text)
    dns_any = _extract_int(r'ANY queries:\s+(\d+)', window_text)
    dns_txt = _extract_int(r'TXT queries:\s+(\d+)', window_text)
    snmp_getbulk = _extract_int(r'GetBulk requests:\s+(\d+)', window_text)
    ssdp_msearch = _extract_int(r'M-SEARCH packets:\s+(\d+)', window_text)
    portmap_getport = _extract_int(r'GETPORT calls:\s+(\d+)', window_text)
    netbios_name = _extract_int(r'Name queries:\s+(\d+)', window_text)
    ldap_search = _extract_int(r'Search requests:\s+(\d+)', window_text)
    mssql_sqlbatch = _extract_int(r'SQLBatch packets:\s+(\d+)', window_text)
    tftp_rrq = _extract_int(r'RRQ \(read\) pkts:\s+(\d+)', window_text)
    syn_packets = _extract_int(r'SYN packets:\s+(\d+)', window_text)
    http_requests = _extract_int(r'HTTP requests:\s+(\d+)', window_text)

    attack_signals = {
        'ntp': ntp_monlist, 'dns': dns_any + dns_txt, 'snmp': snmp_getbulk,
        'ssdp': ssdp_msearch, 'portmap': portmap_getport, 'netbios': netbios_name,
        'ldap': ldap_search, 'mssql': mssql_sqlbatch, 'tftp': tftp_rrq,
        'syn': syn_packets, 'web': http_requests,
    }

    total_signal = sum(float(v) for v in attack_signals.values() if v > 0)
    if total_signal > 0:
        active_types = sum(
            (float(v) / total_signal) >= MIXED_MIN_SHARE
            for v in attack_signals.values()
        )
        entropy = 0.0
        for v in attack_signals.values():
            if v <= 0:
                continue
            p = float(v) / total_signal
            entropy -= p * math.log2(p)
        max_entropy = math.log2(len(attack_signals))
        features['attack_entropy'] = entropy / max_entropy if max_entropy > 0 else 0.0
        features['new_ips_ratio'] = active_types / float(len(attack_signals))
    else:
        features['attack_entropy'] = 0.0
        features['new_ips_ratio'] = 0.0

    features['adaptive_threshold'] = 0.0

    # Return in binary format order
    return [
        features['delta_pps_5w'],
        features['delta_pps_10w'],
        features['pps_variance'],
        features['pps_baseline'],
        features['ratio_vs_baseline'],
        features['top_ip_pps_50ms'],
        features['top_ip_pps_1s'],
        features['top_ip_pps_1min'],
        features['ratio_50ms_1min'],
        features['num_heavy_hitters'],
        features['ip_concentration'],
        features['new_ips_ratio'],
        features['attack_entropy'],
        features['adaptive_threshold'],
    ]


def extract_per_protocol_features(window_text):
    """Extract 50 per-protocol sketch features from [SKETCH-ADV PER-PROTOCOL FEATURES].

    Returns list of 50 floats (48 per-proto + 2 pkt size), or all zeros if section missing.
    Layout: pps[12], heavy_hitters[12], ip_concentration[12], ratio_vs_total[12], avg_pkt, pkt_var
    """
    section = re.search(
        r'\[SKETCH-ADV PER-PROTOCOL FEATURES\](.*)',
        window_text, re.DOTALL)

    per_proto = {}  # feat_name -> {proto: value}
    avg_packet_size = 0.0
    packet_size_variance = 0.0

    if section:
        adv_text = section.group(1)

        for display_name, feat_name in PROTO_DISPLAY_MAP.items():
            pattern = (re.escape(f'[{display_name}') + r'[^\]]*\]\s*'
                       r'PPS:\s+([\d.]+)\s*'
                       r'Heavy-hitters:\s+(\d+)\s*'
                       r'IP Concentration:\s+([\d.]+)%\s*'
                       r'Ratio vs Total:\s+([\d.]+)')
            m = re.search(pattern, adv_text)
            if m:
                per_proto[feat_name] = {
                    'pps': float(m.group(1)),
                    'heavy_hitters': float(int(m.group(2))),
                    'ip_concentration': float(m.group(3)) / 100.0,
                    'ratio_vs_total': float(m.group(4)),
                }
            else:
                per_proto[feat_name] = {
                    'pps': 0.0, 'heavy_hitters': 0.0,
                    'ip_concentration': 0.0, 'ratio_vs_total': 0.0,
                }

        m = re.search(r'Avg Packet Size:\s+([\d.]+)', adv_text)
        avg_packet_size = float(m.group(1)) if m else 0.0

        m = re.search(r'Packet Size Variance:\s+([\d.]+)', adv_text)
        packet_size_variance = float(m.group(1)) if m else 0.0
    else:
        for proto in PROTOCOLS:
            per_proto[proto] = {
                'pps': 0.0, 'heavy_hitters': 0.0,
                'ip_concentration': 0.0, 'ratio_vs_total': 0.0,
            }

    # Build in binary layout order: all pps[12], all hh[12], all conc[12], all ratio[12]
    result = []
    for feat_type in ['pps', 'heavy_hitters', 'ip_concentration', 'ratio_vs_total']:
        for proto in PROTOCOLS:
            result.append(per_proto[proto][feat_type])

    result.append(avg_packet_size)
    result.append(packet_size_variance)

    return result  # 50 values


def _extract_int(pattern, text):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else 0


def convert_log_to_bin(log_path, bin_path):
    """Convert a single .log file to SKAV .bin format."""
    print(f"\n[CONVERTING] {log_path}")
    print(f"         ->  {bin_path}")

    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    windows = re.split(r'\[PACKET COUNTERS - GLOBAL\]', content)
    print(f"  Detection windows found: {len(windows) - 1}")

    has_sketch_adv = '[SKETCH-ADV PER-PROTOCOL FEATURES]' in content
    if has_sketch_adv:
        print(f"  [OK] Log contains SKETCH-ADV per-protocol sections")
    else:
        print(f"  [WARNING] No SKETCH-ADV sections found, per-protocol features will be 0")

    records_written = 0
    records_skipped = 0

    Path(bin_path).parent.mkdir(parents=True, exist_ok=True)

    with open(bin_path, 'wb') as f_out:
        for idx, window in enumerate(windows[1:]):
            global_feats = extract_global_sketch_features(window)
            if global_feats is None:
                records_skipped += 1
                continue

            per_proto_feats = extract_per_protocol_features(window)

            # timestamp_ns: window index * 5 seconds
            timestamp_ns = idx * WINDOW_INTERVAL_NS

            # All 64 doubles: 14 global + 48 per-proto + 2 pkt size
            all_features = global_feats + per_proto_feats
            assert len(all_features) == 64, f"Expected 64 features, got {len(all_features)}"

            record = struct.pack(RECORD_FMT,
                                 RECORD_MAGIC,
                                 RECORD_VERSION,
                                 timestamp_ns,
                                 *all_features)

            f_out.write(record)
            records_written += 1

    file_size = Path(bin_path).stat().st_size
    print(f"  Records written: {records_written}")
    if records_skipped > 0:
        print(f"  Records skipped: {records_skipped}")
    print(f"  File size: {file_size} bytes ({file_size // RECORD_SIZE} x {RECORD_SIZE})")

    return records_written


def main():
    parser = argparse.ArgumentParser(
        description='Convert detector .log files to SKAV .bin for sketch-adv training',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file
  python3 log_to_sketch_bin.py \\
      --input /local/dpdk_100g/mira/ml_system/datasets/raw_logs/2/mixed_traffic_run1.log \\
      --output /local/dpdk_100g/mira/ml_system/datasets/sketches/mixed_sketch_adv_run1.bin

  # All files in a directory
  python3 log_to_sketch_bin.py \\
      --input-dir /local/dpdk_100g/mira/ml_system/datasets/raw_logs/2 \\
      --output-dir /local/dpdk_100g/mira/ml_system/datasets/sketches \\
      --pattern "*.log"
        """
    )

    parser.add_argument('--input', type=str, help='Single input .log file')
    parser.add_argument('--output', type=str, help='Single output .bin file')
    parser.add_argument('--input-dir', type=str, help='Input directory with .log files')
    parser.add_argument('--output-dir', type=str, help='Output directory for .bin files')
    parser.add_argument('--pattern', type=str, default='*.log',
                        help='Glob pattern for log files (default: *.log)')

    args = parser.parse_args()

    print("=" * 60)
    print("LOG TO SKETCH-ADV BINARY CONVERTER")
    print(f"  Output format: SKAV {RECORD_SIZE} bytes/record, 64 doubles")
    print("=" * 60)

    if args.input and args.output:
        # Single file mode
        if not Path(args.input).exists():
            print(f"[ERROR] Not found: {args.input}")
            sys.exit(1)
        n = convert_log_to_bin(args.input, args.output)
        if n == 0:
            print("[ERROR] No records converted")
            sys.exit(1)

    elif args.input_dir and args.output_dir:
        # Batch mode
        input_dir = Path(args.input_dir)
        output_dir = Path(args.output_dir)

        if not input_dir.exists():
            print(f"[ERROR] Input directory not found: {input_dir}")
            sys.exit(1)

        output_dir.mkdir(parents=True, exist_ok=True)

        log_files = sorted(input_dir.glob(args.pattern))
        if not log_files:
            print(f"[ERROR] No files matching '{args.pattern}' in {input_dir}")
            sys.exit(1)

        print(f"\n  Input:   {input_dir}")
        print(f"  Output:  {output_dir}")
        print(f"  Pattern: {args.pattern}")
        print(f"  Files:   {len(log_files)}")

        total_records = 0
        for log_file in log_files:
            # Infer output name: mixed_traffic_run1.log -> mixed_sketch_adv_run1.bin
            stem = log_file.stem
            # Replace _traffic_ or just use the stem
            if '_traffic_' in stem:
                bin_name = stem.replace('_traffic_', '_sketch_adv_') + '.bin'
            else:
                bin_name = stem + '_sketch_adv.bin'

            bin_path = output_dir / bin_name
            n = convert_log_to_bin(str(log_file), str(bin_path))
            total_records += n

        print(f"\n{'='*60}")
        print(f"[DONE] {len(log_files)} files converted, {total_records} total records")
        print(f"  Output: {output_dir}")

    else:
        parser.print_help()
        print("\n[ERROR] Specify either --input/--output or --input-dir/--output-dir")
        sys.exit(1)


if __name__ == '__main__':
    main()
