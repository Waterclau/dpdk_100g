#!/usr/bin/env python3
"""
Binary Sketch-ADV to CSV Converter

Reads binary .bin files produced by detector_system2 (--sketch-adv mode)
and converts them to CSV with labeling for ML training.

Binary record format (528 bytes, packed):
  - uint32  magic          (0x534B4156 = "SKAV")
  - uint32  version        (1)
  - uint64  timestamp_ns   (nanoseconds since detector start)
  - double[14]  global sketch features
  - double[12]  pps_proto
  - double[12]  heavy_hitters_proto
  - double[12]  ip_concentration_proto
  - double[12]  ratio_vs_total_proto
  - double  avg_packet_size
  - double  packet_size_variance

Labeling modes:
  --auto-label (recommended): Auto-detect attack boundaries from sketch features.
    Uses ratio_vs_baseline and per-protocol PPS spikes to find when attack
    traffic starts/ends. Equivalent to .log pipeline auto-label.

  Time-based (manual): Fixed timing with --baseline-before, --attack-duration,
    --baseline-after for experiments with known timing.

Usage:
    # Auto-label (recommended)
    python3 bin_to_csv.py --input /tmp/dns_run1.bin --output dns_run1.csv --attack-type dns --auto-label

    # Time-based
    python3 bin_to_csv.py --input /tmp/dns_run1.bin --output dns_run1.csv --attack-type dns \
        --baseline-before 70 --attack-duration 80 --baseline-after 60
"""

import argparse
import struct
import sys
import pandas as pd
import numpy as np
from pathlib import Path

# Must match C struct sketch_adv_record
RECORD_MAGIC = 0x534B4156  # "SKAV"
RECORD_VERSION = 1
RECORD_SIZE = 528  # bytes

# Struct format: little-endian, uint32 + uint32 + uint64 + 64 doubles
# 14 global + 12*4 per-protocol + 2 packet size = 64 doubles
RECORD_FMT = '<IIQ64d'
assert struct.calcsize(RECORD_FMT) == RECORD_SIZE

# Protocol order (must match C code and feature_groups.py)
PROTOCOLS = [
    'dns', 'ntp', 'snmp', 'ssdp', 'portmap', 'netbios',
    'ldap', 'mssql', 'tftp', 'syn', 'http', 'udp_other',
]

# 14 global feature names (order matches C struct)
GLOBAL_FEATURES = [
    'delta_pps_5w', 'delta_pps_10w', 'pps_variance',
    'pps_baseline', 'ratio_vs_baseline',
    'top_ip_pps_50ms', 'top_ip_pps_1s', 'top_ip_pps_1min',
    'ratio_50ms_1min', 'num_heavy_hitters', 'ip_concentration',
    'new_ips_ratio', 'attack_entropy', 'adaptive_threshold',
]

# Feature indices in the 64-double array
IDX_PPS_BASELINE = 3       # pps_baseline
IDX_RATIO_VS_BASELINE = 4  # ratio_vs_baseline
IDX_PPS_PROTO_START = 14   # pps_proto[0] = pps_dns

# Per-protocol feature types (4 per protocol)
PER_PROTO_TYPES = ['pps', 'heavy_hitters', 'ip_concentration', 'ratio_vs_total']


def build_column_names():
    """Build ordered column names matching binary record layout"""
    cols = list(GLOBAL_FEATURES)

    # C struct layout: pps_proto[12], then heavy_hitters[12], then concentration[12], then ratio[12]
    for feat_type in PER_PROTO_TYPES:
        for proto in PROTOCOLS:
            cols.append(f'{feat_type}_{proto}')

    cols.append('avg_packet_size')
    cols.append('packet_size_variance')

    return cols  # 14 + 48 + 2 = 64


def read_binary_file(bin_path):
    """Read all records from binary file, return list of (timestamp_ns, features[64])"""
    records = []

    with open(bin_path, 'rb') as f:
        data = f.read()

    num_records = len(data) // RECORD_SIZE
    remainder = len(data) % RECORD_SIZE

    if remainder != 0:
        print(f"[WARNING] File size ({len(data)}) not multiple of record size ({RECORD_SIZE})")
        print(f"[WARNING] {remainder} trailing bytes ignored")

    print(f"[INFO] File size: {len(data)} bytes")
    print(f"[INFO] Records found: {num_records}")

    errors = 0
    for i in range(num_records):
        offset = i * RECORD_SIZE
        chunk = data[offset:offset + RECORD_SIZE]
        values = struct.unpack(RECORD_FMT, chunk)

        magic = values[0]
        version = values[1]
        timestamp_ns = values[2]
        features = values[3:]  # 64 doubles

        if magic != RECORD_MAGIC:
            errors += 1
            if errors <= 3:
                print(f"[WARNING] Record {i}: bad magic 0x{magic:08X} (expected 0x{RECORD_MAGIC:08X})")
            continue

        if version != RECORD_VERSION:
            errors += 1
            if errors <= 3:
                print(f"[WARNING] Record {i}: version {version} (expected {RECORD_VERSION})")
            continue

        records.append((timestamp_ns, list(features)))

    if errors > 3:
        print(f"[WARNING] {errors} total bad records skipped")

    print(f"[INFO] Valid records: {len(records)}")
    return records


def auto_detect_boundaries(records, threshold_ratio=2.0, min_pps=100.0):
    """Auto-detect attack start/end from sketch features.

    Uses two signals:
      1. ratio_vs_baseline > threshold (global PPS spike vs running average)
      2. Sum of per-protocol PPS > min_pps (ensures real traffic, not noise)

    Equivalent to .log pipeline's auto-label using attack_packets ratio.

    Returns:
        (attack_start_sec, attack_end_sec) or (None, None) if no attack detected
    """
    attack_start = None
    attack_end = None

    for timestamp_ns, features in records:
        t_sec = timestamp_ns / 1e9
        ratio = features[IDX_RATIO_VS_BASELINE]
        pps_baseline = features[IDX_PPS_BASELINE]

        # Sum per-protocol PPS (12 values starting at index 14)
        total_proto_pps = sum(features[IDX_PPS_PROTO_START:IDX_PPS_PROTO_START + 12])

        # Attack detected when: significant PPS spike AND real traffic present
        is_attack = (ratio >= threshold_ratio and pps_baseline > min_pps) or \
                    (total_proto_pps > min_pps * 5)

        if is_attack:
            if attack_start is None:
                attack_start = t_sec
            attack_end = t_sec

    return attack_start, attack_end


def apply_auto_labels(records, attack_type, threshold_ratio=2.0, min_pps=100.0):
    """Apply auto-detected labels based on sketch feature analysis.

    Like .log pipeline: windows before attack_start = benign,
    during attack = attack_type, after attack_end = benign.
    """
    attack_start, attack_end = auto_detect_boundaries(
        records, threshold_ratio, min_pps
    )

    labeled = []
    stats = {'benign': 0, 'attack': 0}

    if attack_start is None:
        # No attack detected - all benign
        print(f"\n[AUTO-LABEL] No attack traffic detected, labeling all as benign")
        for timestamp_ns, features in records:
            labeled.append((features, 'benign'))
            stats['benign'] += 1
    else:
        print(f"\n[AUTO-LABEL] Attack detected: {attack_start:.1f}s - {attack_end:.1f}s "
              f"(duration: {attack_end - attack_start:.1f}s)")
        for timestamp_ns, features in records:
            t_sec = timestamp_ns / 1e9
            if t_sec < attack_start or t_sec > attack_end:
                label = 'benign'
                stats['benign'] += 1
            else:
                label = attack_type
                stats['attack'] += 1
            labeled.append((features, label))

    print(f"  Benign:  {stats['benign']}")
    print(f"  Attack:  {stats['attack']} ({attack_type})")

    return labeled


def apply_time_labels(records, attack_type, baseline_before, attack_duration, baseline_after):
    """Apply time-based labels to records"""
    attack_start_ns = baseline_before * 1_000_000_000
    attack_end_ns = (baseline_before + attack_duration) * 1_000_000_000
    total_ns = (baseline_before + attack_duration + baseline_after) * 1_000_000_000

    labeled = []
    stats = {'benign': 0, 'attack': 0, 'dropped': 0}

    for timestamp_ns, features in records:
        if timestamp_ns > total_ns:
            stats['dropped'] += 1
            continue

        if timestamp_ns < attack_start_ns:
            label = 'benign'
            stats['benign'] += 1
        elif timestamp_ns < attack_end_ns:
            label = attack_type
            stats['attack'] += 1
        else:
            label = 'benign'
            stats['benign'] += 1

        labeled.append((features, label))

    print(f"\n[LABELING] {baseline_before}s baseline -> "
          f"{attack_duration}s attack -> {baseline_after}s baseline")
    print(f"  Benign:  {stats['benign']}")
    print(f"  Attack:  {stats['attack']} ({attack_type})")
    if stats['dropped'] > 0:
        print(f"  Dropped: {stats['dropped']}")

    return labeled


def to_dataframe(labeled_records, column_names):
    """Convert labeled records to DataFrame"""
    rows = []
    for features, label in labeled_records:
        row = dict(zip(column_names, features))
        row['label'] = label
        rows.append(row)

    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser(
        description='Convert binary sketch-adv .bin to labeled CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-label (recommended - detects attack boundaries from sketch features)
  python3 bin_to_csv.py --input /tmp/dns_run1.bin --output dns_run1.csv --attack-type dns --auto-label

  # Benign-only file (auto-label detects no attack, labels all as benign)
  python3 bin_to_csv.py --input /tmp/benign_run1.bin --output benign_run1.csv --attack-type benign --auto-label

  # Time-based labeling
  python3 bin_to_csv.py --input /tmp/ntp.bin --output ntp.csv --attack-type ntp \\
      --baseline-before 70 --attack-duration 80 --baseline-after 60

Supported attack types:
  benign, dns, ntp, snmp, ssdp, portmap, netbios, ldap, mssql, tftp, syn, udp, webddos, mixed
        """
    )

    parser.add_argument('--input', required=True, help='Input binary .bin file')
    parser.add_argument('--output', required=True, help='Output CSV file')
    parser.add_argument('--attack-type', required=True,
                        help='Attack type label (benign for benign-only captures)')
    parser.add_argument('--auto-label', action='store_true',
                        help='Auto-detect attack boundaries from sketch features '
                             '(like .log pipeline auto-label)')
    parser.add_argument('--baseline-before', type=float, default=70.0,
                        help='Baseline before attack in seconds (default: 70)')
    parser.add_argument('--attack-duration', type=float, default=80.0,
                        help='Attack duration in seconds (default: 80)')
    parser.add_argument('--baseline-after', type=float, default=60.0,
                        help='Baseline after attack in seconds (default: 60)')

    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"[ERROR] Not found: {args.input}")
        sys.exit(1)

    print("=" * 60)
    print("SKETCH-ADV BINARY TO CSV CONVERTER")
    print("=" * 60)
    print(f"  Input:  {args.input}")
    print(f"  Output: {args.output}")
    print(f"  Attack: {args.attack_type}")
    if args.auto_label:
        print(f"  Mode:   AUTO-LABEL (detect attack from sketch features)")
    else:
        print(f"  Mode:   TIME-BASED ({args.baseline_before}s + {args.attack_duration}s + {args.baseline_after}s)")

    records = read_binary_file(args.input)
    if not records:
        print("[ERROR] No valid records")
        sys.exit(1)

    ts_min = records[0][0] / 1e9
    ts_max = records[-1][0] / 1e9
    print(f"\n[INFO] Timestamp range: {ts_min:.1f}s - {ts_max:.1f}s ({ts_max - ts_min:.1f}s span)")

    # Apply labeling
    if args.auto_label:
        if args.attack_type == 'benign':
            # Benign-only: label everything as benign
            labeled = [(features, 'benign') for _, features in records]
            print(f"\n[AUTO-LABEL] Benign-only file, all {len(labeled)} records labeled as benign")
        else:
            labeled = apply_auto_labels(records, args.attack_type)
    else:
        labeled = apply_time_labels(
            records, args.attack_type,
            args.baseline_before, args.attack_duration, args.baseline_after
        )

    if not labeled:
        print("[ERROR] No records after labeling")
        sys.exit(1)

    # Filter: for attack files, drop windows where no protocol PPS activity
    # (equivalent to .log pipeline filtering attack_packets == 0)
    if args.attack_type not in ('benign', 'mixed'):
        before = len(labeled)
        filtered = []
        for features, label in labeled:
            if label == 'benign':
                filtered.append((features, label))
            else:
                # Check that at least some per-protocol PPS is active
                total_proto_pps = sum(features[IDX_PPS_PROTO_START:IDX_PPS_PROTO_START + 12])
                if total_proto_pps > 0:
                    filtered.append((features, label))
        dropped = before - len(filtered)
        if dropped > 0:
            print(f"[FILTER] Dropped {dropped} attack windows with zero protocol PPS")
        labeled = filtered

    column_names = build_column_names()
    df = to_dataframe(labeled, column_names)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)

    print(f"\n[SUCCESS] {len(df)} records -> {args.output}")
    print(f"  Features: {len(column_names)}")
    print(f"  Labels:")
    for label, count in df['label'].value_counts().items():
        print(f"    {label:15s}: {count:5d} ({count/len(df)*100:.1f}%)")

    # Quick sanity check
    active = []
    for proto in PROTOCOLS:
        avg = df[f'pps_{proto}'].mean()
        if avg > 0.1:
            active.append(f"{proto}({avg:.0f})")
    if active:
        print(f"  Active protos: {', '.join(active)}")

    print("\n[DONE]")


if __name__ == '__main__':
    main()
