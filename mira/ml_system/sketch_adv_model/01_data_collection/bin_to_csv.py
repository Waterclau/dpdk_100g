#!/usr/bin/env python3
"""
Binary Sketch-ADV to CSV Converter

Reads binary .bin files produced by detector_system (--sketch-adv mode)
and converts them to labeled CSV for ML training.

All records in the file get the same label (from --label argument),
exactly like the log feature_extractor works.

Binary record format (528 bytes, packed):
  - uint32  magic          (0x534B4156 = "SKAV")
  - uint32  version        (1)
  - uint64  timestamp_ns
  - double[14]  global sketch features
  - double[12]  pps_proto
  - double[12]  heavy_hitters_proto
  - double[12]  ip_concentration_proto
  - double[12]  ratio_vs_total_proto
  - double  avg_packet_size
  - double  packet_size_variance

Usage:
    python3 bin_to_csv.py \
        --input /path/to/dns_sketch_adv_run1.bin \
        --output ../datasets/processed/dns_run1.csv \
        --label dns
"""

import argparse
import struct
import sys
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from feature_groups import SKETCH_FEATURES, SKETCH_ADV_PROTOCOLS, SKETCH_ADV_PER_PROTO

# Must match C struct sketch_adv_record
RECORD_MAGIC = 0x534B4156  # "SKAV"
RECORD_VERSION = 1
RECORD_SIZE = 528  # bytes

# Struct format: little-endian, uint32 + uint32 + uint64 + 64 doubles
# 14 global + 12*4 per-protocol + 2 packet size = 64 doubles
RECORD_FMT = '<IIQ64d'
assert struct.calcsize(RECORD_FMT) == RECORD_SIZE


def build_column_names():
    """Build ordered column names matching binary record layout"""
    cols = list(SKETCH_FEATURES)

    # C struct layout: pps_proto[12], then heavy_hitters[12], then concentration[12], then ratio[12]
    for feat_type in SKETCH_ADV_PER_PROTO:
        for proto in SKETCH_ADV_PROTOCOLS:
            cols.append(f'{feat_type}_{proto}')

    cols.append('avg_packet_size')
    cols.append('packet_size_variance')

    return cols  # 14 + 48 + 2 = 64


def read_binary_file(bin_path):
    """Read all records from binary file, return list of features[64]"""
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

        records.append(list(features))

    if errors > 3:
        print(f"[WARNING] {errors} total bad records skipped")

    print(f"[INFO] Valid records: {len(records)}")
    return records


def main():
    parser = argparse.ArgumentParser(
        description='Convert binary sketch-adv .bin to labeled CSV',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bin_to_csv.py --input /path/to/dns_run1.bin --output ../datasets/processed/dns_run1.csv --label dns
  python3 bin_to_csv.py --input /path/to/benign_run1.bin --output ../datasets/processed/benign_run1.csv --label benign

Supported labels:
  benign, dns, ntp, snmp, ssdp, portmap, netbios, ldap, mssql, tftp, syn, udp, webddos, mixed
        """
    )

    parser.add_argument('--input', required=True, help='Input binary .bin file')
    parser.add_argument('--output', required=True, help='Output CSV file')
    parser.add_argument('--label', required=True, help='Label for all records (benign, dns, ntp, ...)')

    args = parser.parse_args()

    if not Path(args.input).exists():
        print(f"[ERROR] Not found: {args.input}")
        sys.exit(1)

    print("=" * 60)
    print("SKETCH-ADV BINARY TO CSV CONVERTER")
    print("=" * 60)
    print(f"  Input:  {args.input}")
    print(f"  Output: {args.output}")
    print(f"  Label:  {args.label}")

    records = read_binary_file(args.input)
    if not records:
        print("[ERROR] No valid records")
        sys.exit(1)

    column_names = build_column_names()

    # Build DataFrame: all records get the same label
    rows = []
    for features in records:
        row = dict(zip(column_names, features))
        row['label'] = args.label
        rows.append(row)

    df = pd.DataFrame(rows)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.output, index=False)

    print(f"\n[SUCCESS] {len(df)} records -> {args.output}")
    print(f"  Features: {len(column_names)}")
    print(f"  Label: {args.label} ({len(df)} records)")

    # Quick sanity check
    active = []
    for proto in SKETCH_ADV_PROTOCOLS:
        avg = df[f'pps_{proto}'].mean()
        if avg > 0.1:
            active.append(f"{proto}({avg:.0f})")
    if active:
        print(f"  Active protos: {', '.join(active)}")

    print("\n[DONE]")


if __name__ == '__main__':
    main()
