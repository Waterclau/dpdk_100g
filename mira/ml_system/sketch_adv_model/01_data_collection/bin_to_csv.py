#!/usr/bin/env python3
"""
Binary Sketch-ADV to CSV Converter

Reads binary .bin files produced by detector_system (--sketch-adv mode)
and converts them to CSV with time-based labeling for ML training.

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

Labeling (time-based, for structured experiments):
  50s baseline -> 100s attack -> 50s baseline (200s total)
  - 0-50s:    label = benign
  - 50-150s:  label = <attack_type>
  - 150-200s: label = benign

Usage:
    python3 bin_to_csv.py \
        --input /tmp/dns_sketch_adv_run1.bin \
        --output ../datasets/processed/dns_run1.csv \
        --attack-type dns

    # Custom timing
    python3 bin_to_csv.py \
        --input /tmp/experiment.bin \
        --output ../datasets/processed/ntp_run1.csv \
        --attack-type ntp \
        --baseline-before 30 --attack-duration 120 --baseline-after 30
"""

import argparse
import struct
import sys
import pandas as pd
import numpy as np
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
  python3 bin_to_csv.py --input /tmp/dns_run1.bin --output ../datasets/processed/dns_run1.csv --attack-type dns
  python3 bin_to_csv.py --input /tmp/ntp.bin --output ntp.csv --attack-type ntp --baseline-before 30 --attack-duration 120

Supported attack types:
  dns, ntp, snmp, ssdp, portmap, netbios, ldap, mssql, tftp, syn, udp, webddos, mixed
        """
    )

    parser.add_argument('--input', required=True, help='Input binary .bin file')
    parser.add_argument('--output', required=True, help='Output CSV file')
    parser.add_argument('--attack-type', required=True, help='Attack type label')
    parser.add_argument('--baseline-before', type=float, default=50.0,
                        help='Baseline before attack in seconds (default: 50)')
    parser.add_argument('--attack-duration', type=float, default=100.0,
                        help='Attack duration in seconds (default: 100)')
    parser.add_argument('--baseline-after', type=float, default=50.0,
                        help='Baseline after attack in seconds (default: 50)')

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
    print(f"  Timing: {args.baseline_before}s + {args.attack_duration}s + {args.baseline_after}s")

    records = read_binary_file(args.input)
    if not records:
        print("[ERROR] No valid records")
        sys.exit(1)

    ts_min = records[0][0] / 1e9
    ts_max = records[-1][0] / 1e9
    print(f"\n[INFO] Timestamp range: {ts_min:.1f}s - {ts_max:.1f}s ({ts_max - ts_min:.1f}s span)")

    labeled = apply_time_labels(
        records, args.attack_type,
        args.baseline_before, args.attack_duration, args.baseline_after
    )

    if not labeled:
        print("[ERROR] No records after labeling")
        sys.exit(1)

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
    for proto in SKETCH_ADV_PROTOCOLS:
        avg = df[f'pps_{proto}'].mean()
        if avg > 0.1:
            active.append(f"{proto}({avg:.0f})")
    if active:
        print(f"  Active protos: {', '.join(active)}")

    print("\n[DONE]")


if __name__ == '__main__':
    main()
