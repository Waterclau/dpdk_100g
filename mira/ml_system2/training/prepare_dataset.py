#!/usr/bin/env python3
"""
Prepare Dataset for Training (ml_system2 - shared)

Combines multiple CSV files and splits into train/val/test sets.
Optionally filters to only the features for a given mode.

Usage:
    python3 prepare_dataset.py \
        --input ../datasets/processed/*.csv \
        --output ../datasets/splits/ \
        --mode sketch_adv

    python3 prepare_dataset.py \
        --input ../datasets/processed/*.csv \
        --output ../datasets/splits/ \
        --mode dpi_sketch
"""

import argparse
import sys
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
import glob

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from feature_groups import get_feature_columns, filter_dataframe


def _infer_run_id(path: str) -> str:
    stem = Path(path).stem
    parts = stem.split('_run')
    if len(parts) >= 2:
        return f"run{parts[-1]}"
    return "run_unknown"


def load_and_combine(input_files, drop_labels=None, add_run_id=False):
    """Load multiple CSV files and combine them"""
    if isinstance(input_files, str):
        csv_files = glob.glob(input_files)
    elif isinstance(input_files, list):
        csv_files = input_files
    else:
        csv_files = list(input_files)

    if not csv_files:
        raise ValueError("No CSV files found")

    print(f"[INFO] {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {f}")

    dfs = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        if add_run_id:
            df['run_id'] = _infer_run_id(csv_file)
        print(f"  {Path(csv_file).name}: {len(df)} rows, labels: {dict(df['label'].value_counts())}")
        if drop_labels:
            df = df[~df['label'].isin(drop_labels)]
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[COMBINED] {len(combined)} rows, {len(combined.columns)-1} features")
    print(f"  Labels: {dict(combined['label'].value_counts())}")
    return combined


def split_dataset(df, train_ratio, val_ratio, test_ratio):
    """Stratified split into train/val/test"""
    total = train_ratio + val_ratio + test_ratio
    if abs(total - 1.0) > 0.001:
        raise ValueError(f"Ratios must sum to 1.0, got {total}")

    df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)

    train_df, temp_df = train_test_split(
        df_shuffled, test_size=(val_ratio + test_ratio),
        random_state=42, stratify=df_shuffled['label']
    )

    val_rel = val_ratio / (val_ratio + test_ratio)
    val_df, test_df = train_test_split(
        temp_df, test_size=(1 - val_rel),
        random_state=42, stratify=temp_df['label']
    )

    print(f"\n[SPLIT] Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")
    return train_df, val_df, test_df


def split_by_run(df, train_runs, val_runs, test_runs):
    """Split by run_id"""
    if 'run_id' not in df.columns:
        raise ValueError("run_id column missing")

    train_df = df[df['run_id'].isin(train_runs)].copy()
    val_df = df[df['run_id'].isin(val_runs)].copy()
    test_df = df[df['run_id'].isin(test_runs)].copy()

    print(f"\n[SPLIT by run] Train({train_runs}): {len(train_df)} | "
          f"Val({val_runs}): {len(val_df)} | Test({test_runs}): {len(test_df)}")
    return train_df, val_df, test_df


def main():
    parser = argparse.ArgumentParser(description='Prepare dataset for ML training')
    parser.add_argument('--input', type=str, required=True, nargs='+',
                        help='Input CSV files')
    parser.add_argument('--output', type=str, required=True,
                        help='Output directory for splits')
    parser.add_argument('--mode', type=str, default='sketch_adv',
                        choices=['dpi_sketch', 'dpi_ratios', 'sketch', 'sketch_adv'],
                        help='Feature mode (default: sketch_adv)')
    parser.add_argument('--train-ratio', type=float, default=0.7)
    parser.add_argument('--val-ratio', type=float, default=0.15)
    parser.add_argument('--test-ratio', type=float, default=0.15)
    parser.add_argument('--exclude-label', action='append', default=[])
    parser.add_argument('--split-by-run', action='store_true')
    parser.add_argument('--train-runs', type=str, default='')
    parser.add_argument('--val-runs', type=str, default='')
    parser.add_argument('--test-runs', type=str, default='')
    parser.add_argument('--subsample', type=int, default=1,
                        help='Take 1 every N windows to reduce temporal autocorrelation (default: 1 = no subsampling)')

    args = parser.parse_args()

    combined = load_and_combine(
        args.input, drop_labels=args.exclude_label, add_run_id=args.split_by_run
    )

    if combined.isnull().any().any():
        print("[WARNING] Missing values -> filling with 0")
        combined = combined.fillna(0)

    # Subsample: take 1 every N windows per source file to reduce temporal autocorrelation
    if args.subsample > 1:
        before = len(combined)
        combined = combined.groupby(
            ['label'] + (['run_id'] if 'run_id' in combined.columns else []),
            group_keys=False
        ).apply(lambda g: g.iloc[::args.subsample]).reset_index(drop=True)
        print(f"[SUBSAMPLE] 1/{args.subsample}: {before} -> {len(combined)} rows")

    # Filter to selected features
    expected = get_feature_columns(args.mode)
    available = [c for c in expected if c in combined.columns]
    missing = [c for c in expected if c not in combined.columns]
    if missing:
        print(f"[WARNING] Missing {len(missing)} features for mode '{args.mode}': {missing[:5]}...")
    print(f"[MODE] {args.mode}: {len(available)}/{len(expected)} features available")

    # Keep only selected features + label + run_id
    keep = available + ['label']
    if 'run_id' in combined.columns:
        keep.append('run_id')
    combined = combined[keep]

    # Split
    if args.split_by_run:
        train_runs = [r.strip() for r in args.train_runs.split(',') if r.strip()]
        val_runs = [r.strip() for r in args.val_runs.split(',') if r.strip()]
        test_runs = [r.strip() for r in args.test_runs.split(',') if r.strip()]
        train_df, val_df, test_df = split_by_run(combined, train_runs, val_runs, test_runs)
    else:
        train_df, val_df, test_df = split_dataset(
            combined, args.train_ratio, args.val_ratio, args.test_ratio
        )

    # Drop run_id from final output
    for df in [train_df, val_df, test_df]:
        if 'run_id' in df.columns:
            df.drop(columns=['run_id'], inplace=True)

    # Save
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    for name, df in [('train', train_df), ('val', val_df), ('test', test_df)]:
        path = output_path / f'{name}.csv'
        df.to_csv(path, index=False)
        print(f"  {name}: {path} ({len(df)} rows)")

    print(f"\n[DONE] Features: {len(available)} | Mode: {args.mode}")


if __name__ == '__main__':
    main()
