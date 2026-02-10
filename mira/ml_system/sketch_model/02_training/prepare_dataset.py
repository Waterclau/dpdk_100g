#!/usr/bin/env python3
"""
Prepare Dataset for Training
Combines multiple CSV files and splits into train/val/test sets

Usage:
    # Shell will expand wildcard
    python3 prepare_dataset.py \
        --input ../datasets/processed/*.csv \
        --output ../datasets/splits/ \
        --train-ratio 0.7 \
        --val-ratio 0.15 \
        --test-ratio 0.15

    # Or specify files explicitly
    python3 prepare_dataset.py \
        --input ../datasets/processed/benign.csv ../datasets/processed/attack.csv \
        --output ../datasets/splits/
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
import glob


def _infer_run_id(path: str) -> str:
    stem = Path(path).stem
    parts = stem.split('_run')
    if len(parts) >= 2:
        return f"run{parts[-1]}"
    return "run_unknown"


def load_and_combine_datasets(input_files, drop_labels=None, add_run_id=False) -> pd.DataFrame:
    """Load multiple CSV files and combine them"""

    # Handle both list of files and glob pattern
    if isinstance(input_files, str):
        csv_files = glob.glob(input_files)
    elif isinstance(input_files, list):
        csv_files = input_files
    else:
        csv_files = list(input_files)

    if not csv_files:
        raise ValueError(f"No CSV files provided or found")

    print(f"[INFO] Found {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {f}")

    dataframes = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        if add_run_id:
            df['run_id'] = _infer_run_id(csv_file)
        print(f"\n[INFO] Loaded {csv_file}:")
        print(f"  Rows: {len(df)}")
        print(f"  Label distribution:")
        print(df['label'].value_counts())
        if drop_labels:
            df = df[~df['label'].isin(drop_labels)]
        dataframes.append(df)

    # Combine all dataframes
    combined_df = pd.concat(dataframes, ignore_index=True)

    print(f"\n[INFO] Combined dataset:")
    print(f"  Total rows: {len(combined_df)}")
    print(f"  Features: {list(combined_df.columns)}")
    print(f"  Label distribution:")
    print(combined_df['label'].value_counts())

    return combined_df


def split_dataset(df: pd.DataFrame, train_ratio: float, val_ratio: float, test_ratio: float):
    """Split dataset into train/val/test sets"""

    # Validate ratios
    total = train_ratio + val_ratio + test_ratio
    if abs(total - 1.0) > 0.001:
        raise ValueError(f"Ratios must sum to 1.0, got {total}")

    print(f"\n[INFO] Splitting dataset:")
    print(f"  Train: {train_ratio*100:.1f}%")
    print(f"  Val:   {val_ratio*100:.1f}%")
    print(f"  Test:  {test_ratio*100:.1f}%")

    # Shuffle data
    df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # First split: train vs (val + test)
    train_df, temp_df = train_test_split(
        df_shuffled,
        test_size=(val_ratio + test_ratio),
        random_state=42,
        stratify=df_shuffled['label']  # Stratify to maintain label distribution
    )

    # Second split: val vs test
    val_size_relative = val_ratio / (val_ratio + test_ratio)
    val_df, test_df = train_test_split(
        temp_df,
        test_size=(1 - val_size_relative),
        random_state=42,
        stratify=temp_df['label']
    )

    print(f"\n[INFO] Split results:")
    print(f"  Train set: {len(train_df)} rows")
    print(f"  Val set:   {len(val_df)} rows")
    print(f"  Test set:  {len(test_df)} rows")

    # Verify label distribution
    print(f"\n[INFO] Train set label distribution:")
    print(train_df['label'].value_counts())
    print(f"\n[INFO] Val set label distribution:")
    print(val_df['label'].value_counts())
    print(f"\n[INFO] Test set label distribution:")
    print(test_df['label'].value_counts())

    return train_df, val_df, test_df


def split_by_run(df: pd.DataFrame, train_runs, val_runs, test_runs):
    """Split dataset by run_id lists"""
    if 'run_id' not in df.columns:
        raise ValueError("run_id column missing; cannot split by run")

    train_df = df[df['run_id'].isin(train_runs)].copy()
    val_df = df[df['run_id'].isin(val_runs)].copy()
    test_df = df[df['run_id'].isin(test_runs)].copy()

    print(f"\n[INFO] Split by run_id:")
    print(f"  Train runs: {train_runs}")
    print(f"  Val runs:   {val_runs}")
    print(f"  Test runs:  {test_runs}")

    print(f"\n[INFO] Split results:")
    print(f"  Train set: {len(train_df)} rows")
    print(f"  Val set:   {len(val_df)} rows")
    print(f"  Test set:  {len(test_df)} rows")

    # Verify label distribution
    print(f"\n[INFO] Train set label distribution:")
    print(train_df['label'].value_counts())
    print(f"\n[INFO] Val set label distribution:")
    print(val_df['label'].value_counts())
    print(f"\n[INFO] Test set label distribution:")
    print(test_df['label'].value_counts())

    return train_df, val_df, test_df


def save_splits(train_df, val_df, test_df, output_dir: str):
    """Save train/val/test splits to CSV files"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Save splits
    train_file = output_path / 'train.csv'
    val_file = output_path / 'val.csv'
    test_file = output_path / 'test.csv'

    train_df.to_csv(train_file, index=False)
    val_df.to_csv(val_file, index=False)
    test_df.to_csv(test_file, index=False)

    print(f"\n[SUCCESS] Saved dataset splits:")
    print(f"  Train: {train_file}")
    print(f"  Val:   {val_file}")
    print(f"  Test:  {test_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Prepare and split dataset for ML training',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Prepare dataset with default 70/15/15 split (shell expands wildcard)
  python3 prepare_dataset.py \\
      --input ../datasets/processed/*.csv \\
      --output ../datasets/splits/

  # Specify files explicitly
  python3 prepare_dataset.py \\
      --input ../datasets/processed/benign_baseline.csv \\
              ../datasets/processed/attack_cic_ids.csv \\
              ../datasets/processed/mixed_traffic.csv \\
      --output ../datasets/splits/

  # Custom split ratios
  python3 prepare_dataset.py \\
      --input ../datasets/processed/*.csv \\
      --output ../datasets/splits/ \\
      --train-ratio 0.8 \\
      --val-ratio 0.1 \\
      --test-ratio 0.1
        """
    )

    parser.add_argument('--input', type=str, required=True, nargs='+',
                       help='Input CSV files (can specify multiple files or use wildcards)')
    parser.add_argument('--output', type=str, required=True,
                       help='Output directory for splits')
    parser.add_argument('--train-ratio', type=float, default=0.7,
                       help='Training set ratio (default: 0.7)')
    parser.add_argument('--val-ratio', type=float, default=0.15,
                       help='Validation set ratio (default: 0.15)')
    parser.add_argument('--test-ratio', type=float, default=0.15,
                       help='Test set ratio (default: 0.15)')
    parser.add_argument('--exclude-label', action='append', default=[],
                       help='Exclude label(s) from dataset (repeatable)')
    parser.add_argument('--split-by-run', action='store_true',
                       help='Split by run_id inferred from filename')
    parser.add_argument('--train-runs', type=str, default='',
                       help='Comma-separated run_ids for train (e.g., run1,run2)')
    parser.add_argument('--val-runs', type=str, default='',
                       help='Comma-separated run_ids for val (e.g., run3)')
    parser.add_argument('--test-runs', type=str, default='',
                       help='Comma-separated run_ids for test (e.g., run4)')

    args = parser.parse_args()

    # Load and combine datasets
    combined_df = load_and_combine_datasets(
        args.input,
        drop_labels=args.exclude_label,
        add_run_id=args.split_by_run,
    )

    # Check for missing values
    if combined_df.isnull().any().any():
        print("\n[WARNING] Dataset contains missing values!")
        print(combined_df.isnull().sum())
        print("[INFO] Filling missing values with 0...")
        combined_df = combined_df.fillna(0)

    # Split dataset
    if args.split_by_run:
        train_runs = [r.strip() for r in args.train_runs.split(',') if r.strip()]
        val_runs = [r.strip() for r in args.val_runs.split(',') if r.strip()]
        test_runs = [r.strip() for r in args.test_runs.split(',') if r.strip()]
        if not train_runs or not val_runs or not test_runs:
            raise ValueError("split-by-run requires --train-runs, --val-runs, --test-runs")
        train_df, val_df, test_df = split_by_run(combined_df, train_runs, val_runs, test_runs)
    else:
        train_df, val_df, test_df = split_dataset(
            combined_df,
            args.train_ratio,
            args.val_ratio,
            args.test_ratio
        )
        if 'run_id' in train_df.columns:
            train_df = train_df.drop(columns=['run_id'])
        if 'run_id' in val_df.columns:
            val_df = val_df.drop(columns=['run_id'])
        if 'run_id' in test_df.columns:
            test_df = test_df.drop(columns=['run_id'])

    # Save splits
    save_splits(train_df, val_df, test_df, args.output)

    print("\n[DONE] Dataset preparation complete!")
    print("\nNext steps:")
    print("1. Train model: python3 export_lightgbm_model.py --train ../datasets/splits/train.csv")
    print("2. Evaluate model: python3 evaluate_model.py --test ../datasets/splits/test.csv")


if __name__ == '__main__':
    main()
