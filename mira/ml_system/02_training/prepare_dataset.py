#!/usr/bin/env python3
"""
Prepare Dataset for Training
Combines multiple CSV files and splits into train/val/test sets

Usage:
    python3 prepare_dataset.py \
        --input ../datasets/processed/*.csv \
        --output ../datasets/splits/ \
        --train-ratio 0.7 \
        --val-ratio 0.15 \
        --test-ratio 0.15
"""

import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
import glob


def load_and_combine_datasets(input_pattern: str) -> pd.DataFrame:
    """Load multiple CSV files and combine them"""

    csv_files = glob.glob(input_pattern)

    if not csv_files:
        raise ValueError(f"No CSV files found matching pattern: {input_pattern}")

    print(f"[INFO] Found {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {f}")

    dataframes = []
    for csv_file in csv_files:
        df = pd.read_csv(csv_file)
        print(f"\n[INFO] Loaded {csv_file}:")
        print(f"  Rows: {len(df)}")
        print(f"  Label distribution:")
        print(df['label'].value_counts())
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
  # Prepare dataset with default 70/15/15 split
  python3 prepare_dataset.py \\
      --input ../datasets/processed/*.csv \\
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

    parser.add_argument('--input', type=str, required=True,
                       help='Input CSV files pattern (e.g., ../datasets/processed/*.csv)')
    parser.add_argument('--output', type=str, required=True,
                       help='Output directory for splits')
    parser.add_argument('--train-ratio', type=float, default=0.7,
                       help='Training set ratio (default: 0.7)')
    parser.add_argument('--val-ratio', type=float, default=0.15,
                       help='Validation set ratio (default: 0.15)')
    parser.add_argument('--test-ratio', type=float, default=0.15,
                       help='Test set ratio (default: 0.15)')

    args = parser.parse_args()

    # Load and combine datasets
    combined_df = load_and_combine_datasets(args.input)

    # Check for missing values
    if combined_df.isnull().any().any():
        print("\n[WARNING] Dataset contains missing values!")
        print(combined_df.isnull().sum())
        print("[INFO] Filling missing values with 0...")
        combined_df = combined_df.fillna(0)

    # Split dataset
    train_df, val_df, test_df = split_dataset(
        combined_df,
        args.train_ratio,
        args.val_ratio,
        args.test_ratio
    )

    # Save splits
    save_splits(train_df, val_df, test_df, args.output)

    print("\n[DONE] Dataset preparation complete!")
    print("\nNext steps:")
    print("1. Train model: python3 export_lightgbm_model.py --train ../datasets/splits/train.csv")
    print("2. Evaluate model: python3 evaluate_model.py --test ../datasets/splits/test.csv")


if __name__ == '__main__':
    main()
