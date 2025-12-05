#!/usr/bin/env python3
"""
Export LightGBM model for C integration

Usage:
    python3 export_lightgbm_model.py \
        --train ../datasets/splits/train.csv \
        --output ../../detector_system_ml/lightgbm_model.txt
"""

import argparse
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
import json
from pathlib import Path


def train_and_export(train_csv, output_path):
    """Train LightGBM and export to text format for C API"""

    print("="*60)
    print("TRAINING LIGHTGBM MODEL FOR C INTEGRATION")
    print("="*60)

    # Load training data
    print(f"\nLoading: {train_csv}")
    df = pd.read_csv(train_csv)

    # Prepare features
    feature_cols = [col for col in df.columns if col not in ['timestamp', 'label']]
    X = df[feature_cols].values
    y_labels = df['label'].values

    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_labels)

    print(f"Samples: {len(X)}")
    print(f"Features: {feature_cols}")
    print(f"Classes: {list(label_encoder.classes_)}")

    # Create dataset
    train_data = lgb.Dataset(X, label=y, feature_name=feature_cols)

    # Parameters for C API compatibility
    params = {
        'objective': 'multiclass',
        'num_class': len(label_encoder.classes_),
        'metric': 'multi_logloss',
        'learning_rate': 0.1,
        'max_depth': 6,
        'num_leaves': 31,
        'min_data_in_leaf': 20,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'seed': 42
    }

    print("\nTraining model...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=100,
        valid_sets=[train_data],
        callbacks=[lgb.log_evaluation(period=20)]
    )

    # Export model
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    model.save_model(str(output_file))
    print(f"\nModel saved: {output_file}")

    # Save label mapping
    mapping_file = output_file.parent / 'label_mapping.json'
    mapping = {str(i): label for i, label in enumerate(label_encoder.classes_)}
    with open(mapping_file, 'w') as f:
        json.dump(mapping, f, indent=2)
    print(f"Label mapping saved: {mapping_file}")

    # Test inference
    print("\nTesting inference...")
    test_features = X[0:1]
    pred = model.predict(test_features)
    print(f"Test prediction shape: {pred.shape}")
    print(f"Test prediction: {pred}")

    print("\n" + "="*60)
    print("MODEL EXPORT COMPLETE")
    print("="*60)
    print(f"\nModel file: {output_file}")
    print("Usage in C code:")
    print(f'  ml_model_handle model = ml_init("{output_file.name}");')
    print("\nNext steps:")
    print("1. Copy model to detector_system_ml/")
    print("2. Compile detector with: make")
    print("3. Run with model loaded")


def main():
    parser = argparse.ArgumentParser(description='Export LightGBM model for C')
    parser.add_argument('--train', required=True, help='Training CSV file')
    parser.add_argument('--output', required=True, help='Output model file (.txt)')

    args = parser.parse_args()
    train_and_export(args.train, args.output)


if __name__ == '__main__':
    main()
