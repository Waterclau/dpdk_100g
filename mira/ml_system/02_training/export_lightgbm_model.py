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

    # Prepare features (exclude 'label' and 'timestamp' if present)
    exclude_cols = ['label']
    if 'timestamp' in df.columns:
        exclude_cols.append('timestamp')

    feature_cols = [col for col in df.columns if col not in exclude_cols]
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

    # Optimized parameters for larger datasets (1000+ samples)
    # These parameters are tuned for better accuracy and generalization
    params = {
        'objective': 'multiclass',
        'num_class': len(label_encoder.classes_),
        'metric': 'multi_logloss',
        'learning_rate': 0.05,      # Lower learning rate for better convergence
        'max_depth': 8,              # Deeper trees for complex patterns
        'num_leaves': 63,            # More leaves for better expressiveness
        'min_data_in_leaf': 10,      # Lower for larger datasets
        'feature_fraction': 0.9,     # Use more features per iteration
        'bagging_fraction': 0.85,    # Slight increase for stability
        'bagging_freq': 5,
        'lambda_l1': 0.5,            # L1 regularization to prevent overfitting
        'lambda_l2': 0.5,            # L2 regularization
        'min_gain_to_split': 0.01,   # Minimum gain to make a split
        'verbose': -1,
        'seed': 42,
        'boosting_type': 'gbdt',     # Gradient Boosting Decision Tree
        'extra_trees': False,        # Set True for extremely randomized trees
    }

    # Adjust parameters based on dataset size
    dataset_size = len(X)
    if dataset_size < 500:
        print(f"[WARNING] Small dataset detected ({dataset_size} samples)")
        print("[INFO] Adjusting hyperparameters for small dataset...")
        params['max_depth'] = 4
        params['num_leaves'] = 15
        params['min_data_in_leaf'] = 5
        params['lambda_l1'] = 1.0
        params['lambda_l2'] = 1.0
        num_boost_round = 150
    elif dataset_size < 1000:
        print(f"[INFO] Medium dataset ({dataset_size} samples)")
        params['max_depth'] = 6
        params['num_leaves'] = 31
        num_boost_round = 200
    else:
        print(f"[INFO] Large dataset ({dataset_size} samples) - using optimized parameters")
        num_boost_round = 300

    print(f"\n[TRAINING CONFIGURATION]")
    print(f"  Boosting rounds: {num_boost_round}")
    print(f"  Max depth: {params['max_depth']}")
    print(f"  Num leaves: {params['num_leaves']}")
    print(f"  Learning rate: {params['learning_rate']}")
    print(f"  L1 regularization: {params['lambda_l1']}")
    print(f"  L2 regularization: {params['lambda_l2']}")

    print("\nTraining model...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=num_boost_round,
        valid_sets=[train_data],
        callbacks=[
            lgb.log_evaluation(period=50),
            lgb.early_stopping(stopping_rounds=30, verbose=True)  # Early stopping
        ]
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
