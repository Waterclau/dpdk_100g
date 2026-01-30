#!/usr/bin/env python3
"""
Train LightGBM Model with Feature Normalization
Includes StandardScaler for better performance on numerical features

Usage:
    python3 train_with_normalization.py \
        --train ../datasets/splits/train.csv \
        --val ../datasets/splits/val.csv \
        --output ../../detector_system_ml/lightgbm_model.txt
"""

import argparse
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import json
import pickle
from pathlib import Path


def train_and_export(train_csv, val_csv, output_path):
    """Train LightGBM with feature normalization"""

    print("="*70)
    print("TRAINING LIGHTGBM MODEL WITH FEATURE NORMALIZATION")
    print("="*70)

    # Load training data
    print(f"\n[INFO] Loading training data: {train_csv}")
    df_train = pd.read_csv(train_csv)

    # Load validation data
    print(f"[INFO] Loading validation data: {val_csv}")
    df_val = pd.read_csv(val_csv)

    # Prepare features
    exclude_cols = ['label']
    if 'timestamp' in df_train.columns:
        exclude_cols.append('timestamp')
    if 'run_id' in df_train.columns:
        exclude_cols.append('run_id')

    feature_cols = [col for col in df_train.columns if col not in exclude_cols]

    X_train = df_train[feature_cols].values
    y_train_labels = df_train['label'].values

    X_val = df_val[feature_cols].values
    y_val_labels = df_val['label'].values

    # Encode labels
    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(y_train_labels)
    y_val = label_encoder.transform(y_val_labels)

    print(f"\n[DATASET INFO]")
    print(f"  Training samples: {len(X_train)}")
    print(f"  Validation samples: {len(X_val)}")
    print(f"  Features: {len(feature_cols)}")
    print(f"  Classes: {list(label_encoder.classes_)}")

    # Class distribution
    print(f"\n[CLASS DISTRIBUTION]")
    for cls in label_encoder.classes_:
        train_count = np.sum(y_train_labels == cls)
        val_count = np.sum(y_val_labels == cls)
        train_pct = train_count / len(y_train_labels) * 100
        val_pct = val_count / len(y_val_labels) * 100
        print(f"  {cls:10s}: Train={train_count:4d} ({train_pct:5.1f}%)  Val={val_count:4d} ({val_pct:5.1f}%)")

    # Feature normalization
    print(f"\n[FEATURE NORMALIZATION]")
    print(f"  Applying StandardScaler (mean=0, std=1)...")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # Print scaling statistics
    print(f"\n  Feature statistics after scaling:")
    for i, feature in enumerate(feature_cols[:5]):  # Show first 5 features
        print(f"    {feature:20s}: mean={X_train_scaled[:, i].mean():7.3f}, std={X_train_scaled[:, i].std():7.3f}")

    # Create LightGBM datasets
    train_data = lgb.Dataset(X_train_scaled, label=y_train, feature_name=feature_cols)
    val_data = lgb.Dataset(X_val_scaled, label=y_val, reference=train_data, feature_name=feature_cols)

    # Optimized parameters
    dataset_size = len(X_train)

    if dataset_size < 500:
        print(f"\n[WARNING] Small dataset ({dataset_size} samples)")
        params = {
            'objective': 'multiclass',
            'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss',
            'learning_rate': 0.05,
            'max_depth': 4,
            'num_leaves': 15,
            'min_data_in_leaf': 5,
            'feature_fraction': 0.8,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'lambda_l1': 1.0,
            'lambda_l2': 1.0,
            'verbose': -1,
            'seed': 42
        }
        num_boost_round = 150
    elif dataset_size < 1000:
        print(f"\n[WARNING] Medium dataset ({dataset_size} samples) - Using conservative hyperparameters to prevent overfitting")
        params = {
            'objective': 'multiclass',
            'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss',
            'learning_rate': 0.03,           # Reduced from 0.05
            'max_depth': 3,                   # Reduced from 6 (CRITICAL for small data)
            'num_leaves': 7,                  # Reduced from 31 (CRITICAL for small data)
            'min_data_in_leaf': 20,           # Increased from 10
            'feature_fraction': 0.7,          # Reduced from 0.85 (more dropout)
            'bagging_fraction': 0.7,          # Reduced from 0.85 (more dropout)
            'bagging_freq': 5,
            'lambda_l1': 5.0,                 # Increased from 0.5 (L1 regularization)
            'lambda_l2': 10.0,                # Increased from 0.5 (L2 regularization)
            'min_gain_to_split': 1.0,        # Added (require minimum gain for splits)
            'verbose': -1,
            'seed': 42
        }
        num_boost_round = 100                # Reduced from 200
    else:
        print(f"\n[INFO] Large dataset ({dataset_size} samples)")
        params = {
            'objective': 'multiclass',
            'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss',
            'learning_rate': 0.05,
            'max_depth': 8,
            'num_leaves': 63,
            'min_data_in_leaf': 10,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.85,
            'bagging_freq': 5,
            'lambda_l1': 0.5,
            'lambda_l2': 0.5,
            'min_gain_to_split': 0.01,
            'verbose': -1,
            'seed': 42
        }
        num_boost_round = 300

    print(f"\n[TRAINING CONFIGURATION]")
    print(f"  Boosting rounds: {num_boost_round}")
    print(f"  Max depth: {params['max_depth']}")
    print(f"  Num leaves: {params['num_leaves']}")
    print(f"  Learning rate: {params['learning_rate']}")
    print(f"  L1/L2 regularization: {params['lambda_l1']}/{params['lambda_l2']}")

    # Train model
    print("\n[TRAINING MODEL]")
    # Adaptive early stopping based on dataset size
    early_stop_rounds = 10 if dataset_size < 1000 else 20 if dataset_size < 2000 else 30
    print(f"  Early stopping rounds: {early_stop_rounds} (aggressive for small datasets)")

    model = lgb.train(
        params,
        train_data,
        num_boost_round=num_boost_round,
        valid_sets=[train_data, val_data],
        valid_names=['train', 'valid'],
        callbacks=[
            lgb.log_evaluation(period=50),
            lgb.early_stopping(stopping_rounds=early_stop_rounds, verbose=True)
        ]
    )

    # Validation accuracy
    print("\n[VALIDATION RESULTS]")
    y_val_pred_proba = model.predict(X_val_scaled)
    y_val_pred = np.argmax(y_val_pred_proba, axis=1)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"Validation Accuracy: {val_accuracy*100:.2f}%")
    print("\nPer-Class Performance:")
    print(classification_report(y_val, y_val_pred, target_names=label_encoder.classes_))

    # Export model
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    model.save_model(str(output_file))
    print(f"\n[EXPORT] Model saved: {output_file}")

    # Save label mapping
    mapping_file = output_file.parent / 'label_mapping.json'
    mapping = {str(i): label for i, label in enumerate(label_encoder.classes_)}
    with open(mapping_file, 'w') as f:
        json.dump(mapping, f, indent=2)
    print(f"[EXPORT] Label mapping saved: {mapping_file}")

    # Save scaler for inference
    scaler_file = output_file.parent / 'feature_scaler.pkl'
    with open(scaler_file, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[EXPORT] Feature scaler saved: {scaler_file}")

    # Feature importance
    print("\n[FEATURE IMPORTANCE] Top 10 features:")
    importance = model.feature_importance(importance_type='gain')
    feature_importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': importance
    }).sort_values('importance', ascending=False)

    for idx, row in feature_importance.head(10).iterrows():
        print(f"  {row['feature']:25s}: {row['importance']:8.1f}")

    print("\n" + "="*70)
    print("MODEL TRAINING COMPLETE")
    print("="*70)
    print(f"\nFinal Validation Accuracy: {val_accuracy*100:.2f}%")
    print(f"\nFiles created:")
    print(f"  1. {output_file}")
    print(f"  2. {mapping_file}")
    print(f"  3. {scaler_file}")

    if val_accuracy < 0.90:
        print("\n[RECOMMENDATION] Accuracy < 90%. Consider:")
        print("  - Collecting more training data")
        print("  - Checking class balance")
        print("  - Adding more features")
    elif val_accuracy < 0.95:
        print("\n[STATUS] Good performance (90-95%). May benefit from:")
        print("  - Fine-tuning hyperparameters")
        print("  - Collecting more diverse data")
    elif val_accuracy < 0.99:
        print("\n[STATUS] Excellent performance (95-99%)! ✅")
    else:
        print("\n⚠️  [WARNING] POSSIBLE OVERFITTING DETECTED! ⚠️")
        print(f"  Validation accuracy = {val_accuracy*100:.2f}% (suspiciously high)")
        print(f"  Training samples = {dataset_size}")
        print("\n  Recommendations:")
        print("  1. Collect at least 5-10× more training data (target: 5000+ samples)")
        print("  2. Use K-fold cross-validation to verify generalization")
        print("  3. Test on completely unseen attack types (not in training set)")
        print("  4. Check if validation set is too similar to training set")
        print("\n  Current model may NOT generalize to real-world traffic!")


def main():
    parser = argparse.ArgumentParser(
        description='Train LightGBM model with feature normalization'
    )
    parser.add_argument('--train', required=True, help='Training CSV file')
    parser.add_argument('--val', required=True, help='Validation CSV file')
    parser.add_argument('--output', required=True, help='Output model file (.txt)')

    args = parser.parse_args()
    train_and_export(args.train, args.val, args.output)


if __name__ == '__main__':
    main()
