#!/usr/bin/env python3
"""
Train LightGBM Model (ml_system2 - shared)

Works with any feature mode:
  --mode dpi_sketch   (56 features from .log)
  --mode sketch       (14 features from .log)
  --mode sketch_adv   (64 features from .bin)

Usage:
    python3 train_model.py \
        --train ../datasets/splits/train.csv \
        --val ../datasets/splits/val.csv \
        --mode sketch_adv \
        --output ./results/sketch_adv/
"""

import argparse
import sys
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import json
import pickle
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from feature_groups import get_feature_columns


def train_and_export(train_csv, val_csv, mode, output_dir):
    """Train LightGBM with selected feature mode"""

    expected_features = get_feature_columns(mode)

    print("=" * 70)
    print(f"TRAINING - Mode: {mode.upper()} ({len(expected_features)} features)")
    print("=" * 70)

    df_train = pd.read_csv(train_csv)
    df_val = pd.read_csv(val_csv)

    # Use features available in the CSV (should match what prepare_dataset filtered)
    exclude_cols = {'label', 'timestamp', 'run_id'}
    feature_cols = [c for c in df_train.columns if c not in exclude_cols]

    # Verify they match the expected mode
    expected_set = set(expected_features)
    actual_set = set(feature_cols)
    extra = actual_set - expected_set
    missing = expected_set - actual_set
    if extra:
        print(f"[WARNING] {len(extra)} extra features not in mode '{mode}': {list(extra)[:3]}...")
        feature_cols = [c for c in feature_cols if c in expected_set]
    if missing:
        print(f"[WARNING] {len(missing)} missing features: {list(missing)[:3]}...")

    X_train = df_train[feature_cols].values
    X_val = df_val[feature_cols].values
    y_train_labels = df_train['label'].values
    y_val_labels = df_val['label'].values

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(y_train_labels)
    y_val = label_encoder.transform(y_val_labels)

    print(f"\n[DATASET]")
    print(f"  Train: {len(X_train)}  Val: {len(X_val)}")
    print(f"  Features: {len(feature_cols)}")
    print(f"  Classes: {list(label_encoder.classes_)}")

    print(f"\n[CLASS DISTRIBUTION]")
    for cls in label_encoder.classes_:
        t = np.sum(y_train_labels == cls)
        v = np.sum(y_val_labels == cls)
        print(f"  {cls:15s}: Train={t:4d}  Val={v:4d}")

    # Feature normalization
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    train_data = lgb.Dataset(X_train_scaled, label=y_train, feature_name=feature_cols)
    val_data = lgb.Dataset(X_val_scaled, label=y_val, reference=train_data, feature_name=feature_cols)

    # Adaptive hyperparameters
    n = len(X_train)
    if n < 500:
        params = {
            'objective': 'multiclass', 'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss', 'learning_rate': 0.05,
            'max_depth': 4, 'num_leaves': 15, 'min_data_in_leaf': 5,
            'feature_fraction': 0.8, 'bagging_fraction': 0.8, 'bagging_freq': 5,
            'lambda_l1': 1.0, 'lambda_l2': 1.0, 'verbose': -1, 'seed': 42
        }
        num_rounds = 150
    elif n < 1000:
        params = {
            'objective': 'multiclass', 'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss', 'learning_rate': 0.03,
            'max_depth': 3, 'num_leaves': 7, 'min_data_in_leaf': 20,
            'feature_fraction': 0.7, 'bagging_fraction': 0.7, 'bagging_freq': 5,
            'lambda_l1': 5.0, 'lambda_l2': 10.0, 'min_gain_to_split': 1.0,
            'verbose': -1, 'seed': 42
        }
        num_rounds = 100
    else:
        params = {
            'objective': 'multiclass', 'num_class': len(label_encoder.classes_),
            'metric': 'multi_logloss', 'learning_rate': 0.02,
            'max_depth': 4, 'num_leaves': 15, 'min_data_in_leaf': 50,
            'feature_fraction': 0.6, 'bagging_fraction': 0.7, 'bagging_freq': 5,
            'lambda_l1': 5.0, 'lambda_l2': 10.0, 'min_gain_to_split': 0.5,
            'verbose': -1, 'seed': 42
        }
        num_rounds = 500

    early_stop = 10 if n < 1000 else 20 if n < 2000 else 30

    print(f"\n[TRAINING] {num_rounds} rounds, early_stop={early_stop}")

    model = lgb.train(
        params, train_data,
        num_boost_round=num_rounds,
        valid_sets=[train_data, val_data],
        valid_names=['train', 'valid'],
        callbacks=[
            lgb.log_evaluation(period=50),
            lgb.early_stopping(stopping_rounds=early_stop, verbose=True)
        ]
    )

    y_val_pred = np.argmax(model.predict(X_val_scaled), axis=1)
    val_accuracy = accuracy_score(y_val, y_val_pred)

    print(f"\n[VALIDATION] Accuracy: {val_accuracy * 100:.2f}%")
    print(classification_report(y_val, y_val_pred, target_names=label_encoder.classes_))

    # Save everything
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    model.save_model(str(output_path / 'lightgbm_model.txt'))
    with open(output_path / 'label_mapping.json', 'w') as f:
        json.dump({str(i): l for i, l in enumerate(label_encoder.classes_)}, f, indent=2)
    with open(output_path / 'feature_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    # Export scaler as JSON for C inference (mean + std per feature)
    with open(output_path / 'feature_scaler.json', 'w') as f:
        json.dump({
            'num_features': len(feature_cols),
            'feature_names': feature_cols,
            'mean': scaler.mean_.tolist(),
            'scale': scaler.scale_.tolist(),
        }, f, indent=2)
    with open(output_path / 'feature_columns.json', 'w') as f:
        json.dump(feature_cols, f, indent=2)
    with open(output_path / 'training_metadata.json', 'w') as f:
        json.dump({
            'feature_group': mode,
            'num_features': len(feature_cols),
            'feature_columns': feature_cols,
            'train_samples': len(X_train),
            'val_samples': len(X_val),
            'val_accuracy': float(val_accuracy),
            'classes': list(label_encoder.classes_),
            'best_iteration': model.best_iteration,
        }, f, indent=2)

    # Feature importance
    importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': model.feature_importance(importance_type='gain')
    }).sort_values('importance', ascending=False)
    importance.to_csv(output_path / 'feature_importance.csv', index=False)

    print(f"\n[FEATURE IMPORTANCE] Top 10:")
    for _, row in importance.head(10).iterrows():
        print(f"  {row['feature']:30s}: {row['importance']:8.1f}")

    print(f"\n[DONE] {mode}: {val_accuracy*100:.2f}% | {output_path}")

    if val_accuracy >= 0.99:
        print("[WARNING] 99%+ accuracy may indicate overfitting")
    elif val_accuracy >= 0.95:
        print("[STATUS] Excellent (95-99%)")
    elif val_accuracy >= 0.90:
        print("[STATUS] Good (90-95%)")
    else:
        print("[RECOMMENDATION] < 90%. Collect more data.")

    return val_accuracy


def main():
    parser = argparse.ArgumentParser(description='Train LightGBM model')
    parser.add_argument('--train', required=True, help='Training CSV')
    parser.add_argument('--val', required=True, help='Validation CSV')
    parser.add_argument('--mode', required=True,
                        choices=['dpi_sketch', 'dpi_ratios', 'sketch', 'sketch_adv'],
                        help='Feature mode')
    parser.add_argument('--output', required=True, help='Output directory')
    args = parser.parse_args()
    train_and_export(args.train, args.val, args.mode, args.output)


if __name__ == '__main__':
    main()
