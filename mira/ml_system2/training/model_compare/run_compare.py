#!/usr/bin/env python3
"""
Model Comparison (ml_system2 - shared)

Trains multiple ML algorithms and compares performance.
Algorithms: Random Forest, Histogram Gradient Boosting, MLP, KNN, SGD

Usage:
    python3 run_compare.py \
        --train ../../datasets/splits/train.csv \
        --val ../../datasets/splits/val.csv \
        --test ../../datasets/splits/test.csv \
        --output-dir ./results/
"""

import argparse
import json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier


def main():
    parser = argparse.ArgumentParser(description='Compare ML models')
    parser.add_argument('--train', required=True)
    parser.add_argument('--val', required=True)
    parser.add_argument('--test', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    df_train = pd.read_csv(args.train)
    df_val = pd.read_csv(args.val)
    df_test = pd.read_csv(args.test)

    exclude = {'label', 'timestamp', 'run_id'}
    feature_cols = [c for c in df_train.columns if c not in exclude]

    X_train = df_train[feature_cols].values
    X_val = df_val[feature_cols].values
    X_test = df_test[feature_cols].values

    le = LabelEncoder()
    y_train = le.fit_transform(df_train['label'].values)
    y_val = le.transform(df_val['label'].values)
    y_test = le.transform(df_test['label'].values)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)
    X_test_s = scaler.transform(X_test)

    print("=" * 70)
    print(f"MODEL COMPARISON ({len(feature_cols)} features)")
    print(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")
    print(f"Classes: {list(le.classes_)}")
    print("=" * 70)

    models = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200, max_depth=8, min_samples_leaf=5, random_state=42, n_jobs=-1),
        'HistGradientBoosting': HistGradientBoostingClassifier(
            max_iter=200, max_depth=6, min_samples_leaf=10, random_state=42),
        'MLP': MLPClassifier(
            hidden_layer_sizes=(128, 64), max_iter=500, early_stopping=True,
            validation_fraction=0.15, random_state=42),
        'KNN': KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        'SGD': SGDClassifier(loss='modified_huber', max_iter=1000, random_state=42),
    }

    results = {'num_features': len(feature_cols), 'models': {}}

    for name, model in models.items():
        print(f"\n--- {name} ---")
        model.fit(X_train_s, y_train)

        val_acc = accuracy_score(y_val, model.predict(X_val_s))
        test_pred = model.predict(X_test_s)
        test_acc = accuracy_score(y_test, test_pred)
        test_f1 = f1_score(y_test, test_pred, average='weighted', zero_division=0)
        report = classification_report(y_test, test_pred, target_names=le.classes_, output_dict=True)

        print(f"  Val: {val_acc*100:.2f}% | Test: {test_acc*100:.2f}% (F1={test_f1:.3f})")

        results['models'][name] = {
            'val_accuracy': float(val_acc),
            'test_accuracy': float(test_acc),
            'test_report': report,
        }

    # Summary
    print(f"\n{'='*60}")
    print(f"{'Model':<25} {'Val Acc':<12} {'Test Acc':<12} {'Test F1':<10}")
    print("-" * 60)
    for name, data in results['models'].items():
        print(f"{name:<25} {data['val_accuracy']*100:>8.2f}%   "
              f"{data['test_accuracy']*100:>8.2f}%   "
              f"{data['test_report']['weighted avg']['f1-score']:>8.3f}")

    # Save
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / 'summary.json', 'w') as f:
        json.dump(results, f, indent=2, default=float)
    print(f"\n[SAVED] {out / 'summary.json'}")


if __name__ == '__main__':
    main()
