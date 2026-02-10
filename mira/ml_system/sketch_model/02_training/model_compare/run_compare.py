#!/usr/bin/env python3
"""
Multi-Model Comparison - Sketch Features Only (14 features)

Trains RandomForest, HistGradientBoosting, MLP, KNN, SGDClassifier, and
optionally XGBoost using only the 14 sketch features.

Usage:
    python3 run_compare.py \
        --train ../../datasets/splits/train.csv \
        --val ../../datasets/splits/val.csv \
        --test ../../datasets/splits/test.csv \
        --output-dir ../results/sketch/alt_models
"""

import argparse
import json
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier

# Add parent directories for feature_groups import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from feature_groups import get_feature_columns, SKETCH_FEATURES


def _try_import_xgboost():
    try:
        from xgboost import XGBClassifier
        return XGBClassifier
    except Exception:
        return None


def load_split(path):
    df = pd.read_csv(path)
    feature_cols = [c for c in get_feature_columns() if c in df.columns]
    return df, feature_cols


def _print_report(title, y_true, y_pred, labels):
    print(f"\n{title}")
    print("-" * 70)
    print(classification_report(y_true, y_pred, target_names=labels, zero_division=0))


def eval_model(name, model, X_val, y_val, X_test, y_test, labels):
    results = {}
    y_val_pred = model.predict(X_val)
    y_test_pred = model.predict(X_test)
    y_test_proba = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    results['val_accuracy'] = float(accuracy_score(y_val, y_val_pred))
    results['test_accuracy'] = float(accuracy_score(y_test, y_test_pred))
    results['val_report'] = classification_report(
        y_val, y_val_pred, target_names=labels, output_dict=True, zero_division=0
    )
    results['test_report'] = classification_report(
        y_test, y_test_pred, target_names=labels, output_dict=True, zero_division=0
    )
    results['val_confusion_matrix'] = confusion_matrix(y_val, y_val_pred).tolist()
    results['test_confusion_matrix'] = confusion_matrix(y_test, y_test_pred).tolist()

    print(f"\n[{name}]")
    print(f"  Val accuracy:  {results['val_accuracy'] * 100:.2f}%")
    print(f"  Test accuracy: {results['test_accuracy'] * 100:.2f}%")

    _print_report("VALIDATION RESULTS", y_val, y_val_pred, labels)
    _print_report("TEST RESULTS", y_test, y_test_pred, labels)

    # Sample predictions
    print("\nSAMPLE PREDICTIONS (First 10)")
    print(f"{'Index':<8} {'True':<14} {'Predicted':<14} {'Confidence':>10}   {'OK':<5}")
    print("-" * 60)
    for i in range(min(10, len(y_test))):
        true_lbl = labels[y_test[i]]
        pred_lbl = labels[y_test_pred[i]]
        conf = np.max(y_test_proba[i]) if y_test_proba is not None else 0.0
        correct = "YES" if y_test[i] == y_test_pred[i] else "NO"
        print(f"{i:<8d} {true_lbl:<14s} {pred_lbl:<14s} {conf:>9.3f}   {correct}")

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Compare ML models with sketch features only (14 features)'
    )
    parser.add_argument('--train', required=True, help='Train CSV')
    parser.add_argument('--val', required=True, help='Validation CSV')
    parser.add_argument('--test', required=True, help='Test CSV')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    args = parser.parse_args()

    print("=" * 70)
    print("MODEL COMPARISON - SKETCH FEATURES ONLY")
    print(f"  {len(SKETCH_FEATURES)} features (OctoSketch + Ring Buffer)")
    print("=" * 70)

    df_train, feature_cols = load_split(args.train)
    df_val, _ = load_split(args.val)
    df_test, _ = load_split(args.test)

    X_train = df_train[feature_cols].values
    X_val = df_val[feature_cols].values
    X_test = df_test[feature_cols].values

    y_train_labels = df_train['label'].values
    y_val_labels = df_val['label'].values
    y_test_labels = df_test['label'].values

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(y_train_labels)
    y_val = label_encoder.transform(y_val_labels)
    y_test = label_encoder.transform(y_test_labels)

    labels = list(label_encoder.classes_)

    print(f"\n[DATASET]")
    print(f"  Train: {len(X_train)}  Val: {len(X_val)}  Test: {len(X_test)}")
    print(f"  Features: {len(feature_cols)} (sketch)  Classes: {labels}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    XGBClassifier = _try_import_xgboost()

    models = [
        ("RandomForest", RandomForestClassifier(
            n_estimators=300, max_depth=None, n_jobs=-1, random_state=42
        ), False),
        ("HistGradientBoosting", HistGradientBoostingClassifier(
            max_depth=8, learning_rate=0.05, max_iter=300, random_state=42
        ), False),
        ("MLP", MLPClassifier(
            hidden_layer_sizes=(128, 64),
            activation='relu', solver='adam', alpha=1e-4,
            learning_rate_init=1e-3, max_iter=300, random_state=42
        ), True),
        ("KNN", KNeighborsClassifier(
            n_neighbors=15, weights='distance'
        ), True),
        ("SGDClassifier", SGDClassifier(
            loss='log_loss', alpha=1e-4, max_iter=2000, tol=1e-3, random_state=42
        ), True),
    ]

    if XGBClassifier is not None:
        models.append((
            "XGBoost",
            XGBClassifier(
                objective='multi:softprob', num_class=len(labels),
                n_estimators=300, max_depth=6, learning_rate=0.05,
                subsample=0.9, colsample_bytree=0.9, eval_metric='mlogloss',
                tree_method='hist', random_state=42
            ),
            False
        ))
    else:
        print("\n[INFO] XGBoost not installed; skipping.")

    output_root = Path(args.output_dir)
    output_root.mkdir(parents=True, exist_ok=True)

    results = {}
    for name, model, needs_scaler in models:
        X_tr = X_train_scaled if needs_scaler else X_train
        X_v = X_val_scaled if needs_scaler else X_val
        X_te = X_test_scaled if needs_scaler else X_test

        print(f"\nTraining {name} (sketch)...")
        model.fit(X_tr, y_train)
        results[name] = eval_model(name, model, X_v, y_val, X_te, y_test, labels)
        results[name]['feature_group'] = 'sketch'
        results[name]['num_features'] = len(feature_cols)

        model_dir = output_root / name.lower()
        model_dir.mkdir(parents=True, exist_ok=True)

        with open(model_dir / 'model.pkl', 'wb') as f:
            pickle.dump(model, f)
        with open(model_dir / 'label_mapping.json', 'w') as f:
            json.dump({str(i): lbl for i, lbl in enumerate(labels)}, f, indent=2)
        with open(model_dir / 'feature_scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)
        with open(model_dir / 'feature_columns.json', 'w') as f:
            json.dump(feature_cols, f, indent=2)

    # Summary
    summary = {
        'feature_group': 'sketch',
        'num_features': len(feature_cols),
        'feature_columns': feature_cols,
        'models': results,
    }
    with open(output_root / 'summary.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print("MODEL COMPARISON COMPLETE - SKETCH")
    print("=" * 70)

    print(f"\n{'Model':<25} {'Val Acc':<12} {'Test Acc':<12} {'Features':<10}")
    print("-" * 60)
    for name, res in results.items():
        print(f"{name:<25} {res['val_accuracy']*100:>8.2f}%   {res['test_accuracy']*100:>8.2f}%   {len(feature_cols)}")

    print(f"\nSaved under: {output_root}")


if __name__ == '__main__':
    main()
