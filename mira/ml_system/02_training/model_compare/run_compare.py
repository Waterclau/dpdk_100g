#!/usr/bin/env python3
"""
Train and evaluate multiple non-LightGBM models using the same splits.

Usage:
    python3 run_compare.py \
        --train ../../datasets/splits/train.csv \
        --val ../../datasets/splits/val.csv \
        --test ../../datasets/splits/test.csv \
        --output-dir ../../../detector_system_ml/alt_models
"""

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier


def _try_import_xgboost():
    try:
        from xgboost import XGBClassifier  # type: ignore
        return XGBClassifier
    except Exception:
        return None


def load_split(path):
    df = pd.read_csv(path)
    exclude_cols = ['label']
    if 'timestamp' in df.columns:
        exclude_cols.append('timestamp')
    feature_cols = [c for c in df.columns if c not in exclude_cols]
    return df, feature_cols


def eval_model(name, model, X_val, y_val, X_test, y_test, labels):
    results = {}
    y_val_pred = model.predict(X_val)
    y_test_pred = model.predict(X_test)

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
    print(f"  Val accuracy:  {results['val_accuracy']*100:.2f}%")
    print(f"  Test accuracy: {results['test_accuracy']*100:.2f}%")
    return results


def main():
    parser = argparse.ArgumentParser(description='Compare ML models on fixed splits')
    parser.add_argument('--train', required=True, help='Train CSV')
    parser.add_argument('--val', required=True, help='Validation CSV')
    parser.add_argument('--test', required=True, help='Test CSV')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    args = parser.parse_args()

    print("=" * 70)
    print("MODEL COMPARISON (NON-LIGHTGBM)")
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
    print(f"  Features: {len(feature_cols)}  Classes: {labels}")

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
            activation='relu',
            solver='adam',
            alpha=1e-4,
            learning_rate_init=1e-3,
            max_iter=300,
            random_state=42
        ), True),
        ("KNN", KNeighborsClassifier(
            n_neighbors=15, weights='distance'
        ), True),
        ("SGDClassifier", SGDClassifier(
            loss='log_loss',
            alpha=1e-4,
            max_iter=2000,
            tol=1e-3,
            random_state=42
        ), True),
    ]

    if XGBClassifier is not None:
        models.append((
            "XGBoost",
            XGBClassifier(
                objective='multi:softprob',
                num_class=len(labels),
                n_estimators=300,
                max_depth=6,
                learning_rate=0.05,
                subsample=0.9,
                colsample_bytree=0.9,
                eval_metric='mlogloss',
                tree_method='hist',
                random_state=42
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

        print(f"\nTraining {name}...")
        model.fit(X_tr, y_train)
        results[name] = eval_model(name, model, X_v, y_val, X_te, y_test, labels)

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

    with open(output_root / 'summary.json', 'w') as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("MODEL COMPARISON COMPLETE")
    print("=" * 70)
    print(f"Saved results under: {output_root}")


if __name__ == '__main__':
    main()
