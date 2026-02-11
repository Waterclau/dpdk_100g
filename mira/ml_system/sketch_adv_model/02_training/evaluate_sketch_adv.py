#!/usr/bin/env python3
"""
Evaluate LightGBM Model - Sketch-ADV (64 features)

Evaluates a trained model on the test set, respecting the feature group
that was used during training.

Usage:
    python3 evaluate_sketch_adv.py \
        --model ./results/sketch_adv/lightgbm/lightgbm_model.txt \
        --test ../datasets/splits/test.csv
"""

import argparse
import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from pathlib import Path
import json
import pickle


def evaluate_model(model_path: str, test_csv: str):
    """Evaluate trained model on test set"""

    model_dir = Path(model_path).parent

    # Load metadata
    metadata_file = model_dir / 'training_metadata.json'
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        feature_group = metadata.get('feature_group', 'unknown')
        feature_cols = metadata.get('feature_columns', [])
    else:
        fcols_file = model_dir / 'feature_columns.json'
        if fcols_file.exists():
            with open(fcols_file, 'r') as f:
                feature_cols = json.load(f)
        else:
            print("[ERROR] No metadata found")
            return
        feature_group = 'unknown'

    print("=" * 70)
    print(f"EVALUATION - {feature_group.upper()} ({len(feature_cols)} features)")
    print("=" * 70)

    df = pd.read_csv(test_csv)

    # Only use features that exist in test data
    available = [c for c in feature_cols if c in df.columns]
    if len(available) < len(feature_cols):
        missing = set(feature_cols) - set(available)
        print(f"[WARNING] {len(missing)} features missing: {list(missing)[:3]}...")

    X_test = df[available].values
    y_test_labels = df['label'].values

    # Load label mapping
    mapping_file = model_dir / 'label_mapping.json'
    with open(mapping_file, 'r') as f:
        mapping = json.load(f)

    inv_mapping = {v: int(k) for k, v in mapping.items()}
    y_test = np.array([inv_mapping[label] for label in y_test_labels])

    ordered_labels = [label for _, label in sorted((int(k), v) for k, v in mapping.items())]
    le = LabelEncoder()
    le.fit(ordered_labels)

    print(f"  Test: {len(X_test)} samples, {len(available)} features")
    print(f"  Classes: {list(le.classes_)}")

    # Load model + scaler
    model = lgb.Booster(model_file=model_path)
    scaler_path = model_dir / 'feature_scaler.pkl'
    if scaler_path.exists():
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        X_test = scaler.transform(X_test)

    # Predict
    y_pred_proba = model.predict(X_test)
    y_pred = np.argmax(y_pred_proba, axis=1)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average=None, zero_division=0)
    recall = recall_score(y_test, y_pred, average=None, zero_division=0)
    f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
    f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_m = f1_score(y_test, y_pred, average='macro', zero_division=0)

    print(f"\n  Overall Accuracy: {accuracy * 100:.2f}%")
    print(f"\n  {'Class':<15} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("  " + "-" * 50)
    for i, cls in enumerate(le.classes_):
        print(f"  {cls:<15} {precision[i]:<12.3f} {recall[i]:<12.3f} {f1[i]:<12.3f}")
    print(f"\n  Weighted F1: {f1_w:.3f} | Macro F1: {f1_m:.3f}")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\n  Confusion Matrix:")
    header = "  " + "True\\Pred".ljust(12)
    for cls in le.classes_:
        header += f"{cls[:8]:<10}"
    print(header)
    for i, cls in enumerate(le.classes_):
        row = f"  {cls[:8]:<12}"
        for j in range(len(le.classes_)):
            row += f"{cm[i][j]:<10}"
        print(row)

    # Sample predictions
    print(f"\n  {'#':<4} {'True':<12} {'Pred':<12} {'Conf':<8} {'OK'}")
    print("  " + "-" * 40)
    for i in range(min(10, len(y_test))):
        true = le.classes_[y_test[i]]
        pred = le.classes_[y_pred[i]]
        conf = y_pred_proba[i][y_pred[i]]
        ok = "YES" if y_test[i] == y_pred[i] else "NO"
        print(f"  {i:<4} {true:<12} {pred:<12} {conf:<8.3f} {ok}")

    # Save results
    results = {
        'feature_group': feature_group,
        'num_features': len(available),
        'test_samples': len(X_test),
        'accuracy': float(accuracy),
        'weighted_f1': float(f1_w),
        'macro_f1': float(f1_m),
        'per_class': {
            cls: {'precision': float(precision[i]), 'recall': float(recall[i]), 'f1': float(f1[i])}
            for i, cls in enumerate(le.classes_)
        }
    }
    eval_file = model_dir / 'evaluation_results.json'
    with open(eval_file, 'w') as f:
        json.dump(results, f, indent=2)

    if accuracy >= 0.95:
        status = "EXCELLENT"
    elif accuracy >= 0.90:
        status = "GOOD"
    elif accuracy >= 0.80:
        status = "ACCEPTABLE"
    else:
        status = "NEEDS IMPROVEMENT"

    print(f"\n  [{status}] {accuracy*100:.2f}% accuracy | {f1_w:.3f} weighted F1")
    print(f"  Saved: {eval_file}")

    return results


def main():
    parser = argparse.ArgumentParser(description='Evaluate sketch-adv model')
    parser.add_argument('--model', required=True, help='Model file (.txt)')
    parser.add_argument('--test', required=True, help='Test CSV')
    args = parser.parse_args()

    if not Path(args.model).exists():
        print(f"[ERROR] Not found: {args.model}")
        return
    if not Path(args.test).exists():
        print(f"[ERROR] Not found: {args.test}")
        return

    evaluate_model(args.model, args.test)


if __name__ == '__main__':
    main()
