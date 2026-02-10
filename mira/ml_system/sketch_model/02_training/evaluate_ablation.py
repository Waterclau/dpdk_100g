#!/usr/bin/env python3
"""
Evaluate LightGBM Model from Ablation Study

Evaluates a trained model on the test set, respecting the feature group
that was used during training.

Usage:
    python3 evaluate_ablation.py \
        --model ./results/dpi/lightgbm_model.txt \
        --test ../datasets/splits/test.csv

    python3 evaluate_ablation.py \
        --model ./results/sketch/lightgbm_model.txt \
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
    """Evaluate a trained ablation model on the test set"""

    model_dir = Path(model_path).parent

    # Load training metadata to know which feature group was used
    metadata_file = model_dir / 'training_metadata.json'
    if metadata_file.exists():
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        feature_group = metadata.get('feature_group', 'unknown')
        feature_cols = metadata.get('feature_columns', [])
    else:
        # Fallback: load feature columns file
        fcols_file = model_dir / 'feature_columns.json'
        if fcols_file.exists():
            with open(fcols_file, 'r') as f:
                feature_cols = json.load(f)
        else:
            print("[ERROR] No feature_columns.json or training_metadata.json found.")
            return
        feature_group = 'unknown'

    print("=" * 70)
    print(f"ABLATION STUDY - Model Evaluation")
    print(f"Feature Group: {feature_group.upper()} ({len(feature_cols)} features)")
    print("=" * 70)

    # Load test data
    print(f"\n[INFO] Loading test data: {test_csv}")
    df = pd.read_csv(test_csv)

    X_test = df[feature_cols].values
    y_test_labels = df['label'].values

    # Load label mapping
    mapping_file = model_dir / 'label_mapping.json'
    with open(mapping_file, 'r') as f:
        mapping = json.load(f)

    inv_mapping = {v: int(k) for k, v in mapping.items()}
    y_test = np.array([inv_mapping[label] for label in y_test_labels])

    ordered_labels = [label for _, label in sorted((int(k), v) for k, v in mapping.items())]
    label_encoder = LabelEncoder()
    label_encoder.fit(ordered_labels)

    print(f"[INFO] Test samples:  {len(X_test)}")
    print(f"[INFO] Features:      {len(feature_cols)}")
    print(f"[INFO] Classes:       {list(label_encoder.classes_)}")

    # Load model
    print(f"\n[INFO] Loading model: {model_path}")
    model = lgb.Booster(model_file=model_path)

    # Load scaler if exists
    scaler_path = model_dir / 'feature_scaler.pkl'
    if scaler_path.exists():
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        X_test = scaler.transform(X_test)

    # Predictions
    y_pred_proba = model.predict(X_test)
    y_pred = np.argmax(y_pred_proba, axis=1)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)

    print("\n" + "=" * 70)
    print(f"EVALUATION RESULTS - {feature_group.upper()}")
    print("=" * 70)
    print(f"\nOverall Accuracy: {accuracy * 100:.2f}%")

    # Per-class metrics
    precision = precision_score(y_test, y_pred, average=None, zero_division=0)
    recall = recall_score(y_test, y_pred, average=None, zero_division=0)
    f1 = f1_score(y_test, y_pred, average=None, zero_division=0)

    print(f"\n{'Class':<15} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
    print("-" * 55)
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"{class_name:<15} {precision[i]:<12.3f} {recall[i]:<12.3f} {f1[i]:<12.3f}")

    # Weighted averages
    precision_w = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall_w = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)

    print(f"\nWeighted:  Precision={precision_w:.3f}  Recall={recall_w:.3f}  F1={f1_w:.3f}")
    print(f"Macro F1:  {f1_macro:.3f}")

    # Confusion matrix
    print("\n" + "=" * 70)
    print("CONFUSION MATRIX")
    print("=" * 70)
    cm = confusion_matrix(y_test, y_pred)

    header = "True\\Pred".ljust(15)
    for class_name in label_encoder.classes_:
        header += f"{class_name[:8]:<10}"
    print(header)
    print("-" * (15 + 10 * len(label_encoder.classes_)))

    for i, class_name in enumerate(label_encoder.classes_):
        row = f"{class_name[:8]:<15}"
        for j in range(len(label_encoder.classes_)):
            row += f"{cm[i][j]:<10}"
        print(row)

    # Sample predictions
    print(f"\n{'Index':<8} {'True':<15} {'Predicted':<15} {'Confidence':<12} {'OK':<5}")
    print("-" * 55)
    for i in range(min(10, len(y_test))):
        true_label = label_encoder.classes_[y_test[i]]
        pred_label = label_encoder.classes_[y_pred[i]]
        confidence = y_pred_proba[i][y_pred[i]]
        ok = "YES" if y_test[i] == y_pred[i] else "NO"
        print(f"{i:<8} {true_label:<15} {pred_label:<15} {confidence:<12.3f} {ok:<5}")

    # Save evaluation results
    results = {
        'feature_group': feature_group,
        'num_features': len(feature_cols),
        'test_samples': len(X_test),
        'accuracy': float(accuracy),
        'weighted_f1': float(f1_w),
        'macro_f1': float(f1_macro),
        'weighted_precision': float(precision_w),
        'weighted_recall': float(recall_w),
        'per_class': {}
    }
    for i, class_name in enumerate(label_encoder.classes_):
        results['per_class'][class_name] = {
            'precision': float(precision[i]),
            'recall': float(recall[i]),
            'f1': float(f1[i]),
        }

    eval_file = model_dir / 'evaluation_results.json'
    with open(eval_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[SAVED] Evaluation results: {eval_file}")

    print("\n" + "=" * 70)
    print(f"EVALUATION COMPLETE - {feature_group.upper()}: {accuracy * 100:.2f}%")
    print("=" * 70)

    return results


def main():
    parser = argparse.ArgumentParser(
        description='Evaluate ablation study model on test set'
    )
    parser.add_argument('--model', required=True, help='Path to trained model (.txt)')
    parser.add_argument('--test', required=True, help='Path to test CSV file')

    args = parser.parse_args()

    if not Path(args.model).exists():
        print(f"[ERROR] Model not found: {args.model}")
        return
    if not Path(args.test).exists():
        print(f"[ERROR] Test file not found: {args.test}")
        return

    evaluate_model(args.model, args.test)


if __name__ == '__main__':
    main()
