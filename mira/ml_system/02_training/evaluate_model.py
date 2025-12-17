#!/usr/bin/env python3
"""
Evaluate LightGBM Model
Tests trained model on test set and generates metrics

Usage:
    python3 evaluate_model.py \
        --model ../../detector_system_ml/lightgbm_model.txt \
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


def evaluate_model(model_path: str, test_csv: str):
    """Evaluate LightGBM model on test set"""

    print("="*70)
    print("LIGHTGBM MODEL EVALUATION")
    print("="*70)

    # Load test data
    print(f"\n[INFO] Loading test data: {test_csv}")
    df = pd.read_csv(test_csv)

    # Prepare features (exclude 'label' and 'timestamp' if present)
    exclude_cols = ['label']
    if 'timestamp' in df.columns:
        exclude_cols.append('timestamp')

    feature_cols = [col for col in df.columns if col not in exclude_cols]
    X_test = df[feature_cols].values
    y_test_labels = df['label'].values

    # Encode labels
    label_encoder = LabelEncoder()
    y_test = label_encoder.fit_transform(y_test_labels)

    print(f"[INFO] Test samples: {len(X_test)}")
    print(f"[INFO] Features: {len(feature_cols)}")
    print(f"[INFO] Classes: {list(label_encoder.classes_)}")

    # Load model
    print(f"\n[INFO] Loading model: {model_path}")
    model = lgb.Booster(model_file=model_path)

    # Make predictions
    print("\n[INFO] Making predictions...")
    y_pred_proba = model.predict(X_test)
    y_pred = np.argmax(y_pred_proba, axis=1)

    # Calculate metrics
    print("\n" + "="*70)
    print("EVALUATION METRICS")
    print("="*70)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nOverall Accuracy: {accuracy*100:.2f}%")

    # Per-class metrics
    print("\nPer-Class Metrics:")
    print("-" * 70)

    precision = precision_score(y_test, y_pred, average=None, zero_division=0)
    recall = recall_score(y_test, y_pred, average=None, zero_division=0)
    f1 = f1_score(y_test, y_pred, average=None, zero_division=0)

    print(f"{'Class':<15} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
    print("-" * 70)
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"{class_name:<15} {precision[i]:<12.3f} {recall[i]:<12.3f} {f1[i]:<12.3f}")

    # Weighted averages
    print("\nWeighted Averages:")
    print("-" * 70)
    precision_weighted = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall_weighted = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    print(f"Precision: {precision_weighted:.3f}")
    print(f"Recall:    {recall_weighted:.3f}")
    print(f"F1-Score:  {f1_weighted:.3f}")

    # Confusion matrix
    print("\n" + "="*70)
    print("CONFUSION MATRIX")
    print("="*70)
    cm = confusion_matrix(y_test, y_pred)

    # Print header
    header = "True\\Pred".ljust(15)
    for class_name in label_encoder.classes_:
        header += f"{class_name[:10]:<12}"
    print(header)
    print("-" * 70)

    # Print matrix rows
    for i, class_name in enumerate(label_encoder.classes_):
        row = f"{class_name[:10]:<15}"
        for j in range(len(label_encoder.classes_)):
            row += f"{cm[i][j]:<12}"
        print(row)

    # Classification report
    print("\n" + "="*70)
    print("DETAILED CLASSIFICATION REPORT")
    print("="*70)
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Sample predictions
    print("\n" + "="*70)
    print("SAMPLE PREDICTIONS (First 10)")
    print("="*70)

    print(f"{'Index':<8} {'True Label':<15} {'Predicted':<15} {'Confidence':<12} {'Correct':<10}")
    print("-" * 70)

    for i in range(min(10, len(y_test))):
        true_label = label_encoder.classes_[y_test[i]]
        pred_label = label_encoder.classes_[y_pred[i]]
        confidence = y_pred_proba[i][y_pred[i]]
        correct = "✓" if y_test[i] == y_pred[i] else "✗"

        print(f"{i:<8} {true_label:<15} {pred_label:<15} {confidence:<12.3f} {correct:<10}")

    # Check for label mapping file
    model_dir = Path(model_path).parent
    mapping_file = model_dir / 'label_mapping.json'

    if mapping_file.exists():
        print(f"\n[INFO] Label mapping found: {mapping_file}")
        with open(mapping_file, 'r') as f:
            mapping = json.load(f)
        print("[INFO] Label mapping:")
        for idx, label in mapping.items():
            print(f"  {idx}: {label}")

    # Performance summary
    print("\n" + "="*70)
    print("PERFORMANCE SUMMARY")
    print("="*70)

    if accuracy >= 0.95:
        status = "✓ EXCELLENT"
    elif accuracy >= 0.90:
        status = "✓ GOOD"
    elif accuracy >= 0.80:
        status = "⚠ ACCEPTABLE"
    else:
        status = "✗ NEEDS IMPROVEMENT"

    print(f"\nModel Performance: {status}")
    print(f"Accuracy: {accuracy*100:.2f}%")
    print(f"Weighted F1: {f1_weighted:.3f}")

    if accuracy < 0.90:
        print("\n[RECOMMENDATION] Consider:")
        print("  - Collecting more training data")
        print("  - Feature engineering (add new features)")
        print("  - Hyperparameter tuning")
        print("  - Checking for data quality issues")

    print("\n" + "="*70)
    print("EVALUATION COMPLETE")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Evaluate trained LightGBM model',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Evaluate model on test set
  python3 evaluate_model.py \\
      --model ../../detector_system_ml/lightgbm_model.txt \\
      --test ../datasets/splits/test.csv
        """
    )

    parser.add_argument('--model', type=str, required=True,
                       help='Path to trained model file (.txt)')
    parser.add_argument('--test', type=str, required=True,
                       help='Path to test CSV file')

    args = parser.parse_args()

    # Validate files exist
    if not Path(args.model).exists():
        print(f"[ERROR] Model file not found: {args.model}")
        return

    if not Path(args.test).exists():
        print(f"[ERROR] Test file not found: {args.test}")
        return

    # Run evaluation
    evaluate_model(args.model, args.test)


if __name__ == '__main__':
    main()
