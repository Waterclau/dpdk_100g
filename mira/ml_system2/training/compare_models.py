#!/usr/bin/env python3
"""
Compare ML Models (ml_system2)

Compares evaluation results from multiple trained models side by side.
Reads evaluation_results.json and training_metadata.json from each model directory.

Usage:
    python3 compare_models.py \
        --models ./results/dpi_sketch/ ./results/sketch_adv/ \
        --labels "DPI+Sketch (75)" "Sketch-ADV (64)"

    # With custom test set evaluation
    python3 compare_models.py \
        --models ./results/dpi_sketch/ ./results/sketch_adv/ \
        --test ../datasets/splits/test.csv
"""

import argparse
import json
import sys
import numpy as np
import pandas as pd
import lightgbm as lgb
import pickle
from pathlib import Path
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


def load_model_results(model_dir):
    """Load evaluation and training metadata from a model directory"""
    model_dir = Path(model_dir)
    result = {'dir': str(model_dir)}

    # Training metadata
    meta_file = model_dir / 'training_metadata.json'
    if meta_file.exists():
        with open(meta_file, 'r') as f:
            meta = json.load(f)
        result['feature_group'] = meta.get('feature_group', 'unknown')
        result['num_features'] = meta.get('num_features', 0)
        result['train_samples'] = meta.get('train_samples', 0)
        result['val_accuracy'] = meta.get('val_accuracy', 0)
        result['classes'] = meta.get('classes', [])
        result['feature_columns'] = meta.get('feature_columns', [])

    # Evaluation results
    eval_file = model_dir / 'evaluation_results.json'
    if eval_file.exists():
        with open(eval_file, 'r') as f:
            result['eval'] = json.load(f)
    else:
        result['eval'] = None

    # Feature importance
    fi_file = model_dir / 'feature_importance.csv'
    if fi_file.exists():
        result['feature_importance'] = pd.read_csv(fi_file)

    return result


def evaluate_on_test(model_dir, test_csv):
    """Re-evaluate a model on a specific test set"""
    model_dir = Path(model_dir)

    # Load model
    model_file = model_dir / 'lightgbm_model.txt'
    if not model_file.exists():
        print(f"[ERROR] No model found: {model_file}")
        return None

    model = lgb.Booster(model_file=str(model_file))

    # Load metadata
    meta_file = model_dir / 'training_metadata.json'
    with open(meta_file, 'r') as f:
        meta = json.load(f)
    feature_cols = meta.get('feature_columns', [])

    # Load label mapping
    mapping_file = model_dir / 'label_mapping.json'
    with open(mapping_file, 'r') as f:
        mapping = json.load(f)
    inv_mapping = {v: int(k) for k, v in mapping.items()}
    ordered_labels = [label for _, label in sorted((int(k), v) for k, v in mapping.items())]

    # Load test data
    df = pd.read_csv(test_csv)
    available = [c for c in feature_cols if c in df.columns]

    if len(available) < len(feature_cols):
        missing = set(feature_cols) - set(available)
        return None  # Can't evaluate with missing features

    X_test = df[available].values
    y_test_labels = df['label'].values

    # Check all labels are known
    unknown = set(y_test_labels) - set(inv_mapping.keys())
    if unknown:
        return None

    y_test = np.array([inv_mapping[label] for label in y_test_labels])

    # Scale
    scaler_path = model_dir / 'feature_scaler.pkl'
    if scaler_path.exists():
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        X_test = scaler.transform(X_test)

    # Predict
    y_pred_proba = model.predict(X_test)
    y_pred = np.argmax(y_pred_proba, axis=1)

    accuracy = accuracy_score(y_test, y_pred)
    f1_w = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_m = f1_score(y_test, y_pred, average='macro', zero_division=0)
    precision = precision_score(y_test, y_pred, average=None, zero_division=0)
    recall_vals = recall_score(y_test, y_pred, average=None, zero_division=0)
    f1_vals = f1_score(y_test, y_pred, average=None, zero_division=0)

    return {
        'accuracy': accuracy,
        'weighted_f1': f1_w,
        'macro_f1': f1_m,
        'per_class': {
            cls: {'precision': float(precision[i]), 'recall': float(recall_vals[i]), 'f1': float(f1_vals[i])}
            for i, cls in enumerate(ordered_labels)
        }
    }


def print_comparison(models, labels, test_results=None):
    """Print side-by-side comparison table"""
    n = len(models)

    print("=" * 80)
    print("MODEL COMPARISON")
    print("=" * 80)

    # Header
    header = f"  {'Metric':<25}"
    for label in labels:
        header += f" {label:>20}"
    print(header)
    print("  " + "-" * (25 + 21 * n))

    # Use test_results if provided, otherwise use stored eval
    results = []
    for i, m in enumerate(models):
        if test_results and test_results[i]:
            results.append(test_results[i])
        elif m.get('eval'):
            results.append(m['eval'])
        else:
            results.append(None)

    # Basic metrics
    for metric, key in [('Features', None), ('Accuracy', 'accuracy'),
                         ('Weighted F1', 'weighted_f1'), ('Macro F1', 'macro_f1')]:
        row = f"  {metric:<25}"
        for i in range(n):
            if key is None:
                row += f" {models[i].get('num_features', '?'):>20}"
            elif results[i]:
                val = results[i].get(key, 0)
                row += f" {val*100:>19.2f}%"
            else:
                row += f" {'N/A':>20}"
        print(row)

    # Per-class F1
    all_classes = set()
    for r in results:
        if r and 'per_class' in r:
            all_classes.update(r['per_class'].keys())

    if all_classes:
        print(f"\n  {'Per-Class F1':<25}" + " " * 21 * n)
        print("  " + "-" * (25 + 21 * n))

        for cls in sorted(all_classes):
            row = f"  {cls:<25}"
            for i in range(n):
                if results[i] and cls in results[i].get('per_class', {}):
                    f1 = results[i]['per_class'][cls]['f1']
                    recall = results[i]['per_class'][cls]['recall']
                    row += f" {f1:>8.3f} (R={recall:.2f})"
                else:
                    row += f" {'N/A':>20}"
            print(row)

    # Feature importance comparison
    print(f"\n  {'Top Features':<25}")
    print("  " + "-" * (25 + 21 * n))
    for rank in range(5):
        row = f"  #{rank+1:<24}"
        for i in range(n):
            if 'feature_importance' in models[i]:
                fi = models[i]['feature_importance']
                if rank < len(fi):
                    feat = fi.iloc[rank]['feature']
                    row += f" {feat:>20}"
                else:
                    row += f" {'-':>20}"
            else:
                row += f" {'N/A':>20}"
        print(row)

    # Verdict
    print(f"\n  {'VERDICT':<25}")
    print("  " + "-" * (25 + 21 * n))

    best_acc = -1
    best_idx = 0
    for i, r in enumerate(results):
        if r and r.get('accuracy', 0) > best_acc:
            best_acc = r['accuracy']
            best_idx = i

    for i in range(n):
        if results[i]:
            acc = results[i].get('accuracy', 0)
            diff = (acc - best_acc) * 100
            if i == best_idx:
                status = "BEST"
            elif acc >= 0.90:
                status = f"OK ({diff:+.2f}pp)"
            else:
                status = f"BELOW 90% ({diff:+.2f}pp)"
            print(f"  {labels[i]:<25} {status}")

    print()


def main():
    parser = argparse.ArgumentParser(description='Compare trained ML models')
    parser.add_argument('--models', required=True, nargs='+',
                        help='Model directories to compare')
    parser.add_argument('--labels', nargs='+',
                        help='Display labels for each model (default: auto from metadata)')
    parser.add_argument('--test', type=str, default=None,
                        help='Re-evaluate all models on this test CSV')

    args = parser.parse_args()

    if args.labels and len(args.labels) != len(args.models):
        print("[ERROR] Number of labels must match number of models")
        sys.exit(1)

    models = []
    for model_dir in args.models:
        if not Path(model_dir).exists():
            print(f"[WARNING] Not found: {model_dir}")
            models.append({'dir': model_dir, 'feature_group': 'missing'})
            continue
        models.append(load_model_results(model_dir))

    # Auto-generate labels if not provided
    if args.labels:
        labels = args.labels
    else:
        labels = []
        for m in models:
            fg = m.get('feature_group', 'unknown')
            nf = m.get('num_features', '?')
            labels.append(f"{fg} ({nf})")

    # Re-evaluate on test set if requested
    test_results = None
    if args.test:
        if not Path(args.test).exists():
            print(f"[ERROR] Test file not found: {args.test}")
            sys.exit(1)
        print(f"[INFO] Re-evaluating on: {args.test}")
        test_results = []
        for m in models:
            r = evaluate_on_test(m['dir'], args.test)
            test_results.append(r)

    print_comparison(models, labels, test_results)


if __name__ == '__main__':
    main()
