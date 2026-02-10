#!/usr/bin/env python3
"""
Full Sketch Training Pipeline

Runs the complete sketch-only training:
  1. Trains LightGBM with 14 sketch features
  2. Evaluates on the test set
  3. Runs model comparison (RF, XGB, MLP, KNN, SGD)
  4. Produces a comparison table

Usage:
    python3 run_full_ablation.py \
        --train ../datasets/splits/train.csv \
        --val ../datasets/splits/val.csv \
        --test ../datasets/splits/test.csv \
        --output ./results/

    # Run only LightGBM (skip model comparison):
    python3 run_full_ablation.py \
        --train ../datasets/splits/train.csv \
        --val ../datasets/splits/val.csv \
        --test ../datasets/splits/test.csv \
        --output ./results/ \
        --lightgbm-only
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from feature_groups import SKETCH_FEATURES


def run_lightgbm(train_csv, val_csv, test_csv, output_dir):
    """Train and evaluate LightGBM with sketch features"""
    group_dir = Path(output_dir) / 'sketch' / 'lightgbm'

    print(f"\n{'='*70}")
    print(f"  LIGHTGBM - SKETCH ONLY ({len(SKETCH_FEATURES)} features)")
    print(f"{'='*70}")

    # Train
    train_script = str(Path(__file__).parent / 'train_ablation.py')
    subprocess.run([
        sys.executable, train_script,
        '--train', train_csv,
        '--val', val_csv,
        '--output', str(group_dir),
    ], check=True)

    # Evaluate on test set
    eval_script = str(Path(__file__).parent / 'evaluate_ablation.py')
    subprocess.run([
        sys.executable, eval_script,
        '--model', str(group_dir / 'lightgbm_model.txt'),
        '--test', test_csv,
    ], check=True)

    # Read results
    eval_file = group_dir / 'evaluation_results.json'
    if eval_file.exists():
        with open(eval_file, 'r') as f:
            return json.load(f)
    return None


def run_model_compare(train_csv, val_csv, test_csv, output_dir):
    """Run multi-model comparison with sketch features"""
    alt_dir = Path(output_dir) / 'sketch' / 'alt_models'

    print(f"\n{'='*70}")
    print(f"  MODEL COMPARISON - SKETCH ONLY")
    print(f"{'='*70}")

    compare_script = str(Path(__file__).parent / 'model_compare' / 'run_compare.py')
    subprocess.run([
        sys.executable, compare_script,
        '--train', train_csv,
        '--val', val_csv,
        '--test', test_csv,
        '--output-dir', str(alt_dir),
    ], check=True)

    # Read results
    summary_file = alt_dir / 'summary.json'
    if summary_file.exists():
        with open(summary_file, 'r') as f:
            return json.load(f)
    return None


def print_comparison_table(lgb_result, alt_result):
    """Print the final comparison table"""

    print("\n")
    print("=" * 80)
    print("  SKETCH-ONLY MODEL COMPARISON")
    print("=" * 80)

    print(f"\n{'Model':<25} {'Features':<10} {'Val Acc':<12} {'Test Acc':<12} {'Test F1':<10}")
    print("-" * 75)

    rows = []

    # LightGBM results
    if lgb_result:
        num_feat = lgb_result.get('num_features', len(SKETCH_FEATURES))
        rows.append({
            'model': 'LightGBM',
            'features': num_feat,
            'test_acc': lgb_result.get('accuracy', 0),
            'test_f1': lgb_result.get('weighted_f1', 0),
        })
        print(f"{'LightGBM':<25} {num_feat:<10} "
              f"{'--':>8}     {lgb_result.get('accuracy', 0)*100:>8.2f}%   "
              f"{lgb_result.get('weighted_f1', 0):>8.3f}")

    # Alt model results
    if alt_result and 'models' in alt_result:
        num_feat = alt_result.get('num_features', len(SKETCH_FEATURES))
        for model_name, model_data in alt_result['models'].items():
            rows.append({
                'model': model_name,
                'features': num_feat,
                'val_acc': model_data.get('val_accuracy', 0),
                'test_acc': model_data.get('test_accuracy', 0),
                'test_f1': model_data.get('test_report', {}).get('weighted avg', {}).get('f1-score', 0),
            })
            print(f"{model_name:<25} {num_feat:<10} "
                  f"{model_data.get('val_accuracy', 0)*100:>8.2f}%   "
                  f"{model_data.get('test_accuracy', 0)*100:>8.2f}%   "
                  f"{model_data.get('test_report', {}).get('weighted avg', {}).get('f1-score', 0):>8.3f}")

    print("=" * 80)

    # Best model
    if rows:
        best = max(rows, key=lambda r: r.get('test_acc', 0))
        print(f"\n[BEST] {best['model']} - Test Accuracy: {best['test_acc']*100:.2f}%")

    return rows


def main():
    parser = argparse.ArgumentParser(
        description='Run full sketch-only training pipeline'
    )
    parser.add_argument('--train', required=True, help='Training CSV')
    parser.add_argument('--val', required=True, help='Validation CSV')
    parser.add_argument('--test', required=True, help='Test CSV')
    parser.add_argument('--output', required=True, help='Output directory for all results')
    parser.add_argument('--lightgbm-only', action='store_true',
                        help='Only train LightGBM (skip model comparison)')

    args = parser.parse_args()

    print("=" * 70)
    print("  SKETCH-ONLY TRAINING PIPELINE")
    print(f"  {len(SKETCH_FEATURES)} features (OctoSketch + Ring Buffer)")
    print("=" * 70)
    print(f"\nModels: LightGBM" + (" + RF, XGB, MLP, KNN, SGD" if not args.lightgbm_only else ""))
    print(f"Output: {args.output}")

    # LightGBM
    lgb_result = run_lightgbm(args.train, args.val, args.test, args.output)

    # Model comparison
    alt_result = None
    if not args.lightgbm_only:
        alt_result = run_model_compare(args.train, args.val, args.test, args.output)

    # Print final comparison
    rows = print_comparison_table(lgb_result, alt_result)

    # Save combined results
    output_path = Path(args.output)
    combined = {
        'feature_group': 'sketch',
        'num_features': len(SKETCH_FEATURES),
        'lightgbm': lgb_result,
        'alt_models': alt_result,
    }
    with open(output_path / 'sketch_results.json', 'w') as f:
        json.dump(combined, f, indent=2)

    # Save CSV summary
    if rows:
        df = pd.DataFrame(rows)
        csv_path = output_path / 'sketch_summary.csv'
        df.to_csv(csv_path, index=False)
        print(f"\n[SAVED] Combined results: {output_path / 'sketch_results.json'}")
        print(f"[SAVED] Summary CSV:      {csv_path}")

    print("\n[DONE] Sketch training pipeline complete!")


if __name__ == '__main__':
    main()
