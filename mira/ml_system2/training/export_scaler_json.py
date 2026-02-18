#!/usr/bin/env python3
"""
Export feature_scaler.json from feature_scaler.pkl

Converts the sklearn StandardScaler pickle to JSON format
readable by the C inference code (ml_inference.c).

Usage:
    python3 export_scaler_json.py --model-dir ./results/dpi_sketch/complete/
    python3 export_scaler_json.py --model-dir ./results/sketch_adv/
"""

import argparse
import json
import pickle
from pathlib import Path


def export_scaler(model_dir):
    model_dir = Path(model_dir)

    pkl_path = model_dir / 'feature_scaler.pkl'
    json_path = model_dir / 'feature_scaler.json'

    if not pkl_path.exists():
        print(f"[ERROR] Not found: {pkl_path}")
        return False

    with open(pkl_path, 'rb') as f:
        scaler = pickle.load(f)

    # Load feature column names if available
    feature_names = []
    cols_path = model_dir / 'feature_columns.json'
    if cols_path.exists():
        with open(cols_path, 'r') as f:
            feature_names = json.load(f)

    data = {
        'num_features': len(scaler.mean_),
        'feature_names': feature_names if feature_names else [f'f{i}' for i in range(len(scaler.mean_))],
        'mean': scaler.mean_.tolist(),
        'scale': scaler.scale_.tolist(),
    }

    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"[OK] Exported: {json_path}")
    print(f"     Features: {data['num_features']}")
    print(f"     Mean range: [{min(data['mean']):.4f}, {max(data['mean']):.4f}]")
    print(f"     Scale range: [{min(data['scale']):.4f}, {max(data['scale']):.4f}]")
    return True


def main():
    parser = argparse.ArgumentParser(description='Export feature_scaler.json from .pkl')
    parser.add_argument('--model-dir', required=True, nargs='+', action='extend',
                        help='Model directory/directories containing feature_scaler.pkl')
    args = parser.parse_args()

    for d in args.model_dir:
        export_scaler(d)


if __name__ == '__main__':
    main()
