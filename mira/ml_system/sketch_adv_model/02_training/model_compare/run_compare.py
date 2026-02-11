#!/usr/bin/env python3
"""
Multi-Model Comparison - Sketch-ADV Features (64 features)

Trains RandomForest, HistGradientBoosting, MLP, KNN, SGDClassifier,
optionally XGBoost, and optionally LSTM (PyTorch) using all 64
sketch-adv features.

Usage:
    python3 run_compare.py \
        --train ../../datasets/splits/train.csv \
        --val ../../datasets/splits/val.csv \
        --test ../../datasets/splits/test.csv \
        --output-dir ../results/sketch_adv/alt_models
"""

import argparse
import json
import os
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
from feature_groups import get_feature_columns, SKETCH_FEATURES_ALL


def _try_import_xgboost():
    try:
        from xgboost import XGBClassifier
        return XGBClassifier
    except Exception:
        return None


def _try_import_torch():
    """Try to import PyTorch, return (torch, nn) or (None, None)"""
    torch_lib_paths = [
        "/usr/local/lib/python3.8/dist-packages/torch/lib",
        "/users/cesteban/.local/lib/python3.8/site-packages/torch/lib",
    ]
    ld_path = os.environ.get("LD_LIBRARY_PATH", "")
    merged_ld = ":".join([p for p in torch_lib_paths if p] + ([ld_path] if ld_path else []))
    os.environ["LD_LIBRARY_PATH"] = merged_ld
    try:
        import torch
        import torch.nn as nn
        _ = torch.tensor([0.0])
        return torch, nn
    except Exception:
        return None, None


def _build_sequences(df, feature_cols, seq_len, stride):
    """Build windowed sequences grouped by label (and run_id if available)"""
    sequences = []
    labels = []

    group_cols = ["label"]
    if "run_id" in df.columns:
        group_cols.append("run_id")

    for _, group in df.groupby(group_cols):
        X = group[feature_cols].values.astype(np.float32)
        y = group["label"].iloc[0]
        for i in range(0, len(X) - seq_len + 1, stride):
            sequences.append(X[i:i + seq_len])
            labels.append(y)

    if not sequences:
        return np.empty((0, seq_len, len(feature_cols)), dtype=np.float32), np.array([])
    return np.stack(sequences), np.array(labels)


def _train_lstm(torch, nn, model, X_train, y_train, X_val, y_val,
                epochs, batch_size):
    """Train LSTM model with early stopping on validation accuracy"""
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()

    best_val = 0.0
    best_state = None

    for epoch in range(1, epochs + 1):
        # Train
        model.train()
        idx = np.random.permutation(len(X_train))
        total_loss = 0.0
        for i in range(0, len(X_train), batch_size):
            batch_idx = idx[i:i + batch_size]
            xb = torch.tensor(X_train[batch_idx], dtype=torch.float32)
            yb = torch.tensor(y_train[batch_idx], dtype=torch.long)
            optimizer.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(xb)
        avg_loss = total_loss / len(X_train)

        # Validate
        model.eval()
        val_preds = []
        with torch.no_grad():
            for i in range(0, len(X_val), batch_size):
                xb = torch.tensor(X_val[i:i + batch_size], dtype=torch.float32)
                logits = model(xb)
                val_preds.append(logits.argmax(dim=1).numpy())
        y_val_pred = np.concatenate(val_preds)
        val_acc = accuracy_score(y_val, y_val_pred)

        if val_acc > best_val:
            best_val = val_acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

        print(f"  [LSTM] Epoch {epoch}/{epochs} - loss {avg_loss:.4f} - val {val_acc*100:.2f}%")

    if best_state:
        model.load_state_dict(best_state)

    return model, best_val


def _eval_lstm(torch, model, X, batch_size):
    """Get predictions from trained LSTM"""
    model.eval()
    preds = []
    probas = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            xb = torch.tensor(X[i:i + batch_size], dtype=torch.float32)
            logits = model(xb)
            proba = torch.softmax(logits, dim=1).numpy()
            preds.append(logits.argmax(dim=1).numpy())
            probas.append(proba)
    return np.concatenate(preds), np.concatenate(probas)


def load_split(path):
    df = pd.read_csv(path)
    feature_cols = [c for c in get_feature_columns(include_adv=True) if c in df.columns]
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
        description='Compare ML models with sketch-adv features (64 features)'
    )
    parser.add_argument('--train', required=True, help='Train CSV')
    parser.add_argument('--val', required=True, help='Validation CSV')
    parser.add_argument('--test', required=True, help='Test CSV')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    args = parser.parse_args()

    print("=" * 70)
    print("MODEL COMPARISON - SKETCH-ADV FEATURES")
    print(f"  {len(SKETCH_FEATURES_ALL)} features (14 global + 48 per-protocol + 2 pkt size)")
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
    print(f"  Features: {len(feature_cols)} (sketch_adv)  Classes: {labels}")

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

        print(f"\nTraining {name} (sketch_adv)...")
        model.fit(X_tr, y_train)
        results[name] = eval_model(name, model, X_v, y_val, X_te, y_test, labels)
        results[name]['feature_group'] = 'sketch_adv'
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

    # LSTM (PyTorch) - sequence model with windowed input
    torch, nn = _try_import_torch()
    if torch is not None:
        print(f"\nTraining LSTM (sketch_adv, seq_len=12, stride=6)...")

        seq_len = 12
        stride = 6
        lstm_epochs = 10
        lstm_batch = 64

        X_seq_train, y_seq_train_lbl = _build_sequences(df_train, feature_cols, seq_len, stride)
        X_seq_val, y_seq_val_lbl = _build_sequences(df_val, feature_cols, seq_len, stride)
        X_seq_test, y_seq_test_lbl = _build_sequences(df_test, feature_cols, seq_len, stride)

        if len(X_seq_train) > 0 and len(X_seq_val) > 0 and len(X_seq_test) > 0:
            # Scale sequences (flatten -> scale -> reshape)
            shape_tr = X_seq_train.shape
            shape_va = X_seq_val.shape
            shape_te = X_seq_test.shape
            lstm_scaler = StandardScaler()
            X_seq_train = lstm_scaler.fit_transform(
                X_seq_train.reshape(-1, shape_tr[-1])
            ).reshape(shape_tr)
            X_seq_val = lstm_scaler.transform(
                X_seq_val.reshape(-1, shape_va[-1])
            ).reshape(shape_va)
            X_seq_test = lstm_scaler.transform(
                X_seq_test.reshape(-1, shape_te[-1])
            ).reshape(shape_te)

            y_seq_train = label_encoder.transform(y_seq_train_lbl)
            y_seq_val = label_encoder.transform(y_seq_val_lbl)
            y_seq_test = label_encoder.transform(y_seq_test_lbl)

            num_classes = len(labels)
            input_dim = X_seq_train.shape[-1]

            class LSTMModel(nn.Module):
                def __init__(self):
                    super().__init__()
                    self.lstm = nn.LSTM(input_dim, 64, batch_first=True)
                    self.dropout = nn.Dropout(0.2)
                    self.fc = nn.Linear(64, num_classes)

                def forward(self, x):
                    out, _ = self.lstm(x)
                    out = out[:, -1, :]
                    out = self.dropout(out)
                    return self.fc(out)

            lstm_model = LSTMModel()
            lstm_model, best_val_acc = _train_lstm(
                torch, nn, lstm_model,
                X_seq_train, y_seq_train,
                X_seq_val, y_seq_val,
                lstm_epochs, lstm_batch
            )

            y_test_pred, y_test_proba = _eval_lstm(torch, lstm_model, X_seq_test, lstm_batch)
            y_val_pred, _ = _eval_lstm(torch, lstm_model, X_seq_val, lstm_batch)

            test_acc = float(accuracy_score(y_seq_test, y_test_pred))
            val_acc = float(accuracy_score(y_seq_val, y_val_pred))

            val_report = classification_report(
                y_seq_val, y_val_pred, target_names=labels, output_dict=True, zero_division=0
            )
            test_report = classification_report(
                y_seq_test, y_test_pred, target_names=labels, output_dict=True, zero_division=0
            )

            print(f"\n[LSTM]")
            print(f"  Val accuracy:  {val_acc * 100:.2f}%")
            print(f"  Test accuracy: {test_acc * 100:.2f}%")
            print(f"  Sequences: train={len(X_seq_train)} val={len(X_seq_val)} test={len(X_seq_test)}")

            _print_report("LSTM VALIDATION RESULTS", y_seq_val, y_val_pred, labels)
            _print_report("LSTM TEST RESULTS", y_seq_test, y_test_pred, labels)

            # Sample predictions
            print("\nSAMPLE PREDICTIONS (First 10)")
            print(f"{'Index':<8} {'True':<14} {'Predicted':<14} {'Confidence':>10}   {'OK':<5}")
            print("-" * 60)
            for i in range(min(10, len(y_seq_test))):
                true_lbl = labels[y_seq_test[i]]
                pred_lbl = labels[y_test_pred[i]]
                conf = float(np.max(y_test_proba[i]))
                correct = "YES" if y_seq_test[i] == y_test_pred[i] else "NO"
                print(f"{i:<8d} {true_lbl:<14s} {pred_lbl:<14s} {conf:>9.3f}   {correct}")

            results['LSTM'] = {
                'val_accuracy': val_acc,
                'test_accuracy': test_acc,
                'val_report': val_report,
                'test_report': test_report,
                'val_confusion_matrix': confusion_matrix(y_seq_val, y_val_pred).tolist(),
                'test_confusion_matrix': confusion_matrix(y_seq_test, y_test_pred).tolist(),
                'feature_group': 'sketch_adv',
                'num_features': len(feature_cols),
                'seq_len': seq_len,
                'stride': stride,
            }

            # Save LSTM model
            lstm_dir = output_root / 'lstm'
            lstm_dir.mkdir(parents=True, exist_ok=True)
            torch.save(lstm_model.state_dict(), lstm_dir / 'model.pt')
            with open(lstm_dir / 'label_mapping.json', 'w') as f:
                json.dump({str(i): lbl for i, lbl in enumerate(labels)}, f, indent=2)
            with open(lstm_dir / 'feature_scaler.pkl', 'wb') as f:
                pickle.dump(lstm_scaler, f)
            with open(lstm_dir / 'feature_columns.json', 'w') as f:
                json.dump(feature_cols, f, indent=2)
            with open(lstm_dir / 'metadata.json', 'w') as f:
                json.dump({'seq_len': seq_len, 'stride': stride, 'input_dim': input_dim,
                           'num_classes': num_classes, 'hidden_dim': 64}, f, indent=2)
        else:
            print("[WARNING] Not enough data to build LSTM sequences (seq_len=12)")
    else:
        print("\n[INFO] PyTorch not installed; skipping LSTM.")

    # Summary
    summary = {
        'feature_group': 'sketch_adv',
        'num_features': len(feature_cols),
        'feature_columns': feature_cols,
        'models': results,
    }
    with open(output_root / 'summary.json', 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print("MODEL COMPARISON COMPLETE - SKETCH-ADV")
    print("=" * 70)

    print(f"\n{'Model':<25} {'Val Acc':<12} {'Test Acc':<12} {'Features':<10}")
    print("-" * 60)
    for name, res in results.items():
        print(f"{name:<25} {res['val_accuracy']*100:>8.2f}%   {res['test_accuracy']*100:>8.2f}%   {len(feature_cols)}")

    print(f"\nSaved under: {output_root}")


if __name__ == '__main__':
    main()
