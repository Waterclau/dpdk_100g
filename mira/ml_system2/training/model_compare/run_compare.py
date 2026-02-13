#!/usr/bin/env python3
"""
Model Comparison (ml_system2 - shared)

Trains multiple ML algorithms and compares performance.
Algorithms: Random Forest, Histogram Gradient Boosting, MLP, KNN, SGD, LSTM

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

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class LSTMClassifier(nn.Module):
    def __init__(self, input_size, hidden_size, num_classes, num_layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers=num_layers,
                            batch_first=True, dropout=dropout if num_layers > 1 else 0)
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        # x: (batch, 1, features) - single timestep per sample
        out, _ = self.lstm(x)
        out = self.dropout(out[:, -1, :])
        return self.fc(out)


def train_lstm(X_train, y_train, X_val, y_val, num_classes, device='cpu'):
    """Train LSTM classifier and return trained model"""
    input_size = X_train.shape[1]
    hidden_size = 128
    batch_size = 64
    num_epochs = 100
    patience = 10

    model = LSTMClassifier(input_size, hidden_size, num_classes).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)

    # Reshape: (N, features) -> (N, 1, features) for LSTM
    X_tr = torch.FloatTensor(X_train).unsqueeze(1).to(device)
    y_tr = torch.LongTensor(y_train).to(device)
    X_v = torch.FloatTensor(X_val).unsqueeze(1).to(device)
    y_v = torch.LongTensor(y_val).to(device)

    train_ds = TensorDataset(X_tr, y_tr)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)

    best_val_acc = 0
    best_state = None
    no_improve = 0

    for epoch in range(num_epochs):
        model.train()
        for batch_x, batch_y in train_loader:
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_pred = model(X_v).argmax(dim=1)
            val_acc = (val_pred == y_v).float().mean().item()
        scheduler.step(1 - val_acc)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            no_improve = 0
        else:
            no_improve += 1

        if no_improve >= patience:
            print(f"    Early stop at epoch {epoch+1} (best val: {best_val_acc*100:.2f}%)")
            break

    if best_state:
        model.load_state_dict(best_state)
    model.to(device)
    return model


def predict_lstm(model, X, device='cpu'):
    """Predict with LSTM model"""
    model.eval()
    X_t = torch.FloatTensor(X).unsqueeze(1).to(device)
    with torch.no_grad():
        return model(X_t).argmax(dim=1).cpu().numpy()


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

    # LSTM
    if HAS_TORCH:
        print(f"\n--- LSTM ---")
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        print(f"    Device: {device}")
        num_classes = len(le.classes_)
        lstm_model = train_lstm(X_train_s, y_train, X_val_s, y_val, num_classes, device)

        val_pred_lstm = predict_lstm(lstm_model, X_val_s, device)
        val_acc = accuracy_score(y_val, val_pred_lstm)
        test_pred_lstm = predict_lstm(lstm_model, X_test_s, device)
        test_acc = accuracy_score(y_test, test_pred_lstm)
        test_f1 = f1_score(y_test, test_pred_lstm, average='weighted', zero_division=0)
        report = classification_report(y_test, test_pred_lstm, target_names=le.classes_, output_dict=True)

        print(f"  Val: {val_acc*100:.2f}% | Test: {test_acc*100:.2f}% (F1={test_f1:.3f})")

        results['models']['LSTM'] = {
            'val_accuracy': float(val_acc),
            'test_accuracy': float(test_acc),
            'test_report': report,
        }
    else:
        print("\n[WARNING] PyTorch not available, skipping LSTM")

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
