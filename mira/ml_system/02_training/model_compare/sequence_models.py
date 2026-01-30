#!/usr/bin/env python3
"""
Train sequence models (LSTM / Transformer) on windowed time series.

Usage:
    python3 sequence_models.py \
        --train ../../datasets/splits/train.csv \
        --val ../../datasets/splits/val.csv \
        --test ../../datasets/splits/test.csv \
        --model lstm \
        --seq-len 12 \
        --stride 6 \
        --epochs 10 \
        --output-dir ../../../detector_system_ml/alt_model_sequence
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report


def _load_csv(path: str):
    df = pd.read_csv(path)
    exclude_cols = ["label"]
    if "timestamp" in df.columns:
        exclude_cols.append("timestamp")
    if "run_id" in df.columns:
        exclude_cols.append("run_id")
    feature_cols = [c for c in df.columns if c not in exclude_cols]
    return df, feature_cols


def _build_sequences(df, feature_cols, seq_len, stride):
    sequences = []
    labels = []

    group_cols = ["label"]
    if "run_id" in df.columns:
        group_cols.append("run_id")

    for _, group in df.groupby(group_cols):
        if "timestamp" in group.columns:
            group = group.sort_values("timestamp")
        X = group[feature_cols].values.astype(np.float32)
        y = group["label"].iloc[0]
        for i in range(0, len(X) - seq_len + 1, stride):
            sequences.append(X[i:i + seq_len])
            labels.append(y)

    return np.stack(sequences), np.array(labels)


def _prepare_data(train_csv, val_csv, test_csv, seq_len, stride):
    df_train, feature_cols = _load_csv(train_csv)
    df_val, _ = _load_csv(val_csv)
    df_test, _ = _load_csv(test_csv)

    X_train, y_train_labels = _build_sequences(df_train, feature_cols, seq_len, stride)
    X_val, y_val_labels = _build_sequences(df_val, feature_cols, seq_len, stride)
    X_test, y_test_labels = _build_sequences(df_test, feature_cols, seq_len, stride)

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(y_train_labels)
    y_val = label_encoder.transform(y_val_labels)
    y_test = label_encoder.transform(y_test_labels)

    scaler = StandardScaler()
    X_train_2d = X_train.reshape(-1, X_train.shape[-1])
    X_val_2d = X_val.reshape(-1, X_val.shape[-1])
    X_test_2d = X_test.reshape(-1, X_test.shape[-1])

    X_train_scaled = scaler.fit_transform(X_train_2d).reshape(X_train.shape)
    X_val_scaled = scaler.transform(X_val_2d).reshape(X_val.shape)
    X_test_scaled = scaler.transform(X_test_2d).reshape(X_test.shape)

    return (
        X_train_scaled, y_train,
        X_val_scaled, y_val,
        X_test_scaled, y_test,
        label_encoder, scaler, feature_cols
    )


def _to_torch():
    import torch
    import torch.nn as nn
    return torch, nn


def _train(model, optimizer, loss_fn, X, y, batch_size, device):
    model.train()
    idx = np.random.permutation(len(X))
    X = X[idx]
    y = y[idx]
    total_loss = 0.0

    for i in range(0, len(X), batch_size):
        xb = X[i:i + batch_size]
        yb = y[i:i + batch_size]
        xb = device.tensor(xb, dtype=device.float32)
        yb = device.tensor(yb, dtype=device.long)
        optimizer.zero_grad()
        logits = model(xb)
        loss = loss_fn(logits, yb)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(xb)
    return total_loss / len(X)


def _evaluate(model, X, y, batch_size, device):
    model.eval()
    preds = []
    with device.no_grad():
        for i in range(0, len(X), batch_size):
            xb = device.tensor(X[i:i + batch_size], dtype=device.float32)
            logits = model(xb)
            preds.append(logits.argmax(dim=1).cpu().numpy())
    y_pred = np.concatenate(preds)
    return y_pred


def _build_lstm(input_dim, num_classes, torch, nn):
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

    return LSTMModel()


def _build_transformer(input_dim, num_classes, torch, nn):
    class TransformerModel(nn.Module):
        def __init__(self):
            super().__init__()
            d_model = 64
            self.proj = nn.Linear(input_dim, d_model)
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=d_model, nhead=4, dim_feedforward=128, dropout=0.2,
                batch_first=True
            )
            self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=2)
            self.fc = nn.Linear(d_model, num_classes)

        def forward(self, x):
            x = self.proj(x)
            x = self.encoder(x)
            x = x.mean(dim=1)
            return self.fc(x)

    return TransformerModel()


def _run_model(name, model, X_train, y_train, X_val, y_val, X_test, y_test,
               label_encoder, epochs, batch_size, output_dir):
    torch, nn = _to_torch()
    device = torch
    model = model.to(device.device("cpu"))
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()

    best_val = 0.0
    best_state = None
    for epoch in range(1, epochs + 1):
        loss = _train(model, optimizer, loss_fn, X_train, y_train, batch_size, device)
        y_val_pred = _evaluate(model, X_val, y_val, batch_size, device)
        val_acc = accuracy_score(y_val, y_val_pred)
        if val_acc > best_val:
            best_val = val_acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        print(f"[{name}] Epoch {epoch}/{epochs} - loss {loss:.4f} - val {val_acc*100:.2f}%")

    if best_state:
        model.load_state_dict(best_state)

    y_test_pred = _evaluate(model, X_test, y_test, batch_size, device)
    test_acc = accuracy_score(y_test, y_test_pred)

    report = classification_report(
        y_test, y_test_pred, target_names=label_encoder.classes_, output_dict=True, zero_division=0
    )

    out_dir = Path(output_dir) / name.lower()
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), out_dir / "model.pt")

    with open(out_dir / "metrics.json", "w") as f:
        json.dump(
            {"val_accuracy": best_val, "test_accuracy": test_acc, "report": report},
            f, indent=2
        )

    print(f"[{name}] Test accuracy: {test_acc*100:.2f}%")


def main():
    parser = argparse.ArgumentParser(description="Train sequence models (LSTM/Transformer)")
    parser.add_argument("--train", required=True)
    parser.add_argument("--val", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--model", choices=["lstm", "transformer", "both"], default="lstm")
    parser.add_argument("--seq-len", type=int, default=12)
    parser.add_argument("--stride", type=int, default=6)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    try:
        torch, nn = _to_torch()
        _ = torch.tensor([0.0])
    except Exception as exc:
        raise SystemExit(
            "PyTorch is required. Install with: pip3 install --user torch"
        ) from exc

    (
        X_train, y_train, X_val, y_val, X_test, y_test,
        label_encoder, scaler, feature_cols
    ) = _prepare_data(args.train, args.val, args.test, args.seq_len, args.stride)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "label_mapping.json", "w") as f:
        json.dump({str(i): c for i, c in enumerate(label_encoder.classes_)}, f, indent=2)
    with open(output_dir / "feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    if args.model in ("lstm", "both"):
        model = _build_lstm(X_train.shape[-1], len(label_encoder.classes_), torch, nn)
        _run_model("LSTM", model, X_train, y_train, X_val, y_val, X_test, y_test,
                   label_encoder, args.epochs, args.batch_size, output_dir)

    if args.model in ("transformer", "both"):
        model = _build_transformer(X_train.shape[-1], len(label_encoder.classes_), torch, nn)
        _run_model("Transformer", model, X_train, y_train, X_val, y_val, X_test, y_test,
                   label_encoder, args.epochs, args.batch_size, output_dir)


if __name__ == "__main__":
    main()
