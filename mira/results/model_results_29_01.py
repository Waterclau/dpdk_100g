#!/usr/bin/env python3
"""
Summarize LightGBM and model-compare results with key metrics and plots.

Usage:
    python3 model_results_29_01.py \
        --results-dir /local/dpdk_100g/mira/results
"""

import argparse
import ast
import re
from pathlib import Path



def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _parse_classes(text: str):
    matches = re.findall(r"Classes:\s*(\[[^\]]+\])", text)
    if not matches:
        return []
    try:
        return ast.literal_eval(matches[-1])
    except Exception:
        return []


def _parse_lightgbm_metrics(text: str):
    classes = _parse_classes(text)

    # Overall accuracy (last occurrence)
    acc_matches = re.findall(r"Overall Accuracy:\s*([0-9.]+)%", text)
    overall_acc = float(acc_matches[-1]) if acc_matches else None

    # Weighted averages (last occurrence)
    prec_matches = re.findall(r"Precision:\s*([0-9.]+)", text)
    rec_matches = re.findall(r"Recall:\s*([0-9.]+)", text)
    f1_matches = re.findall(r"F1-Score:\s*([0-9.]+)", text)
    weighted = {
        "precision": float(prec_matches[-1]) if prec_matches else None,
        "recall": float(rec_matches[-1]) if rec_matches else None,
        "f1": float(f1_matches[-1]) if f1_matches else None,
    }

    # Per-class metrics (last "Per-Class Metrics" section)
    lines = text.splitlines()
    per_class = {}
    last_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "Per-Class Metrics:":
            last_idx = i
    if last_idx is not None:
        i = last_idx + 1
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("=") or line.startswith("-"):
                i += 1
                continue
            if line.startswith("Weighted Averages:"):
                break
            if line.startswith("Class"):
                i += 1
                continue
            parts = line.split()
            if len(parts) >= 4:
                cls = parts[0]
                try:
                    per_class[cls] = {
                        "precision": float(parts[1]),
                        "recall": float(parts[2]),
                        "f1": float(parts[3]),
                    }
                except ValueError:
                    pass
            i += 1

    # Confusion matrix (last)
    cm = None
    cm_start = None
    for i, line in enumerate(lines):
        if line.strip() == "CONFUSION MATRIX":
            cm_start = i
    if cm_start is not None and classes:
        # Find header line with True\Pred then read next len(classes) lines
        header_idx = None
        for i in range(cm_start, min(cm_start + 10, len(lines))):
            if lines[i].strip().startswith("True\\Pred"):
                header_idx = i
                break
        if header_idx is not None:
            rows = []
            for j in range(header_idx + 1, header_idx + 1 + len(classes)):
                nums = re.findall(r"\d+", lines[j])
                if len(nums) >= len(classes):
                    rows.append([int(n) for n in nums[:len(classes)]])
            if len(rows) == len(classes):
                cm = np.array(rows, dtype=int)

    return {
        "classes": classes,
        "overall_acc": overall_acc,
        "weighted": weighted,
        "per_class": per_class,
        "confusion_matrix": cm,
    }


def _parse_model_compare(text: str):
    models = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]") and line != "[DATASET]":
            current = line.strip("[]")
            models.setdefault(current, {})
            continue
        if current:
            m = re.match(r"Val accuracy:\s*([0-9.]+)%", line)
            if m:
                models[current]["val_acc"] = float(m.group(1))
            m = re.match(r"Test accuracy:\s*([0-9.]+)%", line)
            if m:
                models[current]["test_acc"] = float(m.group(1))
    return models


def main():
    parser = argparse.ArgumentParser(description="Summarize ML results and plot metrics")
    parser.add_argument("--results-dir", required=True, help="Path to mira/results")
    parser.add_argument("--lightgbm-file", default="LightGBM.txt", help="LightGBM results file")
    parser.add_argument("--model-compare-file", default="Model compare.txt", help="Model compare results file")
    parser.add_argument("--output-dir", default="analysis_29_01", help="Output folder inside results")
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    lightgbm_path = results_dir / args.lightgbm_file
    compare_path = results_dir / args.model_compare_file
    output_dir = results_dir / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    lightgbm_text = _read_text(lightgbm_path)
    compare_text = _read_text(compare_path)

    lgbm = _parse_lightgbm_metrics(lightgbm_text)
    models = _parse_model_compare(compare_text)

    # Save summary text (pretty format)
    summary_path = output_dir / "summary.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write("LightGBM Summary\n")
        f.write("================\n")
        f.write(f"Overall accuracy: {lgbm['overall_acc']}%\n")
        f.write(f"Weighted precision: {lgbm['weighted']['precision']}\n")
        f.write(f"Weighted recall: {lgbm['weighted']['recall']}\n")
        f.write(f"Weighted F1: {lgbm['weighted']['f1']}\n\n")

        if lgbm["per_class"]:
            f.write("Per-class metrics (F1 / Recall / Precision)\n")
            f.write("===========================================\n")
            for cls in lgbm["classes"]:
                m = lgbm["per_class"].get(cls)
                if m:
                    f.write(f"{cls:10s}  F1={m['f1']:.3f}  R={m['recall']:.3f}  P={m['precision']:.3f}\n")
            f.write("\n")

        f.write("Model Compare (Val/Test accuracy)\n")
        f.write("================================\n")
        for name in sorted(models.keys()):
            f.write(f"{name:22s}  val={models[name].get('val_acc')}  test={models[name].get('test_acc')}\n")

    print(f"[OK] Summary written to: {summary_path}")


if __name__ == "__main__":
    main()
