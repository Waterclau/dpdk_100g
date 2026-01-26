# Model Comparison (Non-LightGBM)

Train and evaluate multiple classifiers on the same splits used for LightGBM.

Models included:
- RandomForest
- XGBoost (optional, if installed)
- MLP
- HistGradientBoosting
- KNN
- SGDClassifier

Usage:
```bash
cd /local/dpdk_100g/mira/ml_system/02_training/model_compare
python3 run_compare.py \
  --train ../../datasets/splits/train.csv \
  --val ../../datasets/splits/val.csv \
  --test ../../datasets/splits/test.csv \
  --output-dir ../../../detector_system_ml/alt_models
```

Outputs:
- Per-model metrics for validation and test.
- Saved model artifacts under `detector_system_ml/alt_models/<model>/`:
  - `model.pkl`
  - `label_mapping.json`
  - `feature_scaler.pkl`
  - `feature_columns.json`
