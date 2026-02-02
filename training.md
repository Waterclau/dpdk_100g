# Training Commands (Runs 1-3)

## 1) Split by run_id (train run1+run2, val run3, test run3)

Note: If you later collect a full `run4` for all labels, use it for `--test-runs` instead of `run3`.

```bash
cd /local/dpdk_100g/mira/ml_system/02_training
sudo python3 prepare_dataset.py \
  --input ../datasets/processed_2/*.csv \
  --output ../datasets/splits_2/ \
  --split-by-run \
  --train-runs run1,run2 \
  --val-runs run3 \
  --test-runs run3
```

## 2) Train LightGBM with normalization (outputs *_2 artifacts)

```bash
cd /local/dpdk_100g/mira/ml_system/02_training
sudo python3 train_with_normalization.py \
  --train ../datasets/splits_2/train.csv \
  --val ../datasets/splits_2/val.csv \
  --output ../../detector_system_ml/lightgbm_model_2.txt
```

## 3) Evaluate on test split

```bash
cd /local/dpdk_100g/mira/ml_system/02_training
sudo python3 evaluate_model.py \
  --model ../../detector_system_ml/lightgbm_model_2.txt \
  --test ../datasets/splits_2/test.csv
```

## 4) Compare non-LightGBM models

```bash
cd /local/dpdk_100g/mira/ml_system/02_training/model_compare
sudo python3 run_compare.py \
  --train ../../datasets/splits_2/train.csv \
  --val ../../datasets/splits_2/val.csv \
  --test ../../datasets/splits_2/test.csv \
  --output-dir ../../../detector_system_ml/alt_models_2
```

## 5) Optional: Sequence models (LSTM/Transformer)

```bash
cd /local/dpdk_100g/mira/ml_system/02_training/model_compare
sudo python3 run_compare.py \
  --train ../../datasets/splits_2/train.csv \
  --val ../../datasets/splits_2/val.csv \
  --test ../../datasets/splits_2/test.csv \
  --output-dir ../../../detector_system_ml/alt_models_2 \
  --sequence-models \
  --seq-len 12 \
  --stride 6 \
  --epochs 10 \
  --seq-output-dir ../../../detector_system_ml/alt_model_sequence_2
```
