# Comandos de entrenamiento y testing - Sketch-ADV (64 features)

## 1. Convertir .bin a CSV

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_adv_model

mkdir -p /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/processed

# Benign
sudo bash -c 'for f in /local/dpdk_100g/mira/ml_system/datasets/sketches/benign_baseline_run*.bin; do run=$(echo "$f" | grep -oP "run[0-9]+"); python3 01_data_collection/bin_to_csv.py --input "$f" --output "/local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/processed/benign_${run}.csv" --label benign; done'

# Ataques
sudo bash -c 'for attack in dns ldap mssql netbios ntp portmap snmp ssdp syn tftp udp webddos; do for f in /local/dpdk_100g/mira/ml_system/datasets/sketches/attack_${attack}_run*.bin; do run=$(echo "$f" | grep -oP "run[0-9]+"); python3 01_data_collection/bin_to_csv.py --input "$f" --output "/local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/processed/${attack}_${run}.csv" --label ${attack}; done; done'

# Mixed
sudo bash -c 'for f in /local/dpdk_100g/mira/ml_system/datasets/sketches/mixed_sketch_adv_run*.bin; do run=$(echo "$f" | grep -oP "run[0-9]+"); python3 01_data_collection/bin_to_csv.py --input "$f" --output "/local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/processed/mixed_${run}.csv" --label mixed; done'
```

## 2. Preparar dataset (split por runs: 1,2 train / 3 val / 4 test)

```bash
python3 02_training/prepare_dataset.py \
    --input /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/processed/*.csv \
    --output /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/ \
    --split-by-run \
    --train-runs run1,run2 \
    --val-runs run3 \
    --test-runs run4
```

## 3. Entrenar LightGBM

```bash
python3 02_training/train_sketch_adv.py \
    --train /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/train.csv \
    --val /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/val.csv \
    --output /local/dpdk_100g/mira/ml_system/sketch_adv_model/02_training/results/sketch_adv/lightgbm/
```

## 4. Evaluar en test set

```bash
python3 02_training/evaluate_sketch_adv.py \
    --model /local/dpdk_100g/mira/ml_system/sketch_adv_model/02_training/results/sketch_adv/lightgbm/lightgbm_model.txt \
    --test /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/test.csv
```

## 5. Comparar modelos (RF, HistGBM, MLP, KNN, SGD, XGBoost, LSTM)

```bash
python3 02_training/model_compare/run_compare.py \
    --train /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/train.csv \
    --val /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/val.csv \
    --test /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/test.csv \
    --output-dir /local/dpdk_100g/mira/ml_system/sketch_adv_model/02_training/results/sketch_adv/alt_models/
```

## 6. Pipeline completo (pasos 3+4+5 juntos)

```bash
python3 02_training/run_full_pipeline.py \
    --train /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/train.csv \
    --val /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/val.csv \
    --test /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/test.csv \
    --output /local/dpdk_100g/mira/ml_system/sketch_adv_model/02_training/results/

# Solo LightGBM (sin comparacion):
python3 02_training/run_full_pipeline.py \
    --train /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/train.csv \
    --val /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/val.csv \
    --test /local/dpdk_100g/mira/ml_system/sketch_adv_model/datasets/splits/test.csv \
    --output /local/dpdk_100g/mira/ml_system/sketch_adv_model/02_training/results/ \
    --lightgbm-only
```

## Clases (14)

benign, dns, ldap, mixed, mssql, netbios, ntp, portmap, snmp, ssdp, syn, tftp, udp, webddos
