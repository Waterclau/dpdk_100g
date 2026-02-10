#!/bin/bash
# Pipeline completo: extraer features + preparar dataset + entrenar
set -e

LOGS="/local/dpdk_100g/mira/ml_system/datasets/raw_logs/2"
BASE="/local/dpdk_100g/mira/ml_system/sketch_model"
PROC="$BASE/datasets/processed"
SPLITS="$BASE/datasets/splits"
EXTRACT="$BASE/01_data_collection/feature_extractor.py"
TRAIN="$BASE/02_training"

mkdir -p "$PROC" "$SPLITS"

echo "===== STEP 1: Extraer features ====="

# Benign
for f in $LOGS/benign_baseline_run*.log; do
    run=$(echo $f | grep -oP 'run\d+')
    python3 "$EXTRACT" --input "$f" --output "$PROC/benign_${run}.csv" --label benign
done

# Ataques
for attack in dns ldap mssql netbios ntp portmap snmp ssdp syn tftp udp webddos; do
    for f in $LOGS/attack_${attack}_run*.log; do
        run=$(echo $f | grep -oP 'run\d+')
        python3 "$EXTRACT" --input "$f" --output "$PROC/${attack}_${run}.csv" --label ${attack}
    done
done

# Mixed
for f in $LOGS/mixed_traffic_run*.log; do
    run=$(echo $f | grep -oP 'run\d+')
    python3 "$EXTRACT" --input "$f" --output "$PROC/mixed_${run}.csv" --label mixed
done

echo "===== STEP 2: Preparar dataset ====="
python3 "$TRAIN/prepare_dataset.py" --input $PROC/*.csv --output "$SPLITS/" --train-ratio 0.7 --val-ratio 0.15 --test-ratio 0.15

echo "===== STEP 3: Entrenar todos los modelos ====="
cd "$TRAIN"
python3 run_full_ablation.py --train "$SPLITS/train.csv" --val "$SPLITS/val.csv" --test "$SPLITS/test.csv" --output ./results/

echo "===== DONE ====="
