#!/bin/bash
# Pipeline .bin: convertir binarios sketch-adv -> CSV -> split -> entrenar
#
# Uso:
#   bash run_pipeline.sh /ruta/con/archivos.bin
set -e

BINS_DIR="${1:?Uso: $0 <bins_dir>}"

BASE="$(cd "$(dirname "$0")" && pwd)"
ML2="$(dirname "$BASE")"
PROC="$ML2/datasets/processed"
SPLITS="$ML2/datasets/splits"
BIN2CSV="$BASE/bin_to_csv.py"
TRAIN_DIR="$ML2/training"

mkdir -p "$PROC" "$SPLITS"

echo "===== BIN PIPELINE (sketch-adv, 64 features) ====="
echo "Bins: $BINS_DIR"
echo ""

echo "===== STEP 1: Convertir .bin a CSV ====="

for f in "$BINS_DIR"/*.bin; do
    [ -f "$f" ] || continue
    fname=$(basename "$f" .bin)

    # Inferir tipo de ataque del nombre
    attack_type="unknown"
    case "$fname" in
        *dns*)     attack_type="dns" ;;
        *ntp*)     attack_type="ntp" ;;
        *snmp*)    attack_type="snmp" ;;
        *ssdp*)    attack_type="ssdp" ;;
        *portmap*) attack_type="portmap" ;;
        *netbios*) attack_type="netbios" ;;
        *ldap*)    attack_type="ldap" ;;
        *mssql*)   attack_type="mssql" ;;
        *tftp*)    attack_type="tftp" ;;
        *syn*)     attack_type="syn" ;;
        *udp*)     attack_type="udp" ;;
        *http*|*web*) attack_type="webddos" ;;
        *mixed*)   attack_type="mixed" ;;
    esac

    if [ "$attack_type" = "unknown" ]; then
        echo "[SKIP] No se pudo inferir tipo de ataque: $fname"
        continue
    fi

    echo "[CONVERT] $fname -> $attack_type"
    python3 "$BIN2CSV" \
        --input "$f" \
        --output "$PROC/${fname}.csv" \
        --attack-type "$attack_type" \
        --baseline-before 50 \
        --attack-duration 100 \
        --baseline-after 50
done

csv_count=$(ls "$PROC"/*.csv 2>/dev/null | wc -l)
if [ "$csv_count" -eq 0 ]; then
    echo "[ERROR] No CSVs generados. Verifica que hay .bin en $BINS_DIR"
    exit 1
fi
echo "[INFO] $csv_count CSVs en $PROC/"

echo ""
echo "===== STEP 2: Preparar dataset ====="
python3 "$TRAIN_DIR/prepare_dataset.py" \
    --input $PROC/*.csv \
    --output "$SPLITS/" \
    --mode sketch_adv

echo ""
echo "===== STEP 3: Entrenar ====="
python3 "$TRAIN_DIR/train_model.py" \
    --train "$SPLITS/train.csv" \
    --val "$SPLITS/val.csv" \
    --mode sketch_adv \
    --output "$TRAIN_DIR/results/sketch_adv/"

echo ""
echo "===== STEP 4: Evaluar ====="
python3 "$TRAIN_DIR/evaluate_model.py" \
    --model "$TRAIN_DIR/results/sketch_adv/lightgbm_model.txt" \
    --test "$SPLITS/test.csv"

echo ""
echo "===== DONE (sketch_adv, 64 features) ====="
