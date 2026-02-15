#!/bin/bash
# Pipeline .bin: convertir binarios sketch-adv -> CSV -> split -> entrenar
#
# Soporta archivos de ataque y benign:
#   - Nombres con "benign": label=benign (todo el fichero)
#   - Nombres con tipo de ataque: auto-detect boundaries del sketch
#   - Nombres con "mixed": auto-detect boundaries (mixed)
#
# Uso:
#   bash run_pipeline.sh /ruta/con/archivos.bin [subsample]
#
# Ejemplo:
#   bash run_pipeline.sh /tmp/captures/ 5
set -e

BINS_DIR="${1:?Uso: $0 <bins_dir> [subsample]}"
SUBSAMPLE="${2:-1}"

BASE="$(cd "$(dirname "$0")" && pwd)"
ML2="$(dirname "$BASE")"
PROC="$ML2/datasets/processed/sketch_adv"
SPLITS="$ML2/datasets/splits"
BIN2CSV="$BASE/bin_to_csv.py"
TRAIN_DIR="$ML2/training"

mkdir -p "$PROC" "$SPLITS"

echo "===== BIN PIPELINE (sketch-adv, 64 features) ====="
echo "Bins: $BINS_DIR"
echo "Subsample: $SUBSAMPLE"
echo ""

echo "===== STEP 1: Convertir .bin a CSV ====="

for f in "$BINS_DIR"/*.bin; do
    [ -f "$f" ] || continue
    fname=$(basename "$f" .bin)

    # Inferir tipo de ataque del nombre
    attack_type=""
    case "$fname" in
        benign_baseline_*|benign_*) attack_type="benign" ;;
        mixed_traffic_*|mixed_*)    attack_type="mixed" ;;
        attack_dns_*|*_dns_*)       attack_type="dns" ;;
        attack_ntp_*|*_ntp_*)       attack_type="ntp" ;;
        attack_snmp_*|*_snmp_*)     attack_type="snmp" ;;
        attack_ssdp_*|*_ssdp_*)     attack_type="ssdp" ;;
        attack_portmap_*|*_portmap_*) attack_type="portmap" ;;
        attack_netbios_*|*_netbios_*) attack_type="netbios" ;;
        attack_ldap_*|*_ldap_*)     attack_type="ldap" ;;
        attack_mssql_*|*_mssql_*)   attack_type="mssql" ;;
        attack_tftp_*|*_tftp_*)     attack_type="tftp" ;;
        attack_syn_*|*_syn_*)       attack_type="syn" ;;
        attack_udp_*|*_udp_*)       attack_type="udp" ;;
        attack_webddos_*|*_web_*)   attack_type="webddos" ;;
        *) echo "[SKIP] No se pudo inferir tipo de ataque: $fname"; continue ;;
    esac

    echo "[CONVERT] $fname -> $attack_type (auto-label)"
    python3 "$BIN2CSV" \
        --input "$f" \
        --output "$PROC/${fname}.csv" \
        --attack-type "$attack_type" \
        --auto-label
done

csv_count=$(ls "$PROC"/*.csv 2>/dev/null | wc -l)
if [ "$csv_count" -eq 0 ]; then
    echo "[ERROR] No CSVs generados. Verifica que hay .bin en $BINS_DIR"
    exit 1
fi
echo "[INFO] $csv_count CSVs en $PROC/"

echo ""
echo "===== STEP 2: Preparar dataset ====="
SUBSAMPLE_ARG=""
if [ "$SUBSAMPLE" -gt 1 ]; then
    SUBSAMPLE_ARG="--subsample $SUBSAMPLE"
fi

python3 "$TRAIN_DIR/prepare_dataset.py" \
    --input $PROC/*.csv \
    --output "$SPLITS/" \
    --mode sketch_adv \
    $SUBSAMPLE_ARG

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
