#!/bin/bash
# Pipeline .log: extraer features de logs del detector -> CSV -> split -> entrenar
#
# Soporta dos modos:
#   --mode dpi_sketch   (56 features, detector_system original)
#   --mode sketch       (14 features, detector_system2 sin --sketch-adv)
#
# Uso:
#   bash run_pipeline.sh /ruta/a/logs/ [dpi_sketch|sketch]
set -e

LOGS_DIR="${1:?Uso: $0 <logs_dir> [dpi_sketch|sketch]}"
MODE="${2:-dpi_sketch}"

BASE="$(cd "$(dirname "$0")" && pwd)"
ML2="$(dirname "$BASE")"
PROC="$ML2/datasets/processed"
SPLITS="$ML2/datasets/splits"
EXTRACT="$BASE/feature_extractor.py"
TRAIN_DIR="$ML2/training"

mkdir -p "$PROC/${MODE}" "$SPLITS"

echo "===== LOG PIPELINE (mode=$MODE) ====="
echo "Logs: $LOGS_DIR"
echo ""

echo "===== STEP 1: Extraer features de .log ====="

for f in "$LOGS_DIR"/*.log; do
    [ -f "$f" ] || continue
    base=$(basename "$f" .log)

    # Inferir label del nombre
    label=""
    case "$base" in
        benign_baseline_*|benign_*) label=benign ;;
        mixed_traffic_*|mixed_*)    label=mixed ;;
        attack_cic_*)               label=attack ;;
        attack_udp_*|*_udp_*)       label=udp ;;
        attack_syn_*|*_syn_*)       label=syn ;;
        attack_dns_*|*_dns_*)       label=dns ;;
        attack_ntp_*|*_ntp_*)       label=ntp ;;
        attack_snmp_*|*_snmp_*)     label=snmp ;;
        attack_ssdp_*|*_ssdp_*)     label=ssdp ;;
        attack_portmap_*|*_portmap_*) label=portmap ;;
        attack_netbios_*|*_netbios_*) label=netbios ;;
        attack_ldap_*|*_ldap_*)     label=ldap ;;
        attack_mssql_*|*_mssql_*)   label=mssql ;;
        attack_tftp_*|*_tftp_*)     label=tftp ;;
        attack_webddos_*|*_web_*)   label=webddos ;;
        *) echo "[SKIP] No label for: $base"; continue ;;
    esac

    echo "[EXTRACT] $base -> $label (auto-label)"
    python3 "$EXTRACT" \
        --input "$f" \
        --output "$PROC/${MODE}/${base}.csv" \
        --label "$label" \
        --auto-label
done

csv_count=$(ls "$PROC/${MODE}"/*.csv 2>/dev/null | wc -l)
if [ "$csv_count" -eq 0 ]; then
    echo "[ERROR] No CSVs generados"
    exit 1
fi
echo "[INFO] $csv_count CSVs en $PROC/${MODE}/"

echo ""
echo "===== STEP 2: Preparar dataset ====="
python3 "$TRAIN_DIR/prepare_dataset.py" \
    --input $PROC/${MODE}/*.csv \
    --output "$SPLITS/" \
    --mode "$MODE"

echo ""
echo "===== STEP 3: Entrenar ====="
python3 "$TRAIN_DIR/train_model.py" \
    --train "$SPLITS/train.csv" \
    --val "$SPLITS/val.csv" \
    --mode "$MODE" \
    --output "$TRAIN_DIR/results/${MODE}/"

echo ""
echo "===== STEP 4: Evaluar ====="
python3 "$TRAIN_DIR/evaluate_model.py" \
    --model "$TRAIN_DIR/results/${MODE}/lightgbm_model.txt" \
    --test "$SPLITS/test.csv"

echo ""
echo "===== DONE (mode=$MODE) ====="
