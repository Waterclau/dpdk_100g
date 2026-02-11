#!/bin/bash
# Pipeline completo sketch-adv: .bin -> CSV -> split -> train
#
# Uso:
#   bash run_pipeline.sh /tmp/
#
# Espera archivos .bin en el directorio indicado con nombres tipo:
#   dns_sketch_adv_run1.bin, ntp_sketch_adv_run2.bin, etc.
#
# Estructura temporal por defecto: 50s baseline -> 100s ataque -> 50s baseline
set -e

BIN_DIR="${1:?Uso: $0 <directorio_bins>}"

BASE="$(cd "$(dirname "$0")" && pwd)"
PROC="$BASE/datasets/processed"
SPLITS="$BASE/datasets/splits"
BIN2CSV="$BASE/01_data_collection/bin_to_csv.py"
TRAIN="$BASE/02_training"

mkdir -p "$PROC" "$SPLITS"

echo "===== STEP 1: Convertir .bin a CSV ====="

for f in "$BIN_DIR"/*sketch_adv*.bin; do
    [ -f "$f" ] || continue
    fname=$(basename "$f" .bin)

    # Inferir tipo de ataque del nombre del archivo
    attack_type=$(echo "$fname" | sed -E 's/^([a-z_]+)_sketch_adv.*/\1/')

    # Inferir run del nombre
    run=$(echo "$fname" | grep -oP 'run\d+' || echo "run1")

    output="$PROC/${attack_type}_${run}.csv"
    echo "  $f -> $output (attack=$attack_type)"

    python3 "$BIN2CSV" \
        --input "$f" \
        --output "$output" \
        --attack-type "$attack_type" \
        --baseline-before 50 --attack-duration 100 --baseline-after 50
done

# Verificar que se generaron CSVs
csv_count=$(ls "$PROC"/*.csv 2>/dev/null | wc -l)
if [ "$csv_count" -eq 0 ]; then
    echo "[ERROR] No se generaron CSVs. Verifica los archivos .bin"
    exit 1
fi
echo "  -> $csv_count CSVs generados"

echo ""
echo "===== STEP 2: Preparar dataset ====="
python3 "$TRAIN/prepare_dataset.py" \
    --input $PROC/*.csv \
    --output "$SPLITS/" \
    --train-ratio 0.7 --val-ratio 0.15 --test-ratio 0.15

echo ""
echo "===== STEP 3: Entrenar todos los modelos ====="
cd "$TRAIN"
python3 run_full_pipeline.py \
    --train "$SPLITS/train.csv" \
    --val "$SPLITS/val.csv" \
    --test "$SPLITS/test.csv" \
    --output ./results/

echo ""
echo "===== DONE ====="
echo "Resultados en: $TRAIN/results/"
