# Comandos de entrenamiento y testing - Sketch-ADV (64 features)

Ruta de los .bin: `/local/dpdk_100g/mira/ml_system/datasets/sketches/`

## 1. Convertir .bin a CSV

```bash
cd /local/dpdk_100g/mira/ml_system/sketch_adv_model

BINS="/local/dpdk_100g/mira/ml_system/datasets/sketches"
PROC="datasets/processed"
BIN2CSV="01_data_collection/bin_to_csv.py"

mkdir -p "$PROC"

# Benign
for f in $BINS/benign*sketch_adv*.bin; do
    run=$(echo $f | grep -oP 'run\d+' || echo "run1")
    python3 "$BIN2CSV" --input "$f" --output "$PROC/benign_${run}.csv" --label benign
done

# Ataques
for attack in dns ldap mssql netbios ntp portmap snmp ssdp syn tftp udp webddos; do
    for f in $BINS/${attack}*sketch_adv*.bin; do
        run=$(echo $f | grep -oP 'run\d+' || echo "run1")
        python3 "$BIN2CSV" --input "$f" --output "$PROC/${attack}_${run}.csv" --label ${attack}
    done
done

# Mixed
for f in $BINS/mixed*sketch_adv*.bin; do
    run=$(echo $f | grep -oP 'run\d+' || echo "run1")
    python3 "$BIN2CSV" --input "$f" --output "$PROC/mixed_${run}.csv" --label mixed
done
```

## 2. Preparar dataset (filtra a 64 features + split)

```bash
python3 02_training/prepare_dataset.py \
    --input datasets/processed/*.csv \
    --output datasets/splits/ \
    --train-ratio 0.7 --val-ratio 0.15 --test-ratio 0.15
```

## 3. Entrenar LightGBM

```bash
python3 02_training/train_sketch_adv.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --output 02_training/results/sketch_adv/lightgbm/
```

## 4. Evaluar en test set

```bash
python3 02_training/evaluate_sketch_adv.py \
    --model 02_training/results/sketch_adv/lightgbm/lightgbm_model.txt \
    --test datasets/splits/test.csv
```

## 5. Comparar modelos (RF, HistGBM, MLP, KNN, SGD, XGBoost)

```bash
python3 02_training/model_compare/run_compare.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output-dir 02_training/results/sketch_adv/alt_models/
```

## 6. Pipeline completo (pasos 3+4+5 juntos)

```bash
python3 02_training/run_full_pipeline.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output 02_training/results/

# Solo LightGBM (sin comparacion):
python3 02_training/run_full_pipeline.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output 02_training/results/ \
    --lightgbm-only
```

## Clases (14)

benign, dns, ldap, mixed, mssql, netbios, ntp, portmap, snmp, ssdp, syn, tftp, udp, webddos

## Resumen de archivos generados

```
02_training/results/
  sketch_adv/
    lightgbm/
      lightgbm_model.txt          # Modelo entrenado
      label_mapping.json          # Mapeo clase -> indice
      feature_scaler.pkl          # StandardScaler
      feature_columns.json        # Lista de 64 features
      training_metadata.json      # Metadata del entrenamiento
      feature_importance.csv      # Importancia de features
      evaluation_results.json     # Metricas en test set
    alt_models/
      summary.json                # Comparacion de todos los modelos
      randomforest/model.pkl
      histgradientboosting/model.pkl
      mlp/model.pkl
      knn/model.pkl
      sgdclassifier/model.pkl
      xgboost/model.pkl           # (si esta instalado)
```
