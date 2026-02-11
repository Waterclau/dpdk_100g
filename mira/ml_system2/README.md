# ml_system2: ML Pipeline para detector_system2

Pipeline de ML unificado con dos sub-pipelines de ingesta y entrenamiento compartido.

## Estructura

```
ml_system2/
  feature_groups.py              # Definiciones de features (14, 42, 56, 64)
  README.md

  log_pipeline/                  # Ingesta desde .log (texto)
    feature_extractor.py         #   .log -> .csv (regex parsing)
    run_pipeline.sh              #   Pipeline completo .log

  bin_pipeline/                  # Ingesta desde .bin (binario)
    bin_to_csv.py                #   .bin -> .csv (struct.unpack + etiquetado temporal)
    run_pipeline.sh              #   Pipeline completo .bin

  training/                      # Entrenamiento compartido (cualquier CSV)
    prepare_dataset.py           #   Combina CSVs + split train/val/test
    train_model.py               #   Entrena LightGBM (mode: dpi_sketch|sketch|sketch_adv)
    evaluate_model.py            #   Evalua modelo en test set
    model_compare/
      run_compare.py             #   Compara RF, XGB, MLP, KNN, SGD

  datasets/
    processed/                   # CSVs individuales por run
    splits/                      # train.csv, val.csv, test.csv
```

## Tres modos de features

| Modo | Features | Input | Detector | Descripcion |
|------|----------|-------|----------|-------------|
| `dpi_sketch` | 56 | `.log` | detector_system (original) | 42 DPI + 14 sketch |
| `sketch` | 14 | `.log` | detector_system2 (sin --sketch-adv) | Solo sketch global |
| `sketch_adv` | 64 | `.bin` | detector_system2 (con --sketch-adv) | 14 global + 48 per-proto + 2 pkt size |

## Uso rapido

### Opcion A: Pipeline .log (DPI + sketch, 56 features)

```bash
# 1. Recolectar datos con detector_system original
cd mira/detector_system
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee /tmp/dns_run1.log

# 2. Pipeline completo
cd mira/ml_system2
bash log_pipeline/run_pipeline.sh /tmp/ dpi_sketch
```

### Opcion B: Pipeline .log (sketch solo, 14 features)

```bash
# 1. Recolectar con detector_system2 (sin --sketch-adv)
cd mira/detector_system2
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee /tmp/dns_run1.log

# 2. Pipeline
cd mira/ml_system2
bash log_pipeline/run_pipeline.sh /tmp/ sketch
```

### Opcion C: Pipeline .bin (sketch-adv, 64 features)

```bash
# 1. Recolectar con detector_system2 + --sketch-adv
cd mira/detector_system2
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- \
    --sketch-adv /tmp/dns_sketch_adv_run1.bin -p 0

# 2. Generador: 50s baseline -> 100s ataque -> 50s baseline
cd mira/traffic_generator
sudo ./mira_traffic_gen ... --attack-rate 0 --duration 50 -p 0
sudo ./mira_traffic_gen ... --attack-rate 5000000 --attack-type dns_amp --duration 100 -p 0
sudo ./mira_traffic_gen ... --attack-rate 0 --duration 50 -p 0

# 3. Pipeline
cd mira/ml_system2
bash bin_pipeline/run_pipeline.sh /tmp/
```

## Paso a paso manual

### 1. Extraer features

**Desde .log:**
```bash
python3 log_pipeline/feature_extractor.py \
    --input /tmp/dns_run1.log \
    --output datasets/processed/dns_run1.csv \
    --label dns
```

**Desde .bin:**
```bash
python3 bin_pipeline/bin_to_csv.py \
    --input /tmp/dns_sketch_adv_run1.bin \
    --output datasets/processed/dns_run1.csv \
    --attack-type dns \
    --baseline-before 50 --attack-duration 100 --baseline-after 50
```

### 2. Preparar dataset

```bash
python3 training/prepare_dataset.py \
    --input datasets/processed/*.csv \
    --output datasets/splits/ \
    --mode sketch_adv    # o dpi_sketch, o sketch
```

### 3. Entrenar

```bash
python3 training/train_model.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --mode sketch_adv \
    --output training/results/sketch_adv/
```

### 4. Evaluar

```bash
python3 training/evaluate_model.py \
    --model training/results/sketch_adv/lightgbm_model.txt \
    --test datasets/splits/test.csv
```

### 5. Comparar modelos (opcional)

```bash
python3 training/model_compare/run_compare.py \
    --train datasets/splits/train.csv \
    --val datasets/splits/val.csv \
    --test datasets/splits/test.csv \
    --output-dir training/results/compare/
```

## Formato binario (.bin) - sketch-adv

Record de 528 bytes (packed, little-endian):

| Offset | Bytes | Tipo | Campo |
|--------|-------|------|-------|
| 0 | 4 | uint32 | Magic (0x534B4156 "SKAV") |
| 4 | 4 | uint32 | Version (1) |
| 8 | 8 | uint64 | timestamp_ns |
| 16 | 112 | double[14] | 14 global sketch features |
| 128 | 96 | double[12] | pps_proto[12] |
| 224 | 96 | double[12] | heavy_hitters_proto[12] |
| 320 | 96 | double[12] | ip_concentration_proto[12] |
| 416 | 96 | double[12] | ratio_vs_total_proto[12] |
| 512 | 8 | double | avg_packet_size |
| 520 | 8 | double | packet_size_variance |

## Etiquetado temporal (bin_pipeline)

Para experimentos estructurados (50s + 100s + 50s = 200s):

```
t=0         t=50s       t=150s      t=200s
|-- benign --|-- attack --|-- benign --|
```

Etiquetado automatico por `bin_to_csv.py` basado en `timestamp_ns`.

## Comparacion de los 4 runs

| Run | Modo | Features | Detector | Pipeline |
|-----|------|----------|----------|----------|
| 1 | dpi_sketch | 56 | detector_system | log_pipeline |
| 2 | sketch | 14 | detector_system2 | log_pipeline |
| 3 | sketch_adv | 64 | detector_system2 --sketch-adv | bin_pipeline |
| 4 | sketch_adv | 64 | detector_system2 --sketch-adv (otro ataque) | bin_pipeline |
