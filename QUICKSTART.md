# Quick Start - Sistema DDoS Completo

## 📦 Archivos Creados

```
✓ attack_generator/
  ✓ __init__.py
  ✓ __main__.py (punto de entrada)
  ✓ generator.py (generador principal)
  ✓ attacks.py
  ✓ benign_traffic.py
  ✓ utils.py
  ✓ README.md (documentación completa)

✓ detector_system/
  ✓ __init__.py
  ✓ detector_dpdk.c (core DPDK + Sketches)
  ✓ config.py
  ✓ feature_extractor.py
  ✓ model_inferencer.py
  ✓ scripts/build.sh
  ✓ scripts/run.sh
  ✓ scripts/run_background.sh
  ✓ scripts/analyze.py
  ✓ README.md (documentación completa)

✓ run_experiment.sh (script de experimentación)
✓ EXPERIMENTS.md (guía paso a paso)
✓ readme.md (resumen general)
```

## ⚡ Comandos Esenciales

### NODO TG (Traffic Generator)

```bash
# 1. Generar tráfico benigno
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign.pcap \
  --benign-duration 60

# 2. Generar ataques (con stdin JSON)
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign.pcap \
  --attack-ratio 0.3 \
  --config - <<'EOFCFG'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000}
  ]
}
EOFCFG

# 3. Ejecutar experimento (después de iniciar detector)
sudo ./run_experiment.sh -n "mi_experimento" -r 2000
```

### NODO DETECTOR

```bash
# 1. Compilar (primera vez)
cd /local/dpdk_100g/detector_system
./scripts/build.sh

# 2. Ejecutar en background
sudo ./scripts/run_background.sh 0000:41:00.0

# 3. Monitorear (en otra terminal)
tail -f /local/logs/ml_features.csv

# 4. Analizar resultados (después del experimento)
python3 scripts/analyze.py --export-features /local/features.csv

# 5. Detener
sudo pkill detector_dpdk
```

## 🎯 Flujo Completo en 4 Pasos

```bash
# PASO 1 (Nodo TG): Generar PCAPs
cd /local/dpdk_100g
sudo python3 -m attack_generator --config attacks.json

# PASO 2 (Nodo Detector): Iniciar detector
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# PASO 3 (Nodo TG): Ejecutar experimento
cd /local/dpdk_100g
sudo ./run_experiment.sh

# PASO 4 (Nodo Detector): Analizar
cd /local/dpdk_100g/detector_system
python3 scripts/analyze.py
```

## 📁 Resultados Generados

```
/local/pcaps/                   # PCAPs generados
  ├── syn_flood.pcap
  ├── syn_flood_mixed.pcap
  ├── udp_flood.pcap
  └── metadata.json

/local/logs/                    # Logs del detector
  ├── detection.log             # Estadísticas básicas
  ├── ml_features.csv           # 19 features ML
  └── alerts.log                # Alertas de seguridad

/local/logs/experiments/        # Logs de experimentos
  └── exp_<timestamp>/
      ├── experiment.log
      ├── stats.csv
      └── report.txt
```

## 🔧 Troubleshooting Rápido

```bash
# Error stdin en generator
# SOLUCIÓN: Usar python3 -m attack_generator (sin .generator)

# Error DPDK no encuentra NIC
dpdk-devbind.py --status
sudo dpdk-devbind.py --bind=vfio-pci 0000:41:00.0

# Error tcpreplay no envía
sudo ip link set enp65s0f0 up
sudo ethtool -K enp65s0f0 gso off tso off

# Ver tráfico en tiempo real
sudo tcpdump -i enp65s0f0 -n -c 20
```

## 📖 Documentación Completa

1. **attack_generator/README.md** - Todo sobre generación de ataques
2. **detector_system/README.md** - Todo sobre el detector
3. **EXPERIMENTS.md** - Guía paso a paso de experimentos
4. **readme.md** - Resumen general del sistema

## 🎓 Ejemplos de Uso

### Ejemplo 1: Test Rápido

```bash
# TG: Generar un solo ataque
sudo python3 -m attack_generator \
  --attack syn_flood \
  --num-packets 50000 \
  --pps 5000

# Detector: Ejecutar
sudo ./detector_system/scripts/run.sh 0000:41:00.0

# TG: Replay (en otra terminal)
sudo tcpreplay -i enp65s0f0 --mbps=1000 /local/pcaps/syn_flood.pcap
```

### Ejemplo 2: Dataset ML

```bash
# TG: Generar múltiples ataques con mezcla
for attack in syn_flood udp_flood http_flood; do
  sudo python3 -m attack_generator \
    --target-ip 10.10.1.2 \
    --attack $attack \
    --num-packets 50000 \
    --mix-benign /local/pcaps/benign.pcap \
    --attack-ratio 0.3
done

# Detector: Correr en background
sudo ./detector_system/scripts/run_background.sh 0000:41:00.0

# TG: Ejecutar todos
sudo ./run_experiment.sh sequential 20

# Detector: Exportar features
python3 detector_system/scripts/analyze.py \
  --export-features /local/ml_training_data.csv
```

## ⚠️ IMPORTANTE

1. El generador ahora usa `python3 -m attack_generator` (sin .generator)
2. El archivo stdin se lee con `--config -` seguido de heredoc
3. Siempre usar `sudo` para detector y tcpreplay
4. Verificar PCI address con `dpdk-devbind.py --status`
5. Verificar interfaz con `ip -br link show`

---

**¡Todo listo para experimentar!** 🚀

Si encuentras problemas, consulta las secciones de Troubleshooting en:
- detector_system/README.md
- EXPERIMENTS.md
