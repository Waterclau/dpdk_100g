# Sistema DDoS - Generación, Detección y Experimentación

Sistema completo para generación, detección y análisis de ataques DDoS en redes 100G usando CloudLab, DPDK y Machine Learning.

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLOUDLAB TOPOLOGY                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────────┐              ┌──────────────────┐       │
│   │   Nodo TG        │   100G       │  Nodo Detector   │       │
│   │  (Generator)     │  ────────>   │    (Target)      │       │
│   │                  │   Ethernet   │                  │       │
│   │ • attack_gen     │              │ • DPDK Detector  │       │
│   │ • tcpreplay      │              │ • Sketches       │       │
│   │ • run_exp.sh     │              │ • ML Features    │       │
│   └──────────────────┘              └──────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Estructura del Proyecto

```
dpdk_100g/
├── attack_generator/           # Generador modular de PCAPs DDoS
│   ├── generator.py           # CLI principal
│   ├── attacks.py             # 9 tipos de ataques
│   ├── benign_traffic.py      # Generador de tráfico normal
│   ├── utils.py               # Utilidades (timestamps, IPs, payloads)
│   └── README.md              # Documentación completa
│
├── detector_system/           # Sistema de detección DPDK + ML
│   ├── detector_dpdk.c        # Core C + DPDK con Sketches
│   ├── feature_extractor.py   # Extracción de features ML
│   ├── model_inferencer.py    # Inferencia ML en tiempo real
│   ├── config.py              # Configuración centralizada
│   ├── scripts/
│   │   ├── build.sh          # Compilar detector
│   │   ├── run.sh            # Ejecutar (foreground)
│   │   ├── run_background.sh # Ejecutar (background)
│   │   └── analyze.py        # Análisis de logs
│   └── README.md              # Documentación completa
│
├── run_experiment.sh          # Script de experimentación (Nodo TG)
├── EXPERIMENTS.md             # Guía paso a paso completa
└── readme.md                  # Este archivo
```

## 🚀 Quick Start

### 1. Generación de Ataques (Nodo TG)

```bash
cd /local/dpdk_100g

# Generar ataques mezclados con tráfico benigno
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --mix-benign /local/pcaps/benign_traffic.pcap \
  --attack-ratio 0.3 \
  --config - <<'EOF'
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000}
  ]
}
EOF
```

### 2. Detección (Nodo Detector)

```bash
cd /local/dpdk_100g/detector_system

# Compilar (primera vez)
./scripts/build.sh

# Ejecutar en background
sudo ./scripts/run_background.sh 0000:41:00.0

# Monitorear
tail -f /local/logs/ml_features.csv
```

### 3. Experimento (Nodo TG)

```bash
cd /local/dpdk_100g

# Reproducir todos los PCAPs
sudo ./run_experiment.sh

# O reproducir específicos
sudo ./run_experiment.sh specific syn_flood_mixed.pcap

# O modo interactivo
sudo ./run_experiment.sh interactive
```

### 4. Análisis (Nodo Detector)

```bash
cd /local/dpdk_100g/detector_system

# Análisis básico
python3 scripts/analyze.py

# Exportar features
python3 scripts/analyze.py --export-features /local/features.csv
```

## 📚 Documentación Detallada

- **[attack_generator/README.md](attack_generator/README.md)** - Generador de ataques
  - 9 tipos de ataques DDoS
  - Generación de tráfico benigno
  - Mezcla y configuración
  - Ejemplos de uso

- **[detector_system/README.md](detector_system/README.md)** - Sistema de detección
  - Compilación y ejecución
  - Sketches (Count-Min, HyperLogLog, Bloom Filter)
  - 19 features ML
  - Análisis de logs

- **[EXPERIMENTS.md](EXPERIMENTS.md)** - Guía de experimentación
  - Setup inicial CloudLab
  - Flujo completo paso a paso
  - Experimentos avanzados
  - Troubleshooting

## 🔥 Características Principales

### Generador de Ataques
- ✅ **9 tipos de ataques**: SYN flood, UDP flood, DNS amp, NTP amp, HTTP flood, ICMP flood, Fragmentation, ACK flood, Volumetric
- ✅ **Tráfico benigno realista**: HTTP, DNS, SSH, ICMP, NTP con sesiones completas
- ✅ **Mezcla automática**: Combina ataques con tráfico normal
- ✅ **Reproducible**: Seeds para generación determinista
- ✅ **Escalable**: Generación streaming sin cargar todo en memoria
- ✅ **Configurable**: CLI + JSON config

### Detector DPDK
- ✅ **Alto rendimiento**: ~20 Mpps en línea 100G
- ✅ **Sketches probabilísticas**: Count-Min, HyperLogLog, Bloom Filter
- ✅ **19 features ML**: Para detección con modelos entrenados
- ✅ **Detección rule-based**: Umbrales configurables
- ✅ **Logging estructurado**: 3 tipos de logs (CSV)
- ✅ **Zero-copy**: Procesamiento eficiente con DPDK

### Sistema de Experimentación
- ✅ **Replay automatizado**: Script completo con tcpreplay
- ✅ **Múltiples modos**: All, interactive, sequential, specific
- ✅ **Estadísticas detalladas**: Logs y reportes automáticos
- ✅ **Rate control**: Configurable en Mbps
- ✅ **Monitoreo**: Logs en tiempo real

## 🛠️ Comandos Rápidos

### Generación
```bash
# Tráfico benigno
sudo python3 -m attack_generator --benign-only --output benign.pcap --benign-duration 60

# Ataque simple
sudo python3 -m attack_generator --attack syn_flood --num-packets 100000 --pps 10000

# Desde config JSON
sudo python3 -m attack_generator --config attacks.json
```

### Detección
```bash
# Compilar
cd detector_system && ./scripts/build.sh

# Ejecutar
sudo ./scripts/run.sh 0000:41:00.0

# Analizar
python3 scripts/analyze.py --export-features features.csv
```

### Experimentación
```bash
# Todos los PCAPs
sudo ./run_experiment.sh

# Rate personalizado
sudo ./run_experiment.sh -r 5000

# Específicos
sudo ./run_experiment.sh specific syn_flood.pcap
```

## 🚦 Flujo Típico de Experimento

```bash
# 1. Nodo TG: Generar ataques
cd /local/dpdk_100g
sudo python3 -m attack_generator --config attacks.json

# 2. Nodo Detector: Iniciar detector
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# 3. Nodo TG: Ejecutar experimento
sudo ./run_experiment.sh -n "exp_syn_udp" -r 2000

# 4. Nodo Detector: Analizar resultados
python3 scripts/analyze.py --export-features /local/features.csv
```

## 📊 Resultados

Los experimentos generan:
- `/local/pcaps/` - PCAPs de ataques generados
- `/local/logs/detection.log` - Estadísticas básicas del detector
- `/local/logs/ml_features.csv` - 19 features para ML
- `/local/logs/alerts.log` - Alertas de seguridad
- `/local/logs/experiments/` - Reportes de experimentos

## ⚖️ Uso Ético

- ✅ Solo para entornos controlados (CloudLab, laboratorios)
- ✅ Solo con autorización explícita
- ✅ Para fines educativos y defensivos
- ❌ Prohibido uso malicioso

---

**¿Necesitas ayuda?** Consulta:
- `attack_generator/README.md` - Generación de ataques
- `detector_system/README.md` - Sistema de detección
- `EXPERIMENTS.md` - Guía completa paso a paso

**¡Listo para experimentar!** 🚀
