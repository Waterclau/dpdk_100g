# Attack Generator - Generador de PCAPs DDoS Realistas

Generador modular y eficiente de archivos PCAP para simulación de ataques DDoS, diseñado para análisis defensivo, entrenamiento de modelos ML y experimentos en entornos controlados (CloudLab, DPDK, OctoSketch).

## Características

- **Modular**: Arquitectura extensible con módulos separados por tipo de ataque
- **Realista**:
  - Timestamps con variabilidad temporal (ráfagas, jitter)
  - TTL, tamaños de paquete y puertos basados en distribuciones reales
  - Payloads plausibles (HTTP válido, DNS formateado, etc.)
  - Opciones TCP/IP variables
- **Eficiente**: Generación streaming con `PcapWriter` (no carga todo en memoria)
- **Configurable**: CLI completa + archivos JSON de configuración
- **Reproducible**: Seeds para generación determinista
- **Basado en datasets**: Extrae distribuciones de PCAPs reales (CIC-IDS, CAIDA, MAWI)
- **Mezcla con tráfico benigno**: Incrusta ataques en tráfico legítimo
- **Trazabilidad**: Genera metadata JSON con parámetros, estadísticas y checksums

## Tipos de Ataques Soportados

| Tipo | Descripción | Características |
|------|-------------|-----------------|
| `syn_flood` | SYN Flood | IPs aleatorias, opciones TCP variadas, ventanas realistas |
| `udp_flood` | UDP Flood | Payloads con distribución long-tail, puertos variados |
| `dns_amp` | DNS Amplification | Respuestas DNS amplificadas desde resolvers conocidos |
| `ntp_amp` | NTP Amplification | Monlist responses desde servidores NTP |
| `http_flood` | HTTP Flood | Requests GET/POST válidos con User-Agents realistas |
| `icmp_flood` | ICMP Flood | Echo, Unreachable, Time Exceeded con payloads variables |
| `fragmentation` | Fragmentación IP | Fragmentos con offsets correctos y flags MF |
| `ack_flood` | ACK Flood | ACKs con window size 0, secuencias aleatorias |
| `volumetric` | Ataque Mixto | Combinación configurable de múltiples tipos |

## Instalación

### Requisitos

```bash
# Python 3.8+
pip install scapy numpy scipy
```

### Instalación

```bash
cd attack_generator
pip install -e .
```

O copiar directamente el directorio `attack_generator/` a tu proyecto.

## Uso

### 1. Modo Básico (CLI)

```bash
# Generar SYN flood simple
python -m attack_generator.generator \
    --target-ip 10.10.1.2 \
    --attack syn_flood \
    --num-packets 100000 \
    --pps 10000 \
    --output-dir ./pcaps

# Especificar duración en lugar de número de paquetes
python -m attack_generator.generator \
    --target-ip 10.10.1.2 \
    --attack udp_flood \
    --duration 60 \
    --pps 15000

# Ver estadísticas sin generar (dry-run)
python -m attack_generator.generator \
    --target-ip 10.10.1.2 \
    --attack http_flood \
    --num-packets 50000 \
    --dry-run
```

### 2. Configuración JSON (Recomendado)

Crear `attacks_config.json`:

```json
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {
      "type": "syn_flood",
      "num_packets": 100000,
      "pps": 10000
    },
    {
      "type": "udp_flood",
      "num_packets": 150000,
      "pps": 15000
    },
    {
      "type": "volumetric",
      "num_packets": 105000,
      "pps": 20000
    }
  ]
}
```

Ejecutar:

```bash
python -m attack_generator.generator --config attacks_config.json
```

### 3. Uso con Datasets

Primero, extraer distribuciones de un PCAP real:

```bash
# Extraer distribuciones estadísticas de un PCAP
python -m attack_generator.generator \
    --extract-dataset /path/to/real_traffic.pcap
# Genera: real_traffic_dist.json
```

Luego usar esas distribuciones:

```bash
python -m attack_generator.generator \
    --target-ip 10.10.1.2 \
    --attack syn_flood \
    --num-packets 50000 \
    --dataset-path real_traffic_dist.json
```

O en JSON:

```json
{
  "target_ip": "10.10.1.2",
  "dataset_path": "/local/datasets/cicids2017_dist.json",
  "attacks": [...]
}
```

### 4. Mezcla con Tráfico Benigno

```bash
python -m attack_generator.generator \
    --target-ip 10.10.1.2 \
    --attack syn_flood \
    --num-packets 50000 \
    --mix-benign /path/to/benign_traffic.pcap \
    --attack-ratio 0.25
# Genera: syn_flood.pcap (ataque puro) + syn_flood_mixed.pcap (25% ataque, 75% benigno)
```

O en JSON:

```json
{
  "target_ip": "10.10.1.2",
  "mix_benign": "/local/pcaps/benign_traffic.pcap",
  "attack_ratio": 0.25,
  "attacks": [...]
}
```

### 5. Reproducibilidad

```bash
# Mismo seed = mismos paquetes
python -m attack_generator.generator \
    --config config.json \
    --seed 12345

# Regenerar con mismo seed produce resultados idénticos
python -m attack_generator.generator \
    --config config.json \
    --seed 12345
```

## Integración con CloudLab/DPDK

### Script de Generación en CloudLab

```bash
#!/bin/bash
# generate_attacks_cloudlab.sh

cd /local/pcaps

# Generar ataques para experimentos DPDK
python3 -m attack_generator.generator --config - <<EOF
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
    {"type": "syn_flood", "num_packets": 100000, "pps": 10000},
    {"type": "udp_flood", "num_packets": 150000, "pps": 15000},
    {"type": "dns_amp", "num_packets": 80000, "pps": 8000},
    {"type": "ntp_amp", "num_packets": 70000, "pps": 7000},
    {"type": "http_flood", "num_packets": 30000, "pps": 3000},
    {"type": "icmp_flood", "num_packets": 50000, "pps": 5000},
    {"type": "fragmentation", "num_packets": 60000, "pps": 5000},
    {"type": "ack_flood", "num_packets": 90000, "pps": 9000},
    {"type": "volumetric", "num_packets": 105000, "pps": 20000}
  ]
}
EOF

echo "Ataques generados en /local/pcaps"
ls -lh /local/pcaps/*.pcap
```

### Ejecutar Experimentos

```bash
# 1. Generar ataques
./generate_attacks_cloudlab.sh

# 2. Ejecutar detector DPDK
cd /local/octosketch
./run_detector.sh

# 3. Ejecutar experimentos con tcpreplay
cd /local
./run_experiment.sh
```

## Estructura del Proyecto

```
attack_generator/
├── __init__.py              # Módulo principal
├── generator.py             # CLI y orquestador
├── attacks.py               # Generadores de ataques
├── utils.py                 # Utilidades (timestamps, IPs, payloads)
├── config_examples/         # Ejemplos de configuración
│   ├── basic_attacks.json
│   └── advanced_with_benign.json
└── tests/                   # Tests unitarios
    └── test_generators.py
```

## Metadata Generada

Cada ejecución genera `metadata.json`:

```json
{
  "generation_time": "2025-01-15 10:30:00",
  "config": {...},
  "seed": 42,
  "stats": {
    "syn_flood": {
      "num_packets": 100000,
      "pps": 10000,
      "duration_sec": 10.52,
      "file_size_mb": 6.8,
      "output_file": "/local/pcaps/syn_flood.pcap"
    },
    ...
  },
  "checksums": {
    "syn_flood.pcap": "a3f5d8c2...",
    ...
  }
}
```

## Tests

```bash
# Ejecutar tests unitarios
cd attack_generator/tests
python -m unittest test_generators.py

# Tests específicos
python -m unittest test_generators.TestTimestampGenerator
python -m unittest test_generators.TestAttackGenerators.test_syn_flood_count
```

## Uso Programático

```python
from attack_generator import AttackPcapGenerator

config = {
    'target_ip': '10.10.1.2',
    'output_dir': './pcaps',
    'seed': 42,
    'attacks': [
        {'type': 'syn_flood', 'num_packets': 10000, 'pps': 1000}
    ]
}

generator = AttackPcapGenerator(config)
generator.generate_from_config(config['attacks'])
```

## Mejores Prácticas

1. **Usa seeds para reproducibilidad** en experimentos científicos
2. **Extrae distribuciones de datasets reales** (CIC-IDS, CAIDA) para mayor realismo
3. **Mezcla con tráfico benigno** (20-30% ataque) para detectores ML
4. **Usa dry-run** primero para estimar tiempos y tamaños
5. **Guarda metadata** para trazabilidad completa de experimentos
6. **Ajusta PPS** según capacidad de red (100G = ~148 Mpps máx teórico)

## Limitaciones y Consideraciones

- **Uso ético**: Solo para entornos controlados, simulaciones defensivas y educación
- **Autorización requerida**: Uso en CloudLab, laboratorios académicos, CTFs
- **No para producción**: No usar en redes reales sin autorización explícita
- **Checksums**: Scapy recalcula checksums automáticamente
- **MACs**: Se usan MACs por defecto de Scapy (pueden personalizarse)

## Parámetros CLI Completos

```
--target-ip IP          IP destino del ataque (default: 10.10.1.2)
--output-dir DIR        Directorio de salida (default: ./pcaps)
--seed SEED             Seed para reproducibilidad

--attack TYPE           Tipo de ataque a generar
--num-packets N         Número de paquetes
--pps RATE              Paquetes por segundo
--duration SECS         Duración en segundos (alternativa a --num-packets)

--config FILE           Archivo JSON con configuración completa
--dataset-path FILE     PCAP o JSON con distribuciones estadísticas
--mix-benign FILE       PCAP con tráfico benigno para mezclar
--attack-ratio RATIO    Ratio de ataque en mezcla (0.0-1.0, default: 0.3)

--dry-run               Solo calcular métricas sin escribir PCAPs
--extract-dataset FILE  Extraer distribuciones de PCAP a JSON
```

## Ejemplos de Configuración Completa

Ver `config_examples/` para:
- `basic_attacks.json` - Generación simple de 9 tipos de ataques
- `advanced_with_benign.json` - Configuración avanzada con datasets y mezcla

## Contribución

Este proyecto es para uso académico y defensivo. Mejoras bienvenidas:
- Nuevos tipos de ataques (QUIC, gRPC, etc.)
- Mejores modelos estadísticos
- Optimizaciones de performance
- Tests adicionales

## Licencia

Uso educativo y académico. Prohibido uso malicioso.

## Referencias

- DPDK: https://www.dpdk.org/
- Scapy: https://scapy.net/
- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CAIDA Datasets: https://www.caida.org/catalog/datasets/
