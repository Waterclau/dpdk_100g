# Detector DDoS - DPDK + Sketches + ML

Sistema completo de detección de ataques DDoS en tiempo real para redes de alta velocidad (100G) usando DPDK, estructuras de datos probabilísticas (Sketches) y Machine Learning.

## Características

### Core del Detector (C + DPDK)
- **Procesamiento zero-copy** con DPDK para máximo rendimiento
- **Count-Min Sketch** para conteo eficiente de flujos
- **HyperLogLog** para estimación de cardinalidad de IPs/puertos únicos
- **Bloom Filter** para detección rápida de IPs vistas
- **Extracción de 19 features ML** en tiempo real
- **Umbrales configurables** para detección rule-based
- **Logging estructurado** (CSV) para análisis posterior

### Sistema de Análisis (Python)
- **Feature Extractor**: Extrae características estadísticas desde logs
- **Model Inferencer**: Inferencia ML con modelos pre-entrenados (XGBoost, RF, etc.)
- **Detección de tipos de ataque**: SYN flood, UDP flood, HTTP flood, etc.
- **Análisis en tiempo real y post-mortem**

## Arquitectura

```
detector_system/
├── detector_dpdk.c          # Core DPDK en C
├── config.py                # Configuración centralizada
├── feature_extractor.py     # Extracción de features
├── model_inferencer.py      # Inferencia ML
├── scripts/
│   ├── build.sh            # Compilar detector
│   ├── run.sh              # Ejecutar en foreground
│   ├── run_background.sh   # Ejecutar en background
│   └── analyze.py          # Análisis de logs
└── README.md
```

## Requisitos

### Sistema
```bash
# Ubuntu 20.04+ / CloudLab
sudo apt update
sudo apt install -y build-essential pkg-config python3 python3-pip

# DPDK (ya instalado en CloudLab)
sudo apt install -y dpdk dpdk-dev
```

### Python
```bash
pip3 install pandas numpy scikit-learn xgboost
```

## Instalación y Compilación

### 1. Clonar o copiar el proyecto
```bash
cd /local
git clone <tu-repo> dpdk_100g
cd dpdk_100g/detector_system
```

### 2. Compilar el detector DPDK
```bash
chmod +x scripts/*.sh
./scripts/build.sh
```

Esto genera el binario `detector_dpdk`.

### 3. Verificar tu NIC
```bash
# Listar dispositivos DPDK
dpdk-devbind.py --status

# Ejemplo de salida:
# 0000:41:00.0 'Ethernet Controller 10G X550T' drv=vfio-pci unused=ixgbe
```

Anota el PCI address (e.g., `0000:41:00.0`) para usarlo en los comandos.

## Uso

### Modo 1: Ejecución en Foreground (Recomendado para debugging)

```bash
# Ejecutar con tu PCI address
sudo ./scripts/run.sh 0000:41:00.0
```

Verás output en tiempo real:

```
Timestamp         PPS       Gbps        TCP        UDP        SYN
════════════════════════════════════════════════════════════════
1705334401     125340      11.23     95000      30000      65000
1705334402     130250      12.05    100000      30000      70000
```

Para detener: `Ctrl+C`

### Modo 2: Ejecución en Background

```bash
# Iniciar en background
sudo ./scripts/run_background.sh 0000:41:00.0

# Ver logs en tiempo real
tail -f /local/logs/detection.log
tail -f /local/logs/ml_features.csv
tail -f /local/logs/alerts.log

# Detener
sudo pkill -9 detector_dpdk
```

### Modo 3: Análisis de Logs (Post-Mortem o Tiempo Real)

Una vez que el detector está corriendo y generando logs:

```bash
# Análisis básico
python3 scripts/analyze.py

# Con modelo ML
python3 scripts/analyze.py --model-path /local/models/xgboost_detector.pkl

# Exportar features para entrenamiento
python3 scripts/analyze.py --export-features /local/training_data.csv

# Análisis con ventana personalizada
python3 scripts/analyze.py --window-size 30
```

## Logs Generados

El detector crea 3 archivos de log en `/local/logs/`:

### 1. `detection.log` - Estadísticas básicas
```csv
timestamp,pps,gbps,tcp,udp,icmp,syn,ack,rst,fin,frag
1705334401,125340,11.23,95000,30000,340,65000,80000,200,150,50
```

### 2. `ml_features.csv` - Features para ML (19 columnas)
```csv
timestamp,gbps,pps,avg_pkt_size,std_dev,tcp_ratio,udp_ratio,icmp_ratio,syn_ratio,ack_ratio,rst_ratio,fin_ratio,frag_ratio,small_pkt_ratio,entropy_src_ip,entropy_dst_port,unique_src_ips,unique_dst_ports,syn_per_sec,ack_per_sec
1705334401,11.23,125340,950.2,142.5,0.758,0.239,0.003,0.684,0.842,0.002,0.001,0.0004,0.123,7.82,9.45,15234,8945,65000,80000
```

### 3. `alerts.log` - Alertas de seguridad
```csv
timestamp,alert_type,severity,details
1705334401,SYN_FLOOD,CRITICAL,syn_ratio=0.78
1705334402,HIGH_PPS,HIGH,pps=250000
```

## Features Extraídas (19 total)

| Feature | Descripción |
|---------|-------------|
| `gbps` | Gigabits por segundo |
| `pps` | Paquetes por segundo |
| `avg_pkt_size` | Tamaño promedio de paquetes (bytes) |
| `std_dev` | Desviación estándar del tamaño |
| `tcp_ratio` | Ratio TCP / Total |
| `udp_ratio` | Ratio UDP / Total |
| `icmp_ratio` | Ratio ICMP / Total |
| `syn_ratio` | Ratio SYN / TCP |
| `ack_ratio` | Ratio ACK / TCP |
| `rst_ratio` | Ratio RST / TCP |
| `fin_ratio` | Ratio FIN / TCP |
| `frag_ratio` | Ratio paquetes fragmentados |
| `small_pkt_ratio` | Ratio paquetes < 100 bytes |
| `entropy_src_ip` | Entropía de IPs origen |
| `entropy_dst_port` | Entropía de puertos destino |
| `unique_src_ips` | IPs origen únicas (HyperLogLog) |
| `unique_dst_ports` | Puertos destino únicos (HyperLogLog) |
| `syn_per_sec` | SYN por segundo |
| `ack_per_sec` | ACK por segundo |

## Umbrales de Detección (Configurables en `config.py`)

```python
THRESHOLDS = {
    'pps_threshold': 100000,         # PPS para alerta volumétrica
    'gbps_threshold': 10.0,          # Gbps para alerta
    'syn_ratio_threshold': 0.7,      # SYN flood
    'udp_ratio_threshold': 0.8,      # UDP flood
    'frag_ratio_threshold': 0.3,     # Ataque de fragmentación
    'entropy_threshold_low': 3.0,    # Entropía baja (mismo origen)
    'small_packet_ratio': 0.6,       # Muchos paquetes pequeños
}
```

## Integración con Generador de Ataques

### Flujo completo de experimentación:

```bash
# Terminal 1: Iniciar detector en background
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# Terminal 2: Generar ataques
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
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

# Terminal 3: Replay con tcpreplay
sudo tcpreplay -i <interface> --mbps 10000 /local/pcaps/syn_flood.pcap

# Terminal 4: Monitorear logs en tiempo real
tail -f /local/logs/ml_features.csv

# Después del experimento: Analizar
cd /local/dpdk_100g/detector_system
python3 scripts/analyze.py \
  --export-features /local/experiment_features.csv
```

## Configuración Avanzada

### Ajustar parámetros de Sketches

Editar `detector_dpdk.c`:

```c
// Para mayor precisión (más memoria):
#define CM_WIDTH 4096      // Default: 2048
#define CM_DEPTH 6         // Default: 4
#define HLL_PRECISION 16   // Default: 14 (2^16 = 65536 buckets)
```

Luego recompilar:
```bash
./scripts/build.sh
```

### Ajustar parámetros DPDK

Editar `config.py`:

```python
class DetectorConfig:
    RX_RING_SIZE = 4096      # Default: 2048
    NUM_MBUFS = 32767        # Default: 16383
    BURST_SIZE = 128         # Default: 64
```

### Usar múltiples cores

Modificar `scripts/run.sh`:

```bash
# Usar cores 0-3
sudo ./detector_dpdk -l 0-3 -a 0000:41:00.0 --
```

## Tipos de Ataque Detectados

El detector identifica:

1. **SYN Flood**: Alto `syn_ratio`, bajo `ack_ratio`
2. **UDP Flood**: Alto `udp_ratio`, alto `pps`
3. **HTTP Flood**: Alto `tcp_ratio`, SYN moderado
4. **DNS Amplification**: Paquetes pequeños + alto UDP
5. **Fragmentation**: Alto `frag_ratio`
6. **Volumetric**: Alto `gbps` o `pps`

## Troubleshooting

### Error: "No hay puertos disponibles"
```bash
# Verificar binding DPDK
dpdk-devbind.py --status

# Bind a DPDK si es necesario
sudo dpdk-devbind.py --bind=vfio-pci 0000:41:00.0
```

### Error de compilación
```bash
# Verificar instalación DPDK
pkg-config --modversion libdpdk

# Reinstalar si es necesario
sudo apt install --reinstall dpdk dpdk-dev
```

### Logs vacíos
```bash
# Verificar permisos
sudo chmod 777 /local/logs

# Verificar que hay tráfico
tcpdump -i <interface> -c 10
```

### Alto uso de CPU
```bash
# Reducir BURST_SIZE en config.py
BURST_SIZE = 32  # Default: 64

# Limitar core affinity
sudo ./detector_dpdk -l 0 -a 0000:41:00.0 --
```

## Ejemplo Completo: Experimento CloudLab

```bash
#!/bin/bash
# Experimento completo en CloudLab

# 1. Compilar detector
cd /local/dpdk_100g/detector_system
./scripts/build.sh

# 2. Generar tráfico benigno
cd /local/dpdk_100g
sudo python3 -m attack_generator \
  --benign-only \
  --output /local/pcaps/benign.pcap \
  --benign-duration 60 \
  --benign-profile normal

# 3. Generar ataques
sudo python3 -m attack_generator \
  --target-ip 10.10.1.2 \
  --attack syn_flood \
  --num-packets 100000 \
  --pps 10000 \
  --mix-benign /local/pcaps/benign.pcap \
  --attack-ratio 0.3

# 4. Iniciar detector
cd /local/dpdk_100g/detector_system
sudo ./scripts/run_background.sh 0000:41:00.0

# 5. Replay tráfico
sudo tcpreplay -i enp65s0f0 --mbps 1000 \
  /local/pcaps/syn_flood_mixed.pcap

# 6. Esperar a que termine
sleep 20

# 7. Detener detector
sudo pkill detector_dpdk

# 8. Analizar resultados
python3 scripts/analyze.py \
  --export-features /local/experiment_results.csv

echo "Resultados en:"
echo "  /local/logs/detection.log"
echo "  /local/logs/ml_features.csv"
echo "  /local/logs/alerts.log"
echo "  /local/experiment_results.csv"
```

## Estructura de Datos (Sketches)

### Count-Min Sketch
- **Uso**: Conteo de paquetes por IP origen
- **Tamaño**: 2048 × 4 = 8,192 counters (32 KB)
- **Error**: ε = e/width ≈ 0.13%

### HyperLogLog
- **Uso**: Cardinalidad de IPs únicas y puertos únicos
- **Tamaño**: 2^14 = 16,384 registros (16 KB)
- **Error**: ±1.04/√m ≈ 0.8%

### Bloom Filter
- **Uso**: Set membership para IPs vistas
- **Tamaño**: 1,000,000 bits = 125 KB
- **False positive**: (1 - e^(-kn/m))^k ≈ 0.01%

**Memoria total**: ~175 KB para sketches

## Performance

En nodo CloudLab (Intel Xeon 2.4 GHz):

- **Throughput**: ~20 Mpps (línea 100G)
- **Latencia**: <1 µs por paquete
- **CPU**: ~80% en 1 core @ 10 Mpps
- **Memoria**: ~2 GB (DPDK mempools)

## Licencia

Uso académico y educativo. Prohibido uso malicioso.

## Referencias

- DPDK: https://www.dpdk.org/
- Count-Min Sketch: Cormode & Muthukrishnan (2005)
- HyperLogLog: Flajolet et al. (2007)
- CloudLab: https://www.cloudlab.us/
