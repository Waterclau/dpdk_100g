# Quick Start - Tráfico Baseline con Tcpreplay

## Inicio Rápido (3 pasos)

### 1. Instalar dependencias
```bash
# Python + Scapy
pip install -r requirements.txt

# Tcpreplay
sudo apt-get install tcpreplay
```

### 2. Generar PCAP baseline
```bash
# Opción A: Automático (100K paquetes)
python3 generate_baseline_pcap.py

# Opción B: Personalizado
python3 generate_baseline_pcap.py -n 1000000 -o my_baseline.pcap
```

### 3. Reproducir tráfico
```bash
# Identificar interfaz
ip link show

# Replay a 10 Gbps
sudo ./replay_baseline.sh -i <tu_interfaz> -r 10000
```

## Modo Interactivo

```bash
# Script guiado paso a paso
./quick_start.sh
```

## Ejemplos Comunes

### Testing Rápido (1 Gbps)
```bash
python3 generate_baseline_pcap.py -n 10000 -o test.pcap
sudo ./replay_baseline.sh -i eth0 -f test.pcap -r 1000
```

### Baseline Normal (10 Gbps, 5 minutos)
```bash
python3 generate_baseline_pcap.py -n 1000000
sudo timeout 300 ./replay_baseline.sh -i eth0 -r 10000
```

### Alto Rendimiento (40 Gbps)
```bash
python3 generate_baseline_pcap.py -n 5000000 -o baseline_5M.pcap -v
sudo ./replay_baseline.sh -i eth0 -f baseline_5M.pcap -r 40000 -p
```

### Máximo Rendimiento (100 Gbps, topspeed)
```bash
python3 generate_baseline_pcap.py -n 10000000 -o baseline_10M.pcap -v
sudo ./replay_baseline.sh -i eth0 -f baseline_10M.pcap -t -p
```

## Suite Completa de PCAPs

Generar múltiples PCAPs de diferentes tamaños:

```bash
./generate_pcap_suite.sh
```

Esto crea:
- `pcaps/baseline_small_*.pcap` (10K paquetes - testing)
- `pcaps/baseline_medium_*.pcap` (100K paquetes - normal)
- `pcaps/baseline_large_*.pcap` (1M paquetes - largo)
- `pcaps/baseline_xlarge_*.pcap` (5M paquetes - extendido)
- `pcaps/baseline_xxlarge_*.pcap` (10M paquetes - máximo)

## Verificación

### Analizar PCAP generado
```bash
python3 analyze_pcap.py baseline_traffic.pcap
```

### Capturar en Monitor
```bash
# En el nodo Monitor
sudo tcpdump -i <interface> -n tcp port 80 -c 10 -A
```

### Ver estadísticas en tiempo real
```bash
# Terminal 1: Replay
sudo ./replay_baseline.sh -i eth0 -r 10000

# Terminal 2: Monitoreo
watch -n 1 'ethtool -S eth0 | grep tx_packets'
```

## Workflow Completo

```bash
# 1. Generar PCAP (una vez)
python3 generate_baseline_pcap.py -n 5000000 -o baseline.pcap -v

# 2. Verificar PCAP
python3 analyze_pcap.py baseline.pcap -n 1000

# 3. Preparar interfaz
sudo ip link set eth0 up
sudo ethtool -K eth0 gro off gso off tso off

# 4. Iniciar captura en Monitor
# (en nodo Monitor con DPDK/OctoSketch)

# 5. Enviar baseline (5 minutos)
sudo timeout 300 ./replay_baseline.sh -i eth0 -f baseline.pcap -r 10000

# 6. Esperar estabilización
sleep 10

# 7. Lanzar ataque HTTP flood
# (tu generador de ataque)

# 8. Comparar métricas baseline vs ataque
```

## Solución de Problemas

### No encuentra interfaz
```bash
# Listar interfaces disponibles
ip link show
ifconfig -a
```

### Bajo rendimiento
```bash
# Deshabilitar offloads
sudo ethtool -K eth0 tso off gso off gro off

# Usar preload
sudo ./replay_baseline.sh -i eth0 -r 10000 -p

# Verificar CPU
top
```

### Paquetes no llegan
```bash
# Verificar link
sudo ethtool eth0 | grep "Link detected"

# Verificar envío
sudo tcpdump -i eth0 -c 5 tcp port 80

# Verificar recepción (en Monitor)
sudo tcpdump -i <monitor_iface> -c 5 tcp port 80
```

## Configuración para tu Entorno

Copiar y editar configuración:
```bash
cp config.example config.sh
nano config.sh
```

Luego modificar:
- `SRC_IP_BASE`: Tu red de origen
- `DST_IP`: IP del Monitor
- `DST_MAC`: MAC del Monitor
- `INTERFACE`: Tu interfaz de red

## Más Información

Ver `README.md` para documentación completa.

## Archivos Principales

| Archivo | Descripción |
|---------|-------------|
| `generate_baseline_pcap.py` | Genera PCAPs con tráfico HTTP |
| `replay_baseline.sh` | Reproduce PCAPs con tcpreplay |
| `analyze_pcap.py` | Analiza contenido de PCAPs |
| `quick_start.sh` | Script interactivo guiado |
| `generate_pcap_suite.sh` | Genera suite completa de PCAPs |
| `README.md` | Documentación completa |
