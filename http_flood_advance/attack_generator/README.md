# Generador de Ataques HTTP Flood

Sistema para generar y reproducir ataques HTTP flood usando PCAPs. Diseñado para ser detectado con DPDK/OctoSketch.

## Descripción

Este generador crea tráfico de ataque HTTP flood desde un **nodo Atacante** hacia el **Monitor**. El tráfico malicioso se puede combinar con el tráfico baseline para simular escenarios realistas de ataque.

## Características

✅ **Múltiples tipos de ataque**: GET flood, POST flood, Random GET, Slowloris, Mixed
✅ **Botnet simulado**: IPs atacantes distribuidas (50-500 bots)
✅ **Patrones maliciosos**: URLs, User-Agents y payloads típicos de ataques
✅ **Alto rendimiento**: Tcpreplay para 1-100 Gbps
✅ **Compatible con DPDK**: PCAPs para análisis con OctoSketch

## Instalación

```bash
pip install -r requirements.txt
sudo apt-get install tcpreplay
```

## Tipos de Ataque

| Tipo | Descripción | Uso |
|------|-------------|-----|
| **get_flood** | GET repetitivos a misma URL (/) | Ataque básico DDoS |
| **post_flood** | POST flood a endpoints de login | Ataque a autenticación |
| **random_get** | GET a URLs aleatorias/maliciosas | Evasión de detección |
| **slowloris** | Conexiones HTTP lentas incompletas | Agotamiento de conexiones |
| **mixed** | Combinación de GET + POST | Ataque realista (recomendado) |

## Uso Básico

### 1. Generar PCAP de Ataque

```bash
# Ataque mixed (recomendado) - 1M paquetes
python3 generate_http_flood.py \
    -t mixed \
    -n 1000000 \
    -o attack_mixed_1M.pcap \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -b 100 \
    -v
```

### 2. Lanzar Ataque

```bash
# Ataque a 5 Gbps
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

## Escenario Completo: Baseline + Ataque

### Paso 1: Monitor - Captura
```bash
sudo tcpdump -i ens1f0 -n tcp port 80 -w capture_full.pcap
```

### Paso 2: Controlador - Baseline (continuo)
```bash
cd ../benign_generator
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

### Paso 3: Atacante - Ataque (después de 30 seg)
```bash
sleep 30
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

## Parámetros de Generación

```bash
python3 generate_http_flood.py [opciones]

Opciones:
  -t, --type          Tipo de ataque (get_flood, post_flood, random_get, slowloris, mixed)
  -n, --num-packets   Número de paquetes (default: 100000)
  -o, --output        Archivo PCAP de salida
  -d, --dst-ip        IP destino (Monitor)
  --dst-mac           MAC destino (Monitor)
  -s, --src-ip        IP base del botnet (default: 203.0.113.0)
  -b, --botnet-size   Número de IPs atacantes (default: 100)
  -v, --verbose       Modo verbose
```

## Parámetros de Replay

```bash
./replay_attack.sh [opciones]

Opciones:
  -i <interface>      Interfaz de red (obligatorio)
  -f <pcap_file>      Archivo PCAP de ataque (obligatorio)
  -r <rate_mbps>      Tasa en Mbps (default: 1000)
  -t                  Modo topspeed (máxima velocidad)
  -l <count>          Loops (0 = infinito)
  -p                  Preload PCAP en RAM
  -q                  Quiet (sin confirmación)
```

## Ejemplos de Ataques

### Ataque Leve (1 Gbps, 100K paquetes)
```bash
python3 generate_http_flood.py -t get_flood -n 100000 -o attack_low.pcap --dst-mac 0c:42:a1:8c:dd:0c -v
sudo ./replay_attack.sh -i ens1f0 -f attack_low.pcap -r 1000 -q
```

### Ataque Medio (5 Gbps, 1M paquetes)
```bash
python3 generate_http_flood.py -t mixed -n 1000000 -o attack_medium.pcap --dst-mac 0c:42:a1:8c:dd:0c -b 100 -v
sudo ./replay_attack.sh -i ens1f0 -f attack_medium.pcap -r 5000 -q
```

### Ataque Intenso (10 Gbps, 5M paquetes)
```bash
python3 generate_http_flood.py -t random_get -n 5000000 -o attack_high.pcap --dst-mac 0c:42:a1:8c:dd:0c -b 200 -v
sudo ./replay_attack.sh -i ens1f0 -f attack_high.pcap -r 10000 -q -p
```

### Ataque Extremo (Topspeed)
```bash
python3 generate_http_flood.py -t mixed -n 10000000 -o attack_extreme.pcap --dst-mac 0c:42:a1:8c:dd:0c -b 500 -v
sudo ./replay_attack.sh -i ens1f0 -f attack_extreme.pcap -t -q -p
```

## Diferencias: Baseline vs Ataque

| Característica | Baseline | Ataque |
|----------------|----------|--------|
| **IPs origen** | 192.168.1.X | 203.0.113.X |
| **URLs** | Variadas realistas | Repetitivas/maliciosas |
| **User-Agents** | Navegadores normales | Bots/vacío |
| **Distribución** | Natural (30% home, 25% API...) | Concentrada (>80% misma URL) |
| **Métodos** | 90% GET, 10% POST | 95%+ GET a "/" |
| **Hosts** | Variados | Mayormente IP |
| **Tasa** | Estable | Burst/sostenida alta |

## Verificación en Monitor

### Ver IPs atacantes
```bash
sudo tcpdump -i ens1f0 -n src net 203.0.113.0/24 -c 20 -v
```

### Ver patrones maliciosos
```bash
sudo tcpdump -i ens1f0 -n tcp port 80 -A -c 50 | grep -E "GET /|POST /|User-Agent"
```

### Comparar tasas
```bash
# Terminal 1 - Durante baseline
ethtool -S ens1f0 | grep rx_packets

# Terminal 2 - Durante ataque (debería aumentar)
ethtool -S ens1f0 | grep rx_packets
```

### Análisis de distribución
```bash
# Capturar 10K paquetes
sudo tcpdump -i ens1f0 -n tcp port 80 -c 10000 -w sample.pcap

# Analizar IPs más frecuentes
tcpdump -r sample.pcap -n | awk '{print $3}' | cut -d'.' -f1-4 | sort | uniq -c | sort -rn | head -20
```

## Botnet Simulado

El generador simula un botnet distribuido:
- **Tamaño configurable**: 50-500 IPs atacantes
- **Red atacante**: 203.0.113.0/24 (TEST-NET-3, RFC 5737)
- **Distribución**: IPs aleatorias dentro del rango
- **Comportamiento**: Cada IP puede atacar múltiples veces

### Ejemplo de IPs generadas:
```
203.0.113.45
203.0.113.123
203.0.113.89
203.0.113.201
...
```

## Patrones Maliciosos

### URLs atacadas:
```
/                    (GET flood básico)
/login               (POST flood)
/admin               (escaneo)
/wp-admin            (WordPress)
/phpmyadmin          (database)
/.env                (config leak)
/api/v1/login        (API abuse)
```

### User-Agents maliciosos:
```
Mozilla/5.0          (genérico)
python-requests/*    (script)
curl/*               (tool)
Wget/*               (tool)
(vacío)              (bot mal configurado)
```

## Rendimiento

### Generación de PCAPs:
- 100K paquetes: ~5-10s (~15 MB)
- 1M paquetes: ~30-60s (~150 MB)
- 5M paquetes: ~3-5min (~750 MB)

### Replay:
- 1 Gbps: Fácil, <20% CPU
- 5 Gbps: Fácil, 30-40% CPU
- 10 Gbps: Alcanzable, 50-70% CPU
- 40+ Gbps: Requiere preload y NIC 100G

## Configuración de Red

```
Atacante (origen):
  IP:  203.0.113.X (botnet simulado)
  MAC: aa:bb:cc:dd:ee:ff (configurable)
  Interface: ens1f0

Monitor (destino):
  IP:  10.0.0.1
  MAC: 0c:42:a1:8c:dd:0c
  Interface: ens1f0
```

## Troubleshooting

### No genera paquetes
```bash
# Verificar Scapy
python3 -c "from scapy.all import *; print('OK')"

# Reinstalar si falla
pip install --upgrade scapy
```

### Replay no envía
```bash
# Verificar interfaz
sudo ip link set ens1f0 up
sudo ethtool ens1f0 | grep "Link detected"

# Verificar permisos
sudo ./replay_attack.sh ...
```

### Monitor no recibe ataque
```bash
# Verificar MAC destino
ip link show ens1f0 | grep link/ether

# Regenerar PCAP con MAC correcta
python3 generate_http_flood.py ... --dst-mac <MAC_correcta>
```

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `generate_http_flood.py` | Generador de PCAPs de ataque |
| `replay_attack.sh` | Script de replay con tcpreplay |
| `COMANDOS_ATAQUE.md` | Guía rápida de comandos |
| `requirements.txt` | Dependencias Python |

## Próximos Pasos

1. ✅ Generar PCAPs de ataque
2. ✅ Reproducir ataques con tcpreplay
3. ⏭️ **Siguiente**: Detector DPDK con OctoSketch

## Licencia

GPL v2
