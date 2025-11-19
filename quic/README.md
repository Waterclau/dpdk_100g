# QUIC Optimistic ACK DDoS Detector

Sistema de deteccion de ataques QUIC Optimistic ACK usando DPDK + OctoSketch, optimizado para enlaces de alta velocidad (25G-100G).

## Descripcion del Ataque

### Que es QUIC Optimistic ACK DDoS?

El ataque QUIC Optimistic ACK explota el mecanismo de control de congestion de QUIC:

1. **Comportamiento normal**: El cliente envia ACKs reconociendo paquetes recibidos del servidor
2. **Ataque**: El cliente envia ACKs "optimistas" reconociendo paquetes que **aun no ha recibido**
3. **Efecto**: El servidor cree que el canal no tiene perdidas y **aumenta agresivamente su tasa de envio**
4. **Resultado**: Amplificacion del trafico - el servidor envia mucho mas de lo que deberia

### Indicadores del Ataque

| Indicador | Normal | Ataque |
|-----------|--------|--------|
| ACK rate por IP | < 1000/s | > 5000/s |
| Bytes OUT/IN ratio | 1-3 | > 10 |
| Packet number jumps | Incrementales | Saltos grandes |
| Patron de ACKs | Coherente | Bursts intensos |

## Arquitectura del Experimento

```
    controller (baseline)          tg (ataque)
           |                           |
           |  QUIC legitimo            |  Optimistic ACKs
           |                           |
           +----------+  +-------------+
                      |  |
                      v  v
                   monitor
                      |
                      v
              DPDK + OctoSketch
                      |
                      v
                 Deteccion
```

- **controller**: Envia trafico QUIC legitimo (baseline) via tcpreplay
- **tg**: Envia trafico de ataque Optimistic ACK via tcpreplay
- **monitor**: Recibe ambos flujos, ejecuta el detector DPDK

## Estructura del Proyecto

```
quic/
├── README.md                           # Este archivo
├── steps.md                            # Guia paso a paso del experimento
├── detector_system/
│   ├── quic_optimistic_ack_detector.c  # Detector DPDK + OctoSketch
│   └── Makefile                        # Compilacion
├── benign_generator/
│   └── generate_baseline_quic.py       # Generador de trafico legitimo
├── attack_generator/
│   └── generate_optimistic_ack_attack.py # Generador de ataque
├── analysis/
│   └── analyze_quic_results.py         # Analisis de resultados
├── results/                            # Logs del detector
└── old/                                # Archivos antiguos
```

## Reglas de Deteccion

El detector implementa 5 reglas principales basadas en OctoSketch:

### 1. ACK Rate Anomaly
```c
if (ack_rate_per_ip > 5000) -> ALERT
```
Detecta IPs que envian demasiados ACKs por segundo.

### 2. Bytes Ratio Anomaly (Amplificacion)
```c
if (bytes_out / bytes_in > 10) -> ALERT
```
El indicador mas importante: el servidor envia mucho mas de lo que recibe.

### 3. Packet Number Jump Detection
```c
if (acked_pkt_num - last_sent_pkt_num > 1000) -> ALERT
```
Detecta ACKs que reconocen paquetes "del futuro".

### 4. Heavy Hitter ACKers
```c
if (ip_ack_count > 500) -> ALERT
```
IPs que acumulan muchos ACKs en la ventana de deteccion.

### 5. Burst Detection
```c
if (acks_in_100ms > 100) -> ALERT
```
Rafagas anormales de ACKs.

## Requisitos

### Hardware
- NIC Mellanox ConnectX-5 (o compatible con DPDK)
- Enlace 25G o 100G
- 2GB+ de hugepages

### Software
- DPDK (version compatible con mlx5)
- Python 3 + Scapy (para generadores)
- tcpreplay

## Instalacion

### 1. Compilar el Detector

```bash
cd /local/dpdk_100g/quic/detector_system
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev
make clean && make
```

### 2. Instalar Dependencias de Generadores

```bash
sudo apt-get install -y python3-pip tcpreplay
pip3 install scapy
```

### 3. Configurar Hugepages

```bash
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
```

## Uso Rapido

### Generar PCAPs

```bash
# En controller: Baseline (5M paquetes)
cd /local/dpdk_100g/quic/benign_generator
python3 generate_baseline_quic.py --output ../baseline_quic_5M.pcap --packets 5000000

# En tg: Ataque (1M paquetes)
cd /local/dpdk_100g/quic/attack_generator
python3 generate_optimistic_ack_attack.py --output ../attack_quic_1M.pcap --packets 1000000
```

### Ejecutar Experimento

```bash
# Terminal 1 (monitor): Detector
cd /local/dpdk_100g/quic/detector_system
sudo timeout 510 ./quic_optimistic_ack_detector -l 1-2 -n 4 -w 0000:41:00.0 -- -p 0

# Terminal 2 (controller): Baseline
cd /local/dpdk_100g/quic
for i in {1..25}; do
    sudo timeout 500 tcpreplay --intf1=ens1f0 --pps=50000 --loop=0 baseline_quic_5M.pcap &
done

# Terminal 3 (tg): Ataque (despues de 200s)
cd /local/dpdk_100g/quic
for i in {1..50}; do
    sudo timeout 300 tcpreplay --intf1=ens1f0 --pps=37500 --loop=0 attack_quic_1M.pcap &
done
```

### Analizar Resultados

```bash
cd /local/dpdk_100g/quic/analysis
python3 analyze_quic_results.py
```

## Configuracion del Experimento

### Para enlace 25G

| Fase | Instancias | PPS/inst | Total PPS | Gbps |
|------|------------|----------|-----------|------|
| Baseline | 25 | 50,000 | 1.25M | ~7 |
| Attack | 50 | 37,500 | 1.875M | ~10.5 |
| **Total** | 75 | - | **3.125M** | **~17.5** |

### Timeline

```
0s      Start detector
5s      Start baseline (25 instances)
200s    Start attack (50 instances)
500s    Traffic stops
510s    Detector stops
```

## Resultados Esperados

### Metricas de Deteccion

- **Detection delay**: < 5 segundos
- **True positive rate**: > 90%
- **False positive rate**: < 5%

### Indicadores de Ataque

Durante la fase de ataque, el detector deberia mostrar:

- Alert level: **HIGH**
- Bytes ratio: > 10
- Heavy ACKers: > 10 IPs
- ACK rate: > 5000/s por IP de ataque

## Diferencias con HTTP Flood

| Aspecto | HTTP Flood | QUIC Optimistic ACK |
|---------|------------|---------------------|
| Protocolo | TCP/HTTP | UDP/QUIC |
| Puerto | 80 | 443 |
| Indicador principal | Request rate | ACK rate + Bytes ratio |
| Tipo de ataque | Volumetrico | Amplificacion |
| Parsing | HTTP headers | QUIC frames |

## Troubleshooting

### Detector no recibe QUIC

```bash
# Verificar trafico UDP/443
tcpdump -i ens1f0 'udp port 443' -c 10

# Verificar que el generador crea QUIC valido
tcpdump -r baseline_quic_5M.pcap -c 5
```

### Bytes ratio siempre es 0

El detector necesita ver trafico bidireccional. Asegurate de que:
- Los PCAPs incluyen respuestas del servidor
- O ajusta la logica para solo analizar direccion cliente->servidor

### Pocas detecciones

Ajusta los umbrales en el detector:
```c
#define ACK_RATE_THRESHOLD 3000      // Reducir de 5000
#define BYTES_RATIO_THRESHOLD 5.0    // Reducir de 10.0
```

## Referencias

- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
- [QUIC Optimistic ACK Attack Paper](https://dl.acm.org/doi/10.1145/3548606.3560591)
- [DPDK Documentation](https://doc.dpdk.org/)
- [OctoSketch Paper](https://dl.acm.org/doi/10.1145/3098822.3098831)

## Autor

QUIC Optimistic ACK Detector Project - TFM
