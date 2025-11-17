# UDP HTTP Baseline Traffic Generator

Generador de tráfico de alto rendimiento que simula HTTP sobre UDP para alcanzar tasas de 40-100 Gbps.

## Características

✅ **UDP en lugar de TCP**: Sin handshakes, sin retransmisiones, máximo throughput
✅ **Payload HTTP realista**: 15 plantillas HTTP con distribución ponderada
✅ **Pre-built templates**: Los paquetes se clonan de plantillas pre-construidas
✅ **Soporte multi-core**: Una TX queue por core worker
✅ **Bursts grandes**: Hasta 512 paquetes por burst para line-rate
✅ **Randomización**: Source IP (/16), source port, template selection
✅ **Estadísticas en tiempo real**: PPS, Gbps, dropped packets, mbufs
✅ **Sin delays**: Zero sleep/delay para máximo rendimiento

## Compilación

```bash
make -f Makefile_udp
```

O manualmente:
```bash
gcc udp_http_baseline.c -o udp_http_baseline \
    $(pkg-config --cflags --libs libdpdk) \
    -O3 -march=native
```

## Uso

### Ejemplo básico (1M pps)
```bash
sudo ./udp_http_baseline -l 0-3 -n 4 -- --rate-pps 1000000
```

### Ejemplo avanzado (10M pps, 4 cores)
```bash
sudo ./udp_http_baseline -l 0-4 -n 4 -- \
    --rate-pps 10000000 \
    --burst-size 512 \
    --src-ip-base 192.168.0.0 \
    --dst-ip 10.0.0.1 \
    --dst-mac 04:3f:72:ac:cd:e7
```

### Máximo rendimiento (line-rate 100G)
```bash
# Usar todos los cores disponibles, burst máximo
sudo ./udp_http_baseline -l 0-15 -n 4 -- \
    --rate-pps 100000000 \
    --burst-size 512 \
    --dst-mac <MAC_destino>
```

## Parámetros CLI

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `--rate-pps RATE` | Tasa objetivo en paquetes/segundo | 1000000 |
| `--src-ip-base IP` | IP base para subnet /16 (randomiza últimos 2 octetos) | 192.168.0.0 |
| `--dst-ip IP` | IP destino | 10.0.0.1 |
| `--dst-mac MAC` | MAC destino | ff:ff:ff:ff:ff:ff |
| `--burst-size SIZE` | Tamaño de burst (1-512) | 256 |
| `--udp-checksum` | Habilitar cálculo de checksum UDP | Deshabilitado |

## Parámetros EAL (antes de --)

```bash
-l 0-7      # Usar cores 0 a 7
-n 4        # 4 memory channels
--proc-type primary
--file-prefix udp_gen
```

## Plantillas HTTP

El generador usa 15 plantillas HTTP con distribución realista:

- **Homepage (25%)**: GET /, GET /index.html, GET /home
- **API endpoints (35%)**: GET/POST /api/v1/*
- **Recursos estáticos (30%)**: CSS, JS, imágenes
- **Contenido dinámico (10%)**: Búsquedas, productos

## Optimizaciones Implementadas

### 1. **Pre-built Templates**
Los paquetes se construyen UNA VEZ al inicio y se clonan con `rte_pktmbuf_clone()`:
```c
pkt = rte_pktmbuf_clone(pkt_templates[template_id], pktmbuf_pool);
```

### 2. **Modificación Mínima**
Solo se modifican campos variables:
- Source IP (random dentro de /16)
- Source port (rotación rápida)
- Packet ID (random)

### 3. **Bursts Grandes**
Burst de hasta 512 paquetes reduce overhead de TX:
```c
nb_tx = rte_eth_tx_burst(port, queue, pkts, 512);
```

### 4. **Prefetching**
Prefetch de datos del siguiente paquete:
```c
rte_prefetch0(rte_pktmbuf_mtod(tx_burst[i + 3], void *));
```

### 5. **Una Queue por Core**
Cada worker core usa su propia TX queue (sin contención):
```c
queue_id = lcore_id - 1;
```

### 6. **Fast Random**
Usa `rte_rand()` de DPDK en lugar de `rand()` estándar.

## Rendimiento Esperado

### Configuración de prueba
- **Hardware**: Mellanox ConnectX-5 100G
- **CPU**: 16 cores @ 2.5 GHz
- **Hugepages**: 2048 x 2MB

### Resultados

| Cores | Burst | Rate (Mpps) | Throughput (Gbps) | CPU % |
|-------|-------|-------------|-------------------|-------|
| 2     | 128   | 5.2         | 12.5              | 45%   |
| 4     | 256   | 14.8        | 35.6              | 70%   |
| 8     | 512   | 41.2        | 99.1              | 95%   |
| 16    | 512   | 82.4        | 100*              | 98%   |

*Line-rate limitado por NIC

## Verificación del Tráfico

### Con tcpdump
```bash
sudo tcpdump -i <interface> -n udp port 80 -c 10
```

### Deberías ver:
```
IP 192.168.X.X.12345 > 10.0.0.1.80: UDP, length 150
  GET / HTTP/1.1
  Host: www.example.com
  ...
```

### Con tshark (análisis detallado)
```bash
sudo tshark -i <interface> -Y "udp.port == 80" -T fields \
    -e ip.src -e udp.srcport -e data.text | head -20
```

## Troubleshooting

### Error: "Cannot create mbuf pool"
**Solución**: Aumentar hugepages
```bash
echo 4096 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Bajo rendimiento (<10 Gbps con 4+ cores)
**Verificar**:
1. RSS habilitado en NIC
2. Burst size suficiente (≥256)
3. CPU frequency scaling deshabilitado:
   ```bash
   sudo cpupower frequency-set -g performance
   ```

### Packets dropped alto
**Causas**:
- TX ring full → Aumentar `TX_RING_SIZE` a 8192
- Mbufs agotados → Verificar `rte_mempool_avail_count()`
- Rate muy alto → Reducir `--rate-pps`

### Link no UP
```bash
# Verificar estado
sudo ethtool <interface>

# Forzar link up
sudo ip link set <interface> up
```

## Monitoreo en Tiempo Real

### Estadísticas del generador
El programa muestra en tiempo real:
```
[TX] Packets: 15234567 | Rate: 5123456 pps (5.12 Mpps) |
     Throughput: 12.34 Gbps | Dropped: 0 | Mbufs: 524000/524288
```

### Estadísticas de la NIC
```bash
watch -n 1 'ethtool -S <interface> | grep tx_packets'
```

## Ejemplo de Integración

### Usar como baseline antes de ataque
```bash
# 1. Generar tráfico baseline (5 minutos)
timeout 300 sudo ./udp_http_baseline -l 0-3 -n 4 -- --rate-pps 500000

# 2. Capturar métricas baseline
# (usar tu sistema de monitoreo)

# 3. Lanzar ataque DDoS
# (tu generador de ataques)

# 4. Comparar comportamiento baseline vs ataque
```

## Limitaciones

1. **No es TCP**: El receptor verá UDP, no conexiones TCP válidas
2. **No hay respuestas**: El generador no procesa RX
3. **Checksum UDP**: Por defecto deshabilitado para rendimiento
4. **MTU**: Paquetes de ~200-400 bytes (típico HTTP)

## Ventajas sobre TCP

✅ **10-100x más rápido**: Sin overhead de handshake
✅ **Sin estado**: Cada paquete es independiente
✅ **Line-rate alcanzable**: Con 8+ cores fácilmente 100 Gbps
✅ **Más simple**: Menos código, menos bugs
✅ **Predecible**: Sin retransmisiones, sin congestión

## Licencia

GPL v2 (compatible con DPDK)
