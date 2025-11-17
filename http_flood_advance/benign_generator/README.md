# Generador de Tráfico Baseline HTTP con Tcpreplay

Solución completa para generar y reproducir tráfico HTTP baseline realista usando archivos PCAP y tcpreplay. Diseñado para ataques HTTP flood en nodos con NICs de 100 Gbps.

## Descripción

Este sistema genera tráfico HTTP normal (baseline) desde el **Controlador al Monitor** para establecer patrones de tráfico normal antes de simular ataques HTTP flood. Utiliza:

1. **Python + Scapy**: Para generar archivos PCAP con tráfico HTTP realista
2. **Tcpreplay**: Para reproducir los PCAPs a altas velocidades (hasta 100 Gbps)

## Ventajas sobre DPDK

✅ **Más confiable**: No hay problemas de compatibilidad con NICs
✅ **Más simple**: No requiere compilación ni configuración compleja de DPDK
✅ **Reproducible**: Los PCAPs se pueden reutilizar y compartir
✅ **Realista**: Tráfico HTTP real sobre TCP (no UDP)
✅ **Flexible**: Fácil modificar patrones de tráfico editando el script Python
✅ **Alto rendimiento**: Tcpreplay puede alcanzar 40-100 Gbps con optimizaciones

## Instalación de Dependencias

### Scapy (para generar PCAPs)
```bash
pip install scapy
```

### Tcpreplay (para reproducir PCAPs)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tcpreplay

# CentOS/RHEL
sudo yum install tcpreplay

# Verificar instalación
tcpreplay --version
```

## Uso

### 1. Generar Archivo PCAP de Baseline

```bash
# Generar 100K paquetes (default) - ~15-20 MB
python generate_baseline_pcap.py

# Generar 1M paquetes - ~150-200 MB
python generate_baseline_pcap.py -n 1000000

# Generar 10M paquetes - ~1.5-2 GB
python generate_baseline_pcap.py -n 10000000

# Con IPs personalizadas (Controlador -> Monitor)
python generate_baseline_pcap.py \
    -s 192.168.1.0 \
    -d 10.0.0.1 \
    --dst-mac 04:3f:72:ac:cd:e7

# Archivo de salida personalizado
python generate_baseline_pcap.py -o my_baseline.pcap -n 500000 -v
```

**Parámetros:**
- `-n, --num-packets`: Número de paquetes a generar
- `-o, --output`: Archivo PCAP de salida
- `-s, --src-ip`: IP origen base (se randomiza en /16)
- `-d, --dst-ip`: IP destino (Monitor)
- `--src-mac`: MAC origen (Controlador)
- `--dst-mac`: MAC destino (Monitor)
- `-v, --verbose`: Mostrar progreso

### 2. Reproducir Tráfico con Tcpreplay

```bash
# Replay básico a 1 Gbps
sudo ./replay_baseline.sh -i eth0

# Replay a 10 Gbps
sudo ./replay_baseline.sh -i eth0 -r 10000

# Replay a 40 Gbps
sudo ./replay_baseline.sh -i eth0 -r 40000

# Replay a máxima velocidad (topspeed)
sudo ./replay_baseline.sh -i eth0 -t

# Replay con multiplicador (5x la velocidad original)
sudo ./replay_baseline.sh -i eth0 -m 5

# Replay en loop infinito a 100 Gbps
sudo ./replay_baseline.sh -i eth0 -r 100000

# Replay 10 veces con preload (mejor para archivos grandes)
sudo ./replay_baseline.sh -i eth0 -r 40000 -l 10 -p

# PCAP personalizado
sudo ./replay_baseline.sh -i eth0 -f my_baseline.pcap -r 50000
```

**Parámetros:**
- `-i <interface>`: Interfaz de red (obligatorio)
- `-f <pcap_file>`: Archivo PCAP a reproducir
- `-r <rate_mbps>`: Tasa en Mbps (1000 = 1 Gbps)
- `-m <multiplier>`: Multiplicador de velocidad
- `-t`: Modo topspeed (máxima velocidad)
- `-l <count>`: Número de loops (0 = infinito)
- `-p`: Preload PCAP en RAM
- `-q`: Modo quiet

## Tráfico Generado

### Distribución de Peticiones HTTP

El generador crea tráfico HTTP realista con la siguiente distribución:

| Categoría | Porcentaje | Descripción |
|-----------|-----------|-------------|
| **Homepage** | ~30% | GET /, /index.html, /home, /main |
| **API** | ~25% | GET/POST /api/v1/*, /api/v2/* |
| **Estáticos** | ~25% | CSS, JS, imágenes, fonts |
| **Dinámico** | ~15% | Búsquedas, productos, perfiles |
| **Realtime** | ~5% | WebSocket handshakes, polling |

### Características del Tráfico

- **Protocolo**: HTTP sobre TCP (no UDP)
- **User-Agents**: 5 navegadores realistas (Chrome, Firefox, Safari, etc.)
- **IPs origen**: Randomizadas dentro de /16 (ej: 192.168.X.X)
- **Puertos origen**: Aleatorios (1024-65535)
- **Headers HTTP**: Realistas con Accept, Accept-Language, etc.
- **Métodos**: GET (90%), POST (10%)
- **Hosts**: Variados (www.example.com, api.example.com, cdn.example.com, etc.)

### Ejemplos de Peticiones

```http
GET / HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Connection: keep-alive

GET /api/v1/users HTTP/1.1
Host: api.example.com
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15
Connection: keep-alive

POST /api/v1/auth HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 45
{"username":"user123","password":"pass456"}
```

## Rendimiento

### Generación de PCAPs

| Paquetes | Tiempo | Tamaño PCAP | Tasa |
|----------|--------|-------------|------|
| 100K | ~5-10s | ~15 MB | 10-20K pps |
| 1M | ~30-60s | ~150 MB | 15-30K pps |
| 10M | ~5-10min | ~1.5 GB | 15-30K pps |

*Tiempos en laptop moderna. CPU intensivo debido a construcción de paquetes*

### Replay con Tcpreplay

| Configuración | Tasa Alcanzable | CPU | Notas |
|---------------|-----------------|-----|-------|
| Default (1 Gbps) | 1 Gbps | 10-20% | Perfecto para testing |
| -r 10000 (10 Gbps) | 10 Gbps | 30-50% | Recomendado para baseline |
| -r 40000 (40 Gbps) | 35-40 Gbps | 70-90% | NIC 100G requerida |
| -r 100000 (100 Gbps) | 80-100 Gbps | 95-100% | NIC 100G + preload |
| --topspeed | Variable | 100% | Máximo que soporta NIC |

**Optimizaciones para alto rendimiento:**
- Usar `-p` (preload) para cargar PCAP en RAM
- Deshabilitar offloads: `ethtool -K <iface> gro off gso off tso off`
- Usar cores dedicados: `taskset -c 0-3 tcpreplay ...`
- Aumentar TX ring: `ethtool -G <iface> tx 4096`

## Workflow Típico

### Paso 1: Generar PCAP (una sola vez)
```bash
# Generar 5M paquetes de baseline (~750 MB)
python generate_baseline_pcap.py -n 5000000 -o baseline_5M.pcap -v
```

### Paso 2: Configurar interfaz
```bash
# Identificar interfaz
ip link show

# Verificar que está UP
sudo ip link set ens3f0 up

# Verificar link con ethtool
sudo ethtool ens3f0 | grep "Link detected"
```

### Paso 3: Replay de baseline
```bash
# Enviar tráfico baseline a 10 Gbps en loop infinito
sudo ./replay_baseline.sh -i ens3f0 -f baseline_5M.pcap -r 10000

# Monitorear en otra terminal
watch -n 1 'ethtool -S ens3f0 | grep tx_packets'
```

### Paso 4: Capturar con DPDK/OctoSketch en Monitor
```bash
# En el nodo Monitor, capturar con tu aplicación DPDK
# El tráfico baseline debería verse como HTTP normal
```

### Paso 5: Lanzar ataque HTTP flood
```bash
# Detener baseline (Ctrl+C en replay)
# Lanzar tu generador de ataque HTTP flood
# Comparar métricas baseline vs ataque en OctoSketch
```

## Verificación del Tráfico

### Con tcpdump (en Monitor)
```bash
# Capturar 10 paquetes HTTP
sudo tcpdump -i <interface> -nn tcp port 80 -c 10 -A

# Verificar IPs y contenido HTTP
sudo tcpdump -i <interface> -nn tcp port 80 -c 100 -v | grep "GET\|POST\|HTTP"
```

### Con tshark
```bash
# Analizar peticiones HTTP
sudo tshark -i <interface> -Y "tcp.port == 80" -T fields \
    -e ip.src -e tcp.srcport -e http.request.method -e http.request.uri \
    | head -20

# Estadísticas de tráfico
sudo tshark -i <interface> -qz io,stat,1
```

### Analizar PCAP generado
```bash
# Información general
capinfos baseline_traffic.pcap

# Primeros 10 paquetes
tcpdump -nn -r baseline_traffic.pcap -c 10 -A

# Distribución de IPs
tshark -r baseline_traffic.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -20
```

## Troubleshooting

### Error: "Cannot open device"
**Solución**: Ejecutar con sudo
```bash
sudo ./replay_baseline.sh -i eth0
```

### Error: "No such device"
**Problema**: Nombre de interfaz incorrecto
**Solución**: Listar interfaces disponibles
```bash
ip link show
# o
ifconfig -a
```

### Bajo rendimiento (<1 Gbps con -r 10000)
**Causas posibles:**
1. **CPU limitado**: Usar menos loops o menor burst
2. **Offloads activos**: Deshabilitar con ethtool
3. **PCAP muy grande**: Usar `-p` (preload)
4. **NIC limitada**: Verificar con `ethtool <iface>`

```bash
# Optimizar
sudo ethtool -K eth0 tso off gso off gro off
sudo ethtool -G eth0 tx 4096
sudo ./replay_baseline.sh -i eth0 -r 10000 -p
```

### Paquetes no llegan al Monitor
**Verificar:**
1. **Link físico**: `ethtool <iface> | grep Link`
2. **Routing**: Verificar que no hay routing entre Controlador-Monitor
3. **Firewall**: Deshabilitar temporalmente
4. **VLAN tags**: Si es necesario, agregar con `--enet-vlan`

```bash
# Verificar conectividad
ping <monitor_ip>

# Ver si los paquetes salen
sudo tcpdump -i eth0 -c 5 tcp port 80
```

### Scapy muy lento
**Optimización:**
```bash
# Generar menos paquetes primero
python generate_baseline_pcap.py -n 10000

# Luego escalar
python generate_baseline_pcap.py -n 1000000 -v
```

## Integración con Sistema de Ataque

### Secuencia Recomendada

```bash
# 1. Generar PCAP baseline (una vez)
python generate_baseline_pcap.py -n 5000000 -o baseline.pcap

# 2. Iniciar captura en Monitor (DPDK + OctoSketch)
# (en nodo Monitor)
sudo ./dpdk_monitor --capture baseline

# 3. Enviar tráfico baseline (5 minutos)
sudo timeout 300 ./replay_baseline.sh -i eth0 -f baseline.pcap -r 10000

# 4. Esperar estabilización
sleep 10

# 5. Lanzar ataque HTTP flood
# (tu generador de ataque)
sudo ./http_flood_attack --rate 1000000

# 6. Analizar diferencias en OctoSketch
# Comparar métricas baseline vs ataque
```

## Personalización

### Modificar Distribución de Peticiones

Editar `generate_baseline_pcap.py`, sección `HTTP_REQUESTS`:

```python
HTTP_REQUESTS = {
    'homepage': [
        {'method': 'GET', 'path': '/', 'host': 'mysite.com', 'weight': 20},
        # Más weight = más frecuente
    ],
    # Añadir categorías personalizadas
    'custom': [
        {'method': 'GET', 'path': '/custom', 'host': 'api.com', 'weight': 10},
    ]
}
```

### Añadir User-Agents Personalizados

```python
USER_AGENTS = [
    'Mi-User-Agent/1.0',
    'Custom-Bot/2.0',
    # ...
]
```

### Generar Tráfico HTTPS (TLS)

Scapy puede generar paquetes con TLS, pero es más complejo. Para simplificar:

```bash
# Generar tráfico en puerto 443
# Modificar en generate_baseline_pcap.py:
dst_port = 443  # En lugar de 80
```

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `generate_baseline_pcap.py` | Generador de PCAP con tráfico HTTP realista |
| `replay_baseline.sh` | Script para reproducir PCAP con tcpreplay |
| `README.md` | Esta documentación |
| `baseline_traffic.pcap` | PCAP generado (default, no incluido en repo) |

## Requisitos del Sistema

- **Python 3.6+** con Scapy
- **Tcpreplay 4.x+**
- **NIC 100G** (Mellanox ConnectX-5/6 recomendado)
- **RAM**: 4+ GB (8+ GB para PCAPs >1M paquetes)
- **CPU**: Multi-core recomendado para alto rendimiento
- **Hugepages**: No requerido (ventaja vs DPDK)

## Limitaciones

1. **Generación lenta**: Scapy es CPU-intensivo (~30K pps)
   - **Solución**: Generar PCAP una vez, reutilizar
2. **Sin respuestas**: El Monitor no responderá
   - **Esperado**: Es tráfico unidireccional de baseline
3. **No es TCP completo**: Sin handshake/ACKs
   - **OK para baseline**: El objetivo es simular volumen, no sesiones
4. **Tamaño de PCAP**: 10M paquetes = ~1.5 GB
   - **Solución**: Usar loops en tcpreplay en lugar de PCAPs enormes

## Licencia

GPL v2 (compatible con tcpreplay y DPDK)

## Soporte

Para problemas o preguntas:
1. Verificar este README
2. Revisar logs de tcpreplay (`-v` para verbose)
3. Verificar configuración de red con `ethtool` e `ip`
