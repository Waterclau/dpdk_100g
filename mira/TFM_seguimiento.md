# TFM - Seguimiento del Sistema de Detección DDoS MIRA

## Tabla de Contenidos

### Parte I: Infraestructura
1. [Introducción](#1-introducción)
2. [Arquitectura de Nodos (Testbed)](#2-arquitectura-de-nodos-testbed)

### Parte II: Detector sin ML
3. [Arquitectura General del Detector sin ML](#3-arquitectura-general-del-detector-sin-ml)
4. [DPDK - Data Plane Development Kit](#4-dpdk---data-plane-development-kit)
5. [OctoSketch - Estructura de Datos Probabilística](#5-octosketch---estructura-de-datos-probabilística)
6. [Flujo de Procesamiento de Paquetes](#6-flujo-de-procesamiento-de-paquetes)
7. [Sistema de Detección de Ataques](#7-sistema-de-detección-de-ataques)
8. [Optimizaciones de Rendimiento](#8-optimizaciones-de-rendimiento)
9. [Métricas y Resultados](#9-métricas-y-resultados)

### Parte III: Sistema ML
10. [Entrenamiento del Modelo ML](#10-entrenamiento-del-modelo-ml)

---

## 1. Introducción

El detector MIRA (Multi-attack In-line Real-time Analyzer) es un sistema de detección de ataques DDoS diseñado para operar a velocidad de línea (line-rate) en redes de alta velocidad (10-100 Gbps). El sistema utiliza DPDK para el procesamiento de paquetes y OctoSketch como estructura de datos probabilística para el conteo eficiente de flujos.

### Archivo Principal
- **Ubicación:** `mira/detector_system/mira_ddos_detector.c`
- **Líneas de código:** ~1,900 líneas
- **Dependencias:** DPDK, OctoSketch (header-only)

### Ataques Detectados (13 tipos)
1. UDP Flood
2. UDP-Lag (paquetes UDP grandes)
3. SYN Flood
4. HTTP Flood
5. ICMP Flood
6. DNS Amplification
7. NTP Amplification
8. SNMP Amplification
9. SSDP
10. PortMap/RPC
11. NetBIOS
12. LDAP
13. MSSQL
14. TFTP
15. ACK Flood
16. Fragmentation Attack

---

## 2. Arquitectura de Nodos (Testbed)

El sistema MIRA se despliega en un entorno de pruebas (testbed) en CloudLab con 4 nodos físicos interconectados mediante una red de alta velocidad (100 Gbps).

### 2.1 Diagrama de la Arquitectura de Red

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        TESTBED CLOUDLAB - ARQUITECTURA MIRA                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌───────────────┐                                    ┌───────────────┐        │
│   │   CONTROLLER  │                                    │      TG       │        │
│   │  (node-ctrl)  │                                    │ (node-tg)     │        │
│   ├───────────────┤                                    ├───────────────┤        │
│   │ IP: 10.10.2.x │                                    │ IP: 10.10.3.x │        │
│   │               │                                    │               │        │
│   │ • Genera      │                                    │ • Genera      │        │
│   │   tráfico     │                                    │   tráfico     │        │
│   │   BENIGNO     │                                    │   de ATAQUE   │        │
│   │               │                                    │               │        │
│   │ • Simula      │                                    │ • 13+ tipos   │        │
│   │   usuarios    │                                    │   de DDoS     │        │
│   │   legítimos   │                                    │               │        │
│   └───────┬───────┘                                    └───────┬───────┘        │
│           │                                                    │                │
│           │ Tráfico Benigno                   Tráfico Ataque   │                │
│           │ (10.10.2.0/24)                    (10.10.3.0/24)   │                │
│           │                                                    │                │
│           └──────────────────┐    ┌────────────────────────────┘                │
│                              │    │                                             │
│                              ▼    ▼                                             │
│                     ┌─────────────────────┐                                     │
│                     │      SWITCH         │                                     │
│                     │   (100 Gbps)        │                                     │
│                     └─────────┬───────────┘                                     │
│                               │                                                 │
│               ┌───────────────┴───────────────┐                                 │
│               │                               │                                 │
│               ▼                               ▼                                 │
│   ┌───────────────────┐           ┌───────────────────┐                         │
│   │     MONITOR       │           │      VICTIM       │                         │
│   │  (node-monitor)   │           │   (node-victim)   │                         │
│   ├───────────────────┤           ├───────────────────┤                         │
│   │ IP: 10.10.1.1     │           │ IP: 10.10.1.2     │                         │
│   │                   │           │                   │                         │
│   │ • Ejecuta DPDK    │           │ • Servidor        │                         │
│   │   detector        │           │   objetivo        │                         │
│   │                   │           │                   │                         │
│   │ • Procesa TODO    │           │ • Recibe tráfico  │                         │
│   │   el tráfico      │           │   benigno +       │                         │
│   │   (inline)        │           │   ataques         │                         │
│   │                   │           │                   │                         │
│   │ • Genera          │           │ • Servicios:      │                         │
│   │   estadísticas    │           │   HTTP, DNS, etc. │                         │
│   │   y alertas       │           │                   │                         │
│   └───────────────────┘           └───────────────────┘                         │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Descripción de Cada Nodo

#### **TG (Traffic Generator) - node-tg**

| Característica | Valor |
|----------------|-------|
| **Función** | Generador de tráfico de ATAQUE |
| **Red de origen** | 10.10.3.0/24 |
| **Herramientas** | Scripts personalizados, hping3, T50, etc. |

**Tipos de ataque generados:**
- UDP Flood, SYN Flood, ICMP Flood
- HTTP Flood (WebDDoS)
- DNS/NTP/SNMP Amplification
- SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP

**Ejemplo de ejecución de ataque:**
```bash
# Desde node-tg
./attack_scripts/udp_flood.sh --target 10.10.1.2 --rate 100000 --duration 60
./attack_scripts/syn_flood.sh --target 10.10.1.2 --port 80 --rate 50000
```

#### **Controller - node-ctrl**

| Característica | Valor |
|----------------|-------|
| **Función** | Generador de tráfico BENIGNO |
| **Red de origen** | 10.10.2.0/24 |
| **Herramientas** | curl, wrk, iperf3, scripts personalizados |

**Tráfico benigno simulado:**
- Peticiones HTTP/HTTPS normales
- Consultas DNS legítimas
- Tráfico de navegación web
- Transferencias de archivos

**Ejemplo de generación de tráfico benigno:**
```bash
# Desde node-ctrl
./benign_traffic/http_requests.sh --target 10.10.1.2 --rate 1000 --duration 300
./benign_traffic/mixed_traffic.sh --target 10.10.1.2
```

#### **Monitor - node-monitor**

| Característica | Valor |
|----------------|-------|
| **Función** | Ejecuta el detector MIRA (DPDK) |
| **IP** | 10.10.1.1 |
| **Modo** | Inline (procesa todo el tráfico) |
| **Cores** | 16 cores (14 workers + 1 coordinator + 1 gestión) |

**Componentes ejecutados:**
- `mira_ddos_detector` (detector sin ML)
- `detectorML` (detector con ML)
- Scripts de captura de logs y métricas

**Comando de ejecución:**
```bash
# Detector sin ML
sudo ./mira_ddos_detector -l 0-15 -n 4 -- -p 0x1

# Detector con ML
sudo ./detectorML -l 0-15 -n 4 -- -p 0x1
```

#### **Victim - node-victim**

| Característica | Valor |
|----------------|-------|
| **Función** | Servidor objetivo de los ataques |
| **IP** | 10.10.1.2 |
| **Servicios** | HTTP (80), HTTPS (443), DNS (53), etc. |

**Servicios expuestos:**
- Servidor web (nginx/apache)
- Servidor DNS
- Otros servicios para pruebas de amplificación

### 2.3 Flujo de Tráfico

```
┌─────────────────────────────────────────────────────────────────────┐
│                       FLUJO DE TRÁFICO                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   CONTROLLER (10.10.2.x)          TG (10.10.3.x)                   │
│        │                               │                            │
│        │ Tráfico Benigno               │ Tráfico de Ataque          │
│        │ (HTTP, DNS normal)            │ (UDP Flood, SYN Flood...)  │
│        │                               │                            │
│        └───────────────┬───────────────┘                            │
│                        │                                            │
│                        ▼                                            │
│              ┌─────────────────┐                                    │
│              │    MONITOR      │                                    │
│              │ (Detector MIRA) │                                    │
│              ├─────────────────┤                                    │
│              │                 │                                    │
│              │ 1. Recibe TODOS │                                    │
│              │    los paquetes │                                    │
│              │                 │                                    │
│              │ 2. Clasifica:   │                                    │
│              │    10.10.2.x →  │──→ Baseline (benigno)              │
│              │    10.10.3.x →  │──→ Attack                          │
│              │                 │                                    │
│              │ 3. Detecta      │                                    │
│              │    ataques por  │                                    │
│              │    thresholds   │                                    │
│              │    o ML         │                                    │
│              │                 │                                    │
│              │ 4. Genera       │──→ Alertas + Estadísticas          │
│              │    alertas      │                                    │
│              └────────┬────────┘                                    │
│                       │                                             │
│                       ▼                                             │
│              ┌─────────────────┐                                    │
│              │     VICTIM      │                                    │
│              │   (Servidor)    │                                    │
│              └─────────────────┘                                    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.4 Direcciones IP y Clasificación

El detector clasifica el tráfico basándose en la IP de origen:

```c
// mira_ddos_detector.c:87-91
#define BASELINE_NETWORK 0x0A0A0200     // 10.10.2.x - tráfico benigno
#define ATTACK_NETWORK   0x0A0A0300     // 10.10.3.x - tráfico de ataque
#define NETWORK_MASK     0xFFFFFF00
#define SERVER_IP        0x0A0A0102     // 10.10.1.2 - servidor víctima
```

| Red | Rango IP | Clasificación | Origen |
|-----|----------|---------------|--------|
| Baseline | 10.10.2.0/24 | Benigno | Controller |
| Attack | 10.10.3.0/24 | Ataque | TG |
| Server | 10.10.1.0/24 | Infraestructura | Monitor + Victim |

### 2.5 Escenarios de Prueba

#### Escenario 1: Solo Tráfico Benigno
```bash
# Solo controller genera tráfico
Controller → Monitor → Victim
(10.10.2.x)   (analiza)  (recibe)
```

#### Escenario 2: Solo Ataque
```bash
# Solo TG genera tráfico
TG → Monitor → Victim
(10.10.3.x)   (detecta)  (recibe)
```

#### Escenario 3: Tráfico Mixto (Escenario Real)
```bash
# Ambos generan tráfico simultáneamente
Controller + TG → Monitor → Victim
(benigno + ataque)  (discrimina)  (recibe)
```

---

## 3. Arquitectura General del Detector sin ML

> **Archivo principal:** `mira/detector_system/mira_ddos_detector.c`

### 3.1 Modelo de Hilos (Multi-Core)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ARQUITECTURA MULTI-CORE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐       ┌─────────┐                │
│   │Worker 0 │ │Worker 1 │ │Worker 2 │  ...  │Worker 13│                │
│   │(lcore 1)│ │(lcore 2)│ │(lcore 3)│       │(lcore 14)│               │
│   ├─────────┤ ├─────────┤ ├─────────┤       ├─────────┤                │
│   │ Queue 0 │ │ Queue 1 │ │ Queue 2 │       │Queue 13 │  ← RSS         │
│   │Sketch 0 │ │Sketch 1 │ │Sketch 2 │       │Sketch 13│  ← Por worker  │
│   │ Stats 0 │ │ Stats 1 │ │ Stats 2 │       │Stats 13 │  ← Locales     │
│   └────┬────┘ └────┬────┘ └────┬────┘       └────┬────┘                │
│        │           │           │                 │                      │
│        └───────────┴───────────┴────────┬────────┘                      │
│                                         │                               │
│                                         ▼                               │
│                              ┌──────────────────┐                       │
│                              │   Coordinator    │                       │
│                              │   (lcore 15)     │                       │
│                              ├──────────────────┤                       │
│                              │ • Agrega stats   │                       │
│                              │ • Merge sketches │                       │
│                              │ • detect_attacks │                       │
│                              │ • print_stats    │                       │
│                              └──────────────────┘                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Configuración de Hilos

```c
// mira_ddos_detector.c:51
#define NUM_RX_QUEUES 14         // 14 workers para 17+ Gbps

// Distribución de lcores:
// - lcores 1-14: Worker threads (procesamiento de paquetes)
// - lcore 15: Coordinator thread (detección y estadísticas)
```

### 3.3 Principio de Diseño: Lock-Free

El sistema evita el uso de locks mediante:
1. **Estadísticas por worker:** Cada worker tiene sus propios contadores locales
2. **Sketches por worker:** Cada worker tiene su propia instancia de OctoSketch
3. **Agregación periódica:** El coordinator lee las estadísticas sin locks (eventual consistency)

---

## 4. DPDK - Data Plane Development Kit

### 4.1 ¿Qué es DPDK?

DPDK es un conjunto de bibliotecas y drivers que permite el procesamiento de paquetes de red en espacio de usuario, bypaseando el kernel de Linux. Esto permite alcanzar tasas de procesamiento de millones de paquetes por segundo.

### 4.2 Conceptos Clave de DPDK Utilizados

#### 4.2.1 EAL (Environment Abstraction Layer)

```c
// mira_ddos_detector.c:1849
int ret = rte_eal_init(argc, argv);
```

El EAL inicializa:
- Reserva de memoria hugepages
- Detección de CPUs y NUMA
- Inicialización de drivers de red

#### 4.2.2 Memory Pool (mbuf_pool)

```c
// mira_ddos_detector.c:46-49
#define NUM_MBUFS 524288         // 524K buffers de paquetes
#define MBUF_CACHE_SIZE 512      // Cache local por core

// mira_ddos_detector.c:1866-1867
mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
    MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
```

El memory pool pre-aloca buffers para paquetes, evitando malloc/free en el fast-path.

#### 4.2.3 RSS (Receive Side Scaling)

```c
// mira_ddos_detector.c:1776-1787
struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,  // Habilita RSS
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,  // Usa clave por defecto
            .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,  // Hash por IP + puertos
        },
    },
};
```

RSS distribuye los paquetes entrantes entre las 14 colas RX basándose en un hash de la 5-tupla (IP src, IP dst, port src, port dst, protocolo). Esto garantiza que los paquetes del mismo flujo siempre van al mismo worker.

#### 4.2.4 Recepción de Paquetes en Ráfagas (Burst)

```c
// mira_ddos_detector.c:50
#define BURST_SIZE 2048          // Paquetes por ráfaga

// mira_ddos_detector.c:1411-1412
struct rte_mbuf *bufs[BURST_SIZE];
uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);
```

`rte_eth_rx_burst()` lee hasta 2048 paquetes de una vez, amortizando el costo de acceso a la NIC.

#### 4.2.5 Prefetching

```c
// mira_ddos_detector.c:1420-1431
// Prefetch primeros 16 paquetes
for (uint16_t i = 0; i < nb_rx && i < 16; i++) {
    rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
}

// En el loop principal, prefetch 16 paquetes adelante
if (i + 16 < nb_rx) {
    rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 16], void *));
}
```

El prefetching carga los datos del paquete en cache L1 antes de que sean necesarios, ocultando la latencia de memoria.

#### 4.2.6 Configuración de Colas RX/TX

```c
// mira_ddos_detector.c:46-47
#define RX_RING_SIZE 32768       // Descriptores RX por cola
#define TX_RING_SIZE 4096        // Descriptores TX

// mira_ddos_detector.c:1814-1818
for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool);
}
```

Cada cola RX tiene 32K descriptores, permitiendo absorber ráfagas de tráfico sin pérdida.

---

## 5. OctoSketch - Estructura de Datos Probabilística

### 5.1 ¿Qué es un Sketch?

Un sketch es una estructura de datos probabilística que permite contar frecuencias de elementos (en este caso, IPs) usando memoria constante O(1), a cambio de una pequeña probabilidad de error.

### 5.2 Implementación de OctoSketch

**Archivo:** `mira/detector_system/octosketch.h`

OctoSketch está basado en "Elastic Sketch" (SIGCOMM 2018) y utiliza la técnica Count-Min Sketch.

#### 5.2.1 Estructura de Datos

```c
// octosketch.h:19-22
#define SKETCH_ROWS 8          // Número de funciones hash
#define SKETCH_COLS 4096       // Buckets por fila (debe ser potencia de 2)
#define SKETCH_MASK (SKETCH_COLS - 1)
#define SKETCH_TOP_K 10        // Rastrear top-10 heavy hitters

// octosketch.h:45-62
struct octosketch {
    // Matriz de contadores: 8 filas × 4096 columnas = 32,768 contadores
    uint32_t counters[SKETCH_ROWS][SKETCH_COLS];  // 128 KB

    // Semillas hash diferentes por fila
    uint32_t seeds[SKETCH_ROWS];

    // Estadísticas locales
    uint64_t total_updates;
    uint64_t total_bytes;

    // Tabla hash para Top-K heavy hitters
    uint32_t ip_counts[65536];  // 256 KB

    // Metadata
    char name[32];
    uint64_t window_start_tsc;
} __rte_cache_aligned;
```

#### 5.2.2 Visualización de la Estructura

```
                    4096 columnas (SKETCH_COLS)
              ┌────────────────────────────────────┐
    Fila 0    │ [0] [1] [2] [3] ... [4094] [4095] │  seed: 0xdeadbeef
              ├────────────────────────────────────┤
    Fila 1    │ [0] [1] [2] [3] ... [4094] [4095] │  seed: 0xc0ffee00
              ├────────────────────────────────────┤
    Fila 2    │ [0] [1] [2] [3] ... [4094] [4095] │  seed: 0xbaadf00d
              ├────────────────────────────────────┤
    ...       │            ...                     │
              ├────────────────────────────────────┤
    Fila 7    │ [0] [1] [2] [3] ... [4094] [4095] │  seed: 0x11223344
              └────────────────────────────────────┘

    Total: 8 × 4096 × 4 bytes = 128 KB por sketch
```

#### 5.2.3 Operación UPDATE (Insertar/Incrementar)

Cuando llega un paquete con IP `src_ip`, se actualiza el sketch:

```c
// octosketch.h:88-103
static inline void octosketch_update_ip(struct octosketch *sketch,
                                        uint32_t ip, uint32_t increment)
{
    // Actualizar TODAS las 8 filas con diferentes funciones hash
    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        sketch->counters[i][col] += increment;
    }

    // Actualizar contador específico de IP para heavy hitters
    uint32_t ip_idx = (ip >> 16) ^ (ip & 0xFFFF);  // Hash simple
    ip_idx = ip_idx % 65536;
    sketch->ip_counts[ip_idx] += increment;

    sketch->total_updates += increment;
}
```

**Ejemplo visual de UPDATE para IP 10.10.3.45:**

```
IP: 10.10.3.45 (0x0A0A032D)

Fila 0: hash(IP, 0xdeadbeef) = 1234  →  counters[0][1234] += 32
Fila 1: hash(IP, 0xc0ffee00) = 567   →  counters[1][567]  += 32
Fila 2: hash(IP, 0xbaadf00d) = 3891  →  counters[2][3891] += 32
Fila 3: hash(IP, 0xfeedface) = 2045  →  counters[3][2045] += 32
Fila 4: hash(IP, 0xcafebabe) = 890   →  counters[4][890]  += 32
Fila 5: hash(IP, 0x12345678) = 3456  →  counters[5][3456] += 32
Fila 6: hash(IP, 0x9abcdef0) = 123   →  counters[6][123]  += 32
Fila 7: hash(IP, 0x11223344) = 2789  →  counters[7][2789] += 32
```

#### 5.2.4 Operación QUERY (Consultar frecuencia)

Para estimar cuántas veces se ha visto una IP:

```c
// octosketch.h:112-125
static inline uint32_t octosketch_query_ip(struct octosketch *sketch, uint32_t ip)
{
    uint32_t min_count = UINT32_MAX;

    // Buscar el MÍNIMO entre las 8 filas
    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        uint32_t count = sketch->counters[i][col];
        if (count < min_count) {
            min_count = count;
        }
    }

    return min_count;  // Estimación conservadora
}
```

**¿Por qué tomar el MÍNIMO?**

El problema de los sketches es que diferentes IPs pueden colisionar en el mismo bucket. Al tomar el mínimo de las 8 filas, se reduce la probabilidad de sobreestimación porque es muy improbable que dos IPs colisionen en las 8 filas simultáneamente.

```
Ejemplo de colisión:

IP_A: 10.10.3.45  →  Fila 0, col 1234: count = 100
IP_B: 10.10.3.99  →  Fila 0, col 1234: count = 100 (¡colisión!)

Pero en Fila 1:
IP_A: →  col 567:  count = 50  (solo IP_A)
IP_B: →  col 2341: count = 50  (solo IP_B)

Query(IP_A) = min(100, 50, ...) = 50 ✓ (estimación correcta)
```

#### 5.2.5 Operación MERGE (Fusionar sketches de workers)

El coordinator combina los sketches de todos los workers:

```c
// octosketch.h:140-165
static inline void octosketch_merge(struct octosketch *dst,
                                    struct octosketch *src[],
                                    int num_sketches)
{
    // Limpiar destino
    memset(dst->counters, 0, sizeof(dst->counters));
    memset(dst->ip_counts, 0, sizeof(dst->ip_counts));

    // Sumar contadores de todos los sketches fuente
    for (int s = 0; s < num_sketches; s++) {
        for (int i = 0; i < SKETCH_ROWS; i++) {
            for (int j = 0; j < SKETCH_COLS; j++) {
                dst->counters[i][j] += src[s]->counters[i][j];
            }
        }

        // Fusionar contadores de IP
        for (int i = 0; i < 65536; i++) {
            dst->ip_counts[i] += src[s]->ip_counts[i];
        }

        dst->total_updates += src[s]->total_updates;
        dst->total_bytes += src[s]->total_bytes;
    }
}
```

#### 5.2.6 Sampling (Muestreo)

Para reducir el overhead, solo se actualiza el sketch cada N paquetes:

```c
// mira_ddos_detector.c:343
#define SKETCH_SAMPLE_RATE 32  // Actualizar sketch cada 32 paquetes (1 en 32)

// mira_ddos_detector.c:1617-1625
if (unlikely(is_attack)) {
    sample_counter++;
    if (sample_counter % SKETCH_SAMPLE_RATE == 0) {
        // Actualizar sketch multiplicando por el factor de muestreo
        octosketch_update_ip(my_sketch, src_ip, SKETCH_SAMPLE_RATE);
        octosketch_update_bytes(my_sketch, pkt_len * SKETCH_SAMPLE_RATE);
    }
}
```

**Beneficios del sampling:**
- Reduce el overhead de actualización al 3.125% (1/32)
- El factor de muestreo se compensa multiplicando el incremento

---

## 6. Flujo de Procesamiento de Paquetes

### 6.1 Worker Thread (Fast Path)

```c
// mira_ddos_detector.c:1374-1741
static int worker_thread(void *arg)
{
    uint16_t queue_id = *(uint16_t *)arg;
    struct octosketch *my_sketch = &g_worker_sketch_attack[queue_id];
    uint64_t sample_counter = 0;

    while (!force_quit) {
        // 1. Recibir ráfaga de paquetes
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0)) continue;

        // 2. Prefetch para mejor rendimiento
        for (uint16_t i = 0; i < nb_rx && i < 16; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
        }

        // 3. Procesar cada paquete
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];

            // 4. Parsear cabeceras
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);

            // 5. Clasificar tráfico por red de origen
            uint32_t network = src_ip & NETWORK_MASK;
            bool is_baseline = (network == BASELINE_NETWORK);  // 10.10.2.x
            bool is_attack = (network == ATTACK_NETWORK);      // 10.10.3.x

            // 6. Incrementar contadores locales (sin locks)
            local_baseline_pkts += is_baseline ? 1 : 0;
            local_attack_pkts += is_attack ? 1 : 0;

            // 7. Parsear protocolo de transporte
            if (proto == IPPROTO_TCP) {
                // Detectar SYN, HTTP, etc.
            } else if (proto == IPPROTO_UDP) {
                // Detectar DNS, NTP, SNMP, etc.
            } else if (proto == IPPROTO_ICMP) {
                local_icmp_pkts++;
            }

            // 8. Actualizar OctoSketch (solo tráfico de ataque + sampling)
            if (unlikely(is_attack)) {
                sample_counter++;
                if (sample_counter % SKETCH_SAMPLE_RATE == 0) {
                    octosketch_update_ip(my_sketch, src_ip, SKETCH_SAMPLE_RATE);
                }
            }

            // 9. Liberar buffer
            rte_pktmbuf_free(m);
        }

        // 10. Actualizar estadísticas del worker
        g_worker_stats[queue_id].total_packets += local_total_pkts;
        // ... más estadísticas ...
    }
}
```

### 6.2 Diagrama de Flujo del Worker

```
┌─────────────────────────────────────────────────────────────────┐
│                     WORKER THREAD (Fast Path)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │ rte_eth_rx_burst│
                    │ (hasta 2048 pkts)│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
         ┌────────┐    ┌────────┐    ┌────────┐
         │ Pkt 0  │    │ Pkt 1  │    │ Pkt N  │
         └───┬────┘    └───┬────┘    └───┬────┘
             │             │             │
             ▼             ▼             ▼
    ┌─────────────────────────────────────────────┐
    │           Parsear Ethernet + IPv4           │
    │         Extraer: src_ip, protocol           │
    └─────────────────────┬───────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │         Clasificar por Red de Origen        │
    │  10.10.2.x → Baseline   10.10.3.x → Attack  │
    └─────────────────────┬───────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │          Parsear Protocolo L4               │
    │  TCP: SYN, HTTP, LDAP, MSSQL                │
    │  UDP: DNS, NTP, SNMP, SSDP, etc.            │
    │  ICMP: contador simple                      │
    └─────────────────────┬───────────────────────┘
                          │
                          ▼
    ┌─────────────────────────────────────────────┐
    │   ¿Es tráfico de ataque? (10.10.3.x)        │
    └─────────────────────┬───────────────────────┘
                          │
              ┌───────────┴───────────┐
              │ SÍ                    │ NO
              ▼                       ▼
    ┌─────────────────┐     ┌─────────────────┐
    │ sample_counter++│     │ (solo contar)   │
    │ if % 32 == 0:   │     └─────────────────┘
    │   update_sketch │
    └─────────────────┘
              │
              ▼
    ┌─────────────────────────────────────────────┐
    │         Actualizar Contadores Locales       │
    │    (Sin locks - escritura solo en mi slot)  │
    └─────────────────────────────────────────────┘
```

### 6.3 Coordinator Thread (Slow Path)

```c
// mira_ddos_detector.c:1744-1771
static int coordinator_thread(__rte_unused void *arg)
{
    uint64_t hz = rte_get_tsc_hz();  // Frecuencia del TSC (Time Stamp Counter)

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        // Cada 50ms: ejecutar detección de ataques
        detect_attacks(cur_tsc, hz);

        // Cada 5s: imprimir estadísticas
        print_stats(port, cur_tsc, hz);

        rte_delay_us_block(10000);  // Sleep 10ms
    }
}
```

---

## 7. Sistema de Detección de Ataques

### 7.1 Función detect_attacks()

```c
// mira_ddos_detector.c:478-883
static void detect_attacks(uint64_t cur_tsc, uint64_t hz)
{
    // Ejecutar cada 50ms (FAST_DETECTION_INTERVAL)
    if (elapsed >= FAST_DETECTION_INTERVAL) {

        // 1. Agregar estadísticas de todos los workers
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_base_pkts += window_baseline_pkts[i];
            window_att_pkts += window_attack_pkts[i];
            window_syn_pkts += g_worker_stats[i].syn_packets;
            window_udp_pkts += g_worker_stats[i].udp_packets;
            // ... más contadores ...
        }

        // 2. Calcular tasas (paquetes por segundo)
        double attack_pps = (double)window_att_pkts / window_sec;
        double syn_pps = (double)window_syn_pkts / window_sec;
        double udp_pps = (double)window_udp_pkts / window_sec;
        // ... más tasas ...

        // 3. Aplicar thresholds de detección
        if (window_att_pkts > 0 && attack_pps > 50000) {

            if (udp_pps > 20000) {
                // UDP Flood detectado
            }
            if (syn_pps > 30000) {
                // SYN Flood detectado
            }
            // ... más detecciones ...
        }

        // 4. Fusionar sketches para análisis
        if (window_att_pkts > 0) {
            struct octosketch *worker_sketches[NUM_RX_QUEUES];
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                worker_sketches[i] = &g_worker_sketch_attack[i];
            }
            octosketch_merge(&g_merged_sketch_attack, worker_sketches, NUM_RX_QUEUES);
        }
    }
}
```

### 7.2 Thresholds de Detección

```c
// mira_ddos_detector.c:53-78

// Thresholds principales (paquetes por segundo)
#define ATTACK_TOTAL_PPS_THRESHOLD 50000   // Mínimo para considerar ataque

// Por tipo de ataque:
| Ataque              | Threshold | Puerto/Protocolo       |
|---------------------|-----------|------------------------|
| UDP Flood           | 20,000    | UDP genérico           |
| SYN Flood           | 30,000    | TCP SYN flag           |
| ICMP Flood          | 10,000    | ICMP                   |
| HTTP Flood          | 15,000    | TCP 80/443             |
| DNS Amplification   | 2,000     | UDP 53 (ANY/TXT)       |
| NTP Amplification   | 1,500     | UDP 123 (mode 7)       |
| SNMP Amplification  | 1,500     | UDP 161 (GetBulk)      |
| SSDP                | 1,500     | UDP 1900 (M-SEARCH)    |
| PortMap             | 1,500     | TCP/UDP 111            |
| NetBIOS             | 1,500     | UDP 137/138            |
| LDAP                | 1,500     | TCP/UDP 389/636        |
| MSSQL               | 1,500     | TCP 1433 / UDP 1434    |
| TFTP                | 1,000     | UDP 69                 |
| UDP-Lag             | 15,000    | UDP + avg_pkt > 900B   |
| ACK Flood           | 4,000     | TCP ACK flag           |
| Fragmentation       | 1,000     | IP fragmented          |
```

### 7.3 Niveles de Alerta

```c
// mira_ddos_detector.c:94-99
typedef enum {
    ALERT_NONE = 0,
    ALERT_LOW = 1,
    ALERT_MEDIUM = 2,
    ALERT_HIGH = 3
} alert_level_t;
```

### 7.4 Detección Multi-Attack

```c
// mira_ddos_detector.c:768-783
// Detectar si hay múltiples tipos de ataque simultáneos
int attack_types = 0;
if (udp_pps > 10000) attack_types++;
if (syn_pps > 10000) attack_types++;
if (icmp_pps > 5000) attack_types++;

if (attack_types >= 2) {
    g_stats.total_flood_detections++;
    alert_reason = "MULTI-ATTACK detected";
}
```

---

## 8. Optimizaciones de Rendimiento

### 8.1 Diseño Lock-Free

```
┌─────────────────────────────────────────────────────────────┐
│              ARQUITECTURA LOCK-FREE                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Worker 0          Worker 1          Worker N               │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐          │
│  │stats[0]  │      │stats[1]  │      │stats[N]  │          │
│  │sketch[0] │      │sketch[1] │      │sketch[N] │          │
│  └──────────┘      └──────────┘      └──────────┘          │
│       │                 │                 │                 │
│       │    ESCRITURA    │    ESCRITURA    │   (sin locks)   │
│       ▼                 ▼                 ▼                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Arrays de Estadísticas                  │  │
│  │  g_worker_stats[0] | g_worker_stats[1] | ... [N]     │  │
│  └──────────────────────────────────────────────────────┘  │
│                          │                                  │
│                          │ LECTURA (sin locks)              │
│                          ▼                                  │
│                   ┌──────────────┐                          │
│                   │ Coordinator  │                          │
│                   │ (solo lee)   │                          │
│                   └──────────────┘                          │
│                                                             │
│  Garantía: Cada worker SOLO escribe en su slot             │
│  Coordinator: SOLO lee (eventual consistency)               │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Prefetching de Paquetes

```c
// mira_ddos_detector.c:1420-1431

// Prefetch primeros 16 paquetes al inicio del burst
for (uint16_t i = 0; i < nb_rx && i < 16; i++) {
    rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
}

// Durante el procesamiento, prefetch 16 adelante
for (uint16_t i = 0; i < nb_rx; i++) {
    if (i + 16 < nb_rx) {
        rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 16], void *));
    }
    // Procesar bufs[i]...
}
```

**Beneficio:** Oculta ~100ns de latencia de memoria por paquete.

### 8.3 Incrementos Branchless

```c
// mira_ddos_detector.c:1459-1463
// En lugar de:
// if (is_baseline) local_baseline_pkts++;

// Usar operación condicional (branchless):
local_baseline_pkts += is_baseline ? 1 : 0;
local_baseline_bytes += is_baseline ? pkt_len : 0;
local_attack_pkts += is_attack ? 1 : 0;
local_attack_bytes += is_attack ? pkt_len : 0;
```

**Beneficio:** Evita branch mispredictions (~15 ciclos penalización).

### 8.4 Alineación de Cache

```c
// octosketch.h:62
} __rte_cache_aligned;  // Alinear a línea de cache (64 bytes)

// mira_ddos_detector.c:119
} __rte_cache_aligned;  // Evitar false sharing entre cores
```

**Beneficio:** Evita false sharing cuando diferentes cores acceden a estructuras adyacentes.

### 8.5 Sampling del Sketch

```c
// Solo actualizar sketch cada 32 paquetes
#define SKETCH_SAMPLE_RATE 32  // 3.125% overhead

if (sample_counter % SKETCH_SAMPLE_RATE == 0) {
    octosketch_update_ip(my_sketch, src_ip, SKETCH_SAMPLE_RATE);
}
```

**Beneficio:** Reduce el overhead de actualización del sketch del 100% al 3.125%.

---

## 9. Métricas y Resultados

### 9.1 Rendimiento del Sistema

| Métrica | Valor | Comparación |
|---------|-------|-------------|
| Throughput | 17+ Gbps | Line-rate para 100G NIC |
| Latencia de detección | < 50ms | vs MULTI-LF: 866ms (17× más rápido) |
| Memoria (sketch) | 128 KB × 14 = 1.79 MB | O(1) constante |
| CPU overhead sketch | ~0.5% | Con sampling 1/32 |
| Workers | 14 | lcores 1-14 |
| Burst size | 2048 paquetes | Amortiza overhead |

### 9.2 Uso de Memoria

```
Componente                    Tamaño
─────────────────────────────────────
Memory pool (mbufs)           524K × ~2KB = ~1 GB
Sketch por worker             ~390 KB
  - counters (8×4096×4)       128 KB
  - ip_counts (65536×4)       256 KB
  - metadata                  ~6 KB
Total sketches (14 workers)   ~5.5 MB
IP hash table                 ~260 KB
Worker stats                  ~50 KB
─────────────────────────────────────
Total memoria aplicación      ~1.1 GB (mayormente mbufs)
```

### 9.3 Intervalos de Tiempo

```
┌─────────────────────────────────────────────────────────────┐
│                    LÍNEA TEMPORAL                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  0ms    10ms    20ms    30ms    40ms    50ms    60ms        │
│  │       │       │       │       │       │       │          │
│  ▼       ▼       ▼       ▼       ▼       ▼       ▼          │
│  ┌───────────────────────────────────────┐                  │
│  │    detect_attacks() cada 50ms         │                  │
│  └───────────────────────────────────────┘                  │
│                                                             │
│  │       │       │       │       │       │       │          │
│  └───────┴───────┴───────┴───────┴───────┘                  │
│          Coordinator sleep 10ms                             │
│                                                             │
│  0s                                      5s                 │
│  │                                       │                  │
│  ▼                                       ▼                  │
│  ┌───────────────────────────────────────┐                  │
│  │    print_stats() cada 5 segundos      │                  │
│  └───────────────────────────────────────┘                  │
│                                                             │
│  │                                       │                  │
│  ▼                                       ▼                  │
│  ┌───────────────────────────────────────┐                  │
│  │ Reset ventana de detección cada 5s    │                  │
│  │ (reset sketches + contadores)         │                  │
│  └───────────────────────────────────────┘                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 9.4 Estadísticas de Detección

El sistema registra métricas detalladas de cada detección:

```c
// Métricas de primera detección
detection_latency_ms        // Tiempo desde primer paquete de ataque
packets_until_detection     // Paquetes procesados hasta detectar
bytes_until_detection       // Bytes procesados hasta detectar

// Métricas agregadas (múltiples detecciones)
total_detection_events      // Número total de detecciones
min_detection_latency_ms    // Detección más rápida
max_detection_latency_ms    // Detección más lenta
avg_detection_latency_ms    // Promedio

// Histograma de latencias
detections_under_20ms       // Detecciones < 20ms
detections_20_30ms          // Detecciones 20-30ms
detections_30_40ms          // Detecciones 30-40ms
detections_40_50ms          // Detecciones 40-50ms
detections_over_50ms        // Detecciones > 50ms
```

---

## Resumen Parte II

El detector MIRA sin ML combina:

1. **DPDK** para procesamiento de paquetes a velocidad de línea
2. **OctoSketch** para conteo probabilístico eficiente en memoria
3. **Arquitectura multi-core lock-free** para escalabilidad
4. **Detección por thresholds** para 13+ tipos de ataques DDoS

La arquitectura permite detectar ataques en menos de 50ms procesando tráfico a 17+ Gbps, una mejora de 17× sobre sistemas basados en ML tradicionales como MULTI-LF.

---

# PARTE III: SISTEMA DE MACHINE LEARNING

---

## 10. Entrenamiento del Modelo ML

### 10.1 Proceso de Captura de Datos

Los datos de entrenamiento se capturan directamente del detector MIRA durante la ejecución de diferentes escenarios de tráfico.

#### 10.1.1 Escenarios de Captura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ESCENARIOS DE CAPTURA DE DATOS                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ESCENARIO 1: Tráfico Benigno (baseline)                               │
│  ─────────────────────────────────────────                              │
│  • Fuente: Controller (10.10.2.x)                                       │
│  • Duración: 3 runs independientes                                      │
│  • Muestras: 179 por run = 537 total                                    │
│  • Label: "benign"                                                      │
│                                                                         │
│  ESCENARIO 2: Ataques Individuales (12 tipos)                          │
│  ─────────────────────────────────────────────                          │
│  • Fuente: TG (10.10.3.x)                                               │
│  • Tipos: UDP, SYN, DNS, NTP, SNMP, SSDP, PortMap,                     │
│           NetBIOS, LDAP, MSSQL, TFTP, WebDDoS                          │
│  • Muestras: 537 por tipo (179 × 3 runs)                               │
│  • Labels: "udp", "syn", "dns", etc.                                   │
│                                                                         │
│  ESCENARIO 3: Tráfico Mixto (realistic)                                │
│  ─────────────────────────────────────────                              │
│  • Fuente: Controller + TG simultáneamente                              │
│  • Muestras: 857 total                                                  │
│  • Label: "mixed"                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 10.1.2 Estructura de Archivos Capturados

```
mira/ml_system/datasets/
├── processed/
│   ├── benign_baseline_run1.csv    # 179 muestras
│   ├── benign_baseline_run2.csv    # 179 muestras
│   ├── benign_baseline_run3.csv    # 179 muestras
│   ├── mixed_traffic_run1.csv      # 179 muestras
│   ├── mixed_traffic_run2.csv      # 179 muestras
│   ├── mixed_traffic_run3.csv      # 179 muestras
│   ├── udp_attack_run1.csv         # ...
│   ├── syn_attack_run1.csv
│   ├── dns_attack_run1.csv
│   └── ... (más archivos por tipo de ataque)
└── splits/
    ├── train.csv                    # 5,332 muestras
    ├── val.csv                      # 2,448 muestras
    └── test.csv                     # 2,448 muestras
```

### 10.2 Dataset Combinado

#### 10.2.1 Distribución de Clases

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    DISTRIBUCIÓN DEL DATASET (7,780 muestras)            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Clase        │ Muestras │  %     │ Descripción                        │
│  ─────────────┼──────────┼────────┼────────────────────────────────────│
│  mixed        │   857    │ 11.0%  │ Tráfico benigno + ataque mezclado  │
│  benign       │   537    │  6.9%  │ Solo tráfico benigno               │
│  udp          │   537    │  6.9%  │ UDP Flood                          │
│  syn          │   537    │  6.9%  │ SYN Flood                          │
│  dns          │   537    │  6.9%  │ DNS Amplification                  │
│  ntp          │   537    │  6.9%  │ NTP Amplification                  │
│  snmp         │   537    │  6.9%  │ SNMP Amplification                 │
│  ssdp         │   537    │  6.9%  │ SSDP Reflection                    │
│  portmap      │   537    │  6.9%  │ PortMap/RPC                        │
│  netbios      │   537    │  6.9%  │ NetBIOS                            │
│  ldap         │   537    │  6.9%  │ LDAP Amplification                 │
│  mssql        │   537    │  6.9%  │ MSSQL                              │
│  tftp         │   537    │  6.9%  │ TFTP                               │
│  webddos      │   479    │  6.2%  │ HTTP Flood (WebDDoS)               │
│  ─────────────┼──────────┼────────┼────────────────────────────────────│
│  TOTAL        │  7,780   │ 100%   │ 14 clases                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 10.2.2 Features Extraídas (42 características)

El detector extrae 42 features por ventana de tiempo:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FEATURES DEL MODELO (42)                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONTADORES BÁSICOS (9 features):                                       │
│  ─────────────────────────────────                                      │
│  • total_packets          - Paquetes totales en la ventana             │
│  • total_bytes            - Bytes totales                               │
│  • udp_packets            - Paquetes UDP                                │
│  • tcp_packets            - Paquetes TCP                                │
│  • icmp_packets           - Paquetes ICMP                               │
│  • syn_packets            - Paquetes con flag SYN                       │
│  • http_requests          - Peticiones HTTP detectadas                  │
│  • dns_queries            - Consultas DNS                               │
│  • baseline_packets       - Paquetes de red benigna (10.10.2.x)        │
│  • attack_packets         - Paquetes de red de ataque (10.10.3.x)      │
│                                                                         │
│  CONTADORES ESPECÍFICOS DE PROTOCOLO (22 features):                     │
│  ───────────────────────────────────────────────────                    │
│  NTP:     ntp_monlist_queries, ntp_responses, avg_ntp_response_size    │
│  DNS:     dns_any_queries, dns_txt_queries, dns_responses,             │
│           avg_dns_response_size                                         │
│  SNMP:    snmp_getbulk_requests, snmp_responses, avg_snmp_response_size│
│  SSDP:    ssdp_msearch_packets, ssdp_responses                         │
│  PortMap: portmap_getport_calls, portmap_dump_calls                    │
│  NetBIOS: netbios_name_queries, netbios_dgram_packets                  │
│  LDAP:    ldap_bind_requests, ldap_search_requests                     │
│  MSSQL:   mssql_sqlbatch_packets, mssql_rpc_packets                    │
│  TFTP:    tftp_rrq_packets, tftp_wrq_packets                           │
│                                                                         │
│  RATIOS DERIVADOS (7 features):                                         │
│  ───────────────────────────────                                        │
│  • udp_tcp_ratio          - UDP / TCP                                   │
│  • syn_total_ratio        - SYN / Total                                 │
│  • baseline_attack_ratio  - Baseline / Attack                           │
│  • bytes_per_packet       - Bytes / Paquetes                            │
│  • ntp_amplification_factor                                             │
│  • dns_amplification_factor                                             │
│  • snmp_amplification_factor                                            │
│                                                                         │
│  INDICADORES ADICIONALES (4 features):                                  │
│  ──────────────────────────────────────                                 │
│  • query_response_ratio   - Queries / Responses                         │
│  • fragmentation_ratio    - Paquetes fragmentados / Total               │
│  • syn_ack_ratio          - SYN / ACK                                   │
│  • run_id                 - Identificador del run (para split)          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.3 División del Dataset (Train/Val/Test)

#### 10.3.1 Estrategia de Split por Run

Para evitar data leakage, se divide por `run_id`:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    DIVISIÓN POR RUN_ID                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
│  │    RUN 1    │    │    RUN 2    │    │    RUN 3    │                 │
│  │             │    │             │    │             │                 │
│  │  (captura   │    │  (captura   │    │  (captura   │                 │
│  │   día 1)    │    │   día 2)    │    │   día 3)    │                 │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                 │
│         │                  │                  │                         │
│         └────────┬─────────┘                  │                         │
│                  │                            │                         │
│                  ▼                            ▼                         │
│         ┌───────────────┐            ┌───────────────┐                 │
│         │    TRAIN      │            │   VAL / TEST  │                 │
│         │  (run1 + run2)│            │    (run3)     │                 │
│         │               │            │               │                 │
│         │  5,332 samples│            │ 2,448 samples │                 │
│         │    (68.5%)    │            │    (31.5%)    │                 │
│         └───────────────┘            └───────────────┘                 │
│                                                                         │
│  Beneficio: Los datos de validación/test son de una sesión             │
│  completamente diferente a los de entrenamiento.                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 10.3.2 Distribución de Clases por Split

```
Split    │ benign │  dns  │ ldap  │ mixed │ mssql │ ... │ TOTAL
─────────┼────────┼───────┼───────┼───────┼───────┼─────┼───────
Train    │   358  │  358  │  358  │  678  │  358  │ ... │ 5,332
Val      │   179  │  179  │  179  │  179  │  179  │ ... │ 2,448
Test     │   179  │  179  │  179  │  179  │  179  │ ... │ 2,448
```

### 10.4 Entrenamiento del Modelo LightGBM

#### 10.4.1 Configuración del Entrenamiento

```python
# train_with_normalization.py

# Normalización de features
scaler = StandardScaler()  # mean=0, std=1

# Parámetros de LightGBM
params = {
    'boosting_type': 'gbdt',
    'objective': 'multiclass',
    'num_class': 14,
    'max_depth': 8,
    'num_leaves': 63,
    'learning_rate': 0.05,
    'n_estimators': 300,
    'reg_alpha': 0.5,      # L1 regularization
    'reg_lambda': 0.5,     # L2 regularization
    'early_stopping_rounds': 30,
}
```

#### 10.4.2 Proceso de Entrenamiento

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PROCESO DE ENTRENAMIENTO                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. CARGA DE DATOS                                                      │
│     ────────────────                                                    │
│     Train: 5,332 samples × 42 features                                  │
│     Val:   2,448 samples × 42 features                                  │
│                                                                         │
│  2. NORMALIZACIÓN (StandardScaler)                                      │
│     ───────────────────────────────                                     │
│     Para cada feature: x_norm = (x - mean) / std                        │
│     Scaler ajustado SOLO con datos de train                             │
│                                                                         │
│  3. ENTRENAMIENTO ITERATIVO                                             │
│     ───────────────────────────                                         │
│     Epoch 50:  train_loss=0.0589  val_loss=0.0662                      │
│     Epoch 100: train_loss=0.0419  val_loss=0.0476                      │
│     Epoch 150: train_loss=0.0409  val_loss=0.0471                      │
│     Epoch 200: train_loss=0.0406  val_loss=0.0466                      │
│     Epoch 255: train_loss=0.0403  val_loss=0.0464 ← BEST (early stop)  │
│                                                                         │
│  4. EXPORTACIÓN                                                         │
│     ────────────                                                        │
│     • lightgbm_model.txt    (modelo serializado)                        │
│     • label_mapping.json    (mapeo clase → índice)                      │
│     • feature_scaler.pkl    (scaler para normalización)                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.5 Resultados del Entrenamiento

#### 10.5.1 Métricas Generales

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    RESULTADOS DEL MODELO                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ╔═══════════════════════════════════════════════════════════════════╗ │
│  ║  ACCURACY EN VALIDACIÓN:   98.41%                                 ║ │
│  ║  ACCURACY EN TEST:         98.41%                                 ║ │
│  ╚═══════════════════════════════════════════════════════════════════╝ │
│                                                                         │
│  Métricas Promedio (Weighted):                                          │
│  ─────────────────────────────                                          │
│  • Precision: 0.987                                                     │
│  • Recall:    0.984                                                     │
│  • F1-Score:  0.985                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 10.5.2 Rendimiento por Clase

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MÉTRICAS POR CLASE (TEST SET)                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Clase     │ Precision │ Recall │ F1-Score │ Support │ Observaciones   │
│  ──────────┼───────────┼────────┼──────────┼─────────┼─────────────────│
│  benign    │   0.989   │ 0.972  │  0.980   │   179   │ ✓ Excelente     │
│  dns       │   1.000   │ 0.983  │  0.992   │   179   │ ✓ Perfecto      │
│  ldap      │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  mixed     │   0.827   │ 0.989  │  0.901   │   179   │ ⚠ Más difícil   │
│  mssql     │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  netbios   │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  ntp       │   1.000   │ 0.983  │  0.992   │   179   │ ✓ Perfecto      │
│  portmap   │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  snmp      │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  ssdp      │   1.000   │ 0.983  │  0.992   │   179   │ ✓ Perfecto      │
│  syn       │   1.000   │ 0.978  │  0.989   │   179   │ ✓ Perfecto      │
│  tftp      │   1.000   │ 0.989  │  0.994   │   179   │ ✓ Perfecto      │
│  udp       │   1.000   │ 0.983  │  0.992   │   179   │ ✓ Perfecto      │
│  webddos   │   1.000   │ 0.967  │  0.983   │   121   │ ✓ Perfecto      │
│                                                                         │
│  Nota: La clase "mixed" tiene menor precision porque algunos ataques   │
│  se confunden con tráfico mixto (es esperado dado su naturaleza).      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 10.5.3 Matriz de Confusión

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    MATRIZ DE CONFUSIÓN (SIMPLIFICADA)                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Las principales confusiones son entre ataques específicos y "mixed":   │
│                                                                         │
│  True\Pred │ benign │ mixed │ (resto) │                                │
│  ──────────┼────────┼───────┼─────────┤                                │
│  benign    │  174   │   5   │    0    │  5 benign → mixed              │
│  dns       │    0   │   3   │  176    │  3 dns → mixed                 │
│  syn       │    0   │   4   │  175    │  4 syn → mixed                 │
│  ntp       │    0   │   3   │  176    │  3 ntp → mixed                 │
│  mixed     │    2   │  177  │    0    │  2 mixed → benign              │
│  ...       │  ...   │  ...  │   ...   │                                │
│                                                                         │
│  Total errores: 39 de 2,448 = 1.59%                                     │
│                                                                         │
│  Patrón: La mayoría de errores son ataques clasificados como "mixed"   │
│  (lo cual es parcialmente correcto ya que mixed incluye ataques)        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.6 Features Más Importantes

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TOP 10 FEATURES (IMPORTANCIA)                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Rank │ Feature                  │ Importancia │ Interpretación        │
│  ─────┼──────────────────────────┼─────────────┼───────────────────────│
│   1   │ syn_total_ratio          │   28,645.7  │ Detecta SYN floods    │
│   2   │ syn_ack_ratio            │   22,349.8  │ Ratio SYN/ACK         │
│   3   │ dns_any_queries          │   16,052.3  │ DNS amplification     │
│   4   │ ntp_monlist_queries      │   15,744.5  │ NTP amplification     │
│   5   │ ssdp_msearch_packets     │   15,669.0  │ SSDP reflection       │
│   6   │ netbios_name_queries     │   15,345.4  │ NetBIOS attacks       │
│   7   │ avg_dns_response_size    │   15,340.3  │ DNS amp factor        │
│   8   │ portmap_getport_calls    │   14,614.1  │ PortMap attacks       │
│   9   │ tftp_rrq_packets         │   14,581.5  │ TFTP attacks          │
│  10   │ mssql_sqlbatch_packets   │   14,460.1  │ MSSQL attacks         │
│                                                                         │
│  Observación: Los ratios (syn_total, syn_ack) son los más importantes  │
│  porque capturan la "firma" de los ataques de manera normalizada.       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.7 Comparación de Modelos

Se evaluaron múltiples algoritmos en las mismas condiciones:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    COMPARACIÓN DE ALGORITMOS                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Modelo                 │ Val Acc  │ Test Acc │ Observaciones          │
│  ───────────────────────┼──────────┼──────────┼────────────────────────│
│  LightGBM               │  98.41%  │  98.41%  │ ★ Mejor balance        │
│  RandomForest           │  98.41%  │  98.41%  │ Igual que LightGBM     │
│  HistGradientBoosting   │  98.41%  │  98.41%  │ Igual que LightGBM     │
│  XGBoost                │  98.37%  │  98.37%  │ Ligeramente peor       │
│  KNN (k=15)             │  98.49%  │  98.49%  │ Mejor pero más lento   │
│  MLP (128,64)           │  98.28%  │  98.28%  │ Redes neuronales       │
│  SGDClassifier          │  98.08%  │  98.08%  │ Lineal                 │
│  LSTM (seq_len=12)      │  98.96%  │  98.96%  │ Secuencial - mejor     │
│                                                                         │
│  Selección: LightGBM por su balance entre:                              │
│  • Accuracy competitivo (98.41%)                                        │
│  • Velocidad de inferencia (~1-3ms)                                     │
│  • Tamaño del modelo pequeño                                            │
│  • Fácil integración con C (API nativa)                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.8 Archivos Generados

```
mira/detector_system_ml/
├── lightgbm_model.txt      # Modelo serializado (texto)
├── label_mapping.json      # {"0": "benign", "1": "dns", ...}
├── feature_scaler.pkl      # StandardScaler (pickle)
├── feature_columns.json    # Lista de nombres de features
└── alt_model/              # Modelos alternativos
    ├── randomforest/
    ├── histgradientboosting/
    ├── knn/
    ├── mlp/
    ├── sgdclassifier/
    └── xgboost/
```

### 10.9 Integración en el Detector

El modelo LightGBM se integra en el detector DPDK mediante la C API:

```c
// ml_inference.c

#include <lightgbm/c_api.h>

// Cargar modelo
BoosterHandle booster;
LGBM_BoosterCreateFromModelfile("lightgbm_model.txt", &num_iterations, &booster);

// Predecir (cada 50ms)
double features[42] = {...};  // Extraídas del sketch
double predictions[14];       // Probabilidades por clase

LGBM_BoosterPredictForMat(
    booster,
    features,
    C_API_DTYPE_FLOAT64,
    1,                // 1 muestra
    42,               // 42 features
    1,                // row major
    C_API_PREDICT_NORMAL,
    0,
    -1,
    "",
    &out_len,
    predictions
);

// Clase con mayor probabilidad
int predicted_class = argmax(predictions, 14);
float confidence = predictions[predicted_class];
```

---

## Resumen Final

El sistema MIRA combina:

### Infraestructura (4 nodos)
- **TG**: Genera tráfico de ataque (10.10.3.x)
- **Controller**: Genera tráfico benigno (10.10.2.x)
- **Monitor**: Ejecuta el detector DPDK
- **Victim**: Servidor objetivo

### Detector sin ML
- DPDK para procesamiento a 17+ Gbps
- OctoSketch para conteo eficiente O(1)
- 14 workers + 1 coordinator (lock-free)
- Detección por thresholds en <50ms

### Sistema ML
- 42 features extraídas del tráfico
- 14 clases (benign + 12 ataques + mixed)
- LightGBM con 98.41% accuracy
- Inferencia integrada en C (~1-3ms)

La combinación de thresholds + ML permite:
- Detección rápida de ataques obvios (thresholds)
- Detección de ataques sutiles (ML)
- Reducción de falsos positivos (~2% vs 8%)
