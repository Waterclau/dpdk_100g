# Mejoras del Detector MIRA - Febrero 2026

## Resumen Ejecutivo

Se han implementado dos mejoras principales al detector:

1. **Ring Buffer** - Análisis temporal para detectar tendencias
2. **Multi-Scale Sketches** - Detección de bursts a múltiples escalas temporales

**Nota:** Se mantienen thresholds FIJOS para detección. Las features temporales se calculan para ML pero no contaminan la detección.

---

## 1. Problema que Resuelven las Mejoras

### Detector Original (Limitaciones)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  LIMITACIONES DEL DETECTOR ORIGINAL                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Solo ve la ventana actual (50ms)                                   │
│     - No sabe si el ataque está subiendo o bajando                     │
│     - No detecta ataques que escalan gradualmente                      │
│                                                                         │
│  2. Un solo sketch (50ms)                                              │
│     - No distingue ráfaga instantánea de ataque sostenido              │
│     - No puede comparar actividad actual vs histórica                  │
│                                                                         │
│  3. Solo 42 features para ML                                           │
│     - Sin información temporal                                          │
│     - Sin comparación multi-escala                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Arquitectura de las Mejoras

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ARQUITECTURA MEJORADA                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  WORKERS (14 cores) - Por cada paquete de ataque (sampled 1/32):       │
│                                                                         │
│    octosketch_update(&sketch_50ms, ip);   // Escala instantánea        │
│    octosketch_update(&sketch_1s, ip);     // Escala 1 segundo          │
│    octosketch_update(&sketch_10s, ip);    // Escala 10 segundos        │
│    octosketch_update(&sketch_1min, ip);   // Escala 1 minuto           │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  COORDINATOR (cada 50ms):                                               │
│                                                                         │
│    1. Detección por THRESHOLDS FIJOS (sin cambios)                     │
│       - UDP > 20K pps → UDP_FLOOD                                      │
│       - SYN > 30K pps → SYN_FLOOD                                      │
│       - etc.                                                            │
│                                                                         │
│    2. Merge multi-scale sketches                                        │
│                                                                         │
│    3. Calcular features temporales (RING BUFFER)                       │
│       - delta_pps_5w, delta_pps_10w                                    │
│       - pps_variance                                                    │
│       - ratio_vs_baseline                                               │
│                                                                         │
│    4. Calcular features multi-escala (SKETCHES)                        │
│       - top_ip_pps a 50ms, 1s, 1min                                    │
│       - burst_ratio = 50ms / 1min                                      │
│       - ip_concentration                                                │
│                                                                         │
│    5. Detección de TENDENCIAS (ring buffer)                            │
│       - Si delta_pps > 10K en 250ms → TREND alert                      │
│                                                                         │
│    6. Detección de BURSTS (multi-scale)                                │
│       - Si ratio_50ms_1min > 5x → BURST alert                          │
│                                                                         │
│    7. Guardar en ring buffer (56 features para ML)                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Ring Buffer - Análisis Temporal

### Estructura

```c
#define RING_BUFFER_SIZE 100  // 100 ventanas × 50ms = 5 segundos

struct ring_buffer {
    struct feature_window windows[100];  // Historial circular
    uint32_t write_idx;                  // Índice de escritura
    uint64_t total_windows;              // Total procesadas
};
```

### Funcionamiento

```
Tiempo →  [t-99][t-98]...[t-10][t-5][t-4][t-3][t-2][t-1][t-0]
              │              │     │                       │
              │              │     │                       └── Ventana actual
              │              │     └───────────────────────── Hace 250ms
              │              └─────────────────────────────── Hace 500ms
              └────────────────────────────────────────────── Hace 5 segundos

Operaciones O(1):
  - ring_buffer_get(-5)  → Ventana de hace 250ms
  - ring_buffer_push()   → Añadir nueva ventana
```

### Features Temporales (del Ring Buffer)

| Feature | Cálculo | Qué detecta |
|---------|---------|-------------|
| `delta_pps_5w` | pps[0] - pps[-5] | Cambio en 250ms (ataque comenzando) |
| `delta_pps_10w` | pps[0] - pps[-10] | Cambio en 500ms (tendencia) |
| `pps_variance` | var(últimas 20) | Estabilidad del tráfico |
| `pps_baseline` | media(ring buffer) | Baseline móvil (solo para ML) |
| `ratio_vs_baseline` | pps / baseline | Ratio de anomalía |

### Detección de Tendencias

```c
/* Si el tráfico sube rápidamente → ataque escalando */
if (delta_pps_5w > 10000 && delta_pps_10w > 20000) {
    alert("TREND: attack rising (+%.0f pps in 250ms)", delta_pps_5w);
}
```

**Memoria:** ~19 KB (100 ventanas × 188 bytes)

---

## 4. Multi-Scale Sketches - Detección de Bursts

### Estructura

```c
struct multiscale_sketches {
    struct octosketch sketch_50ms;   // Reset cada ventana
    struct octosketch sketch_1s;     // Reset cada 20 ventanas (1s)
    struct octosketch sketch_10s;    // Reset cada 200 ventanas (10s)
    struct octosketch sketch_1min;   // Reset cada 1200 ventanas (1min)
};
```

### Escalas Temporales

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  Escala 50ms    ████████████████████  → Ráfagas instantáneas           │
│                 (reset cada ventana)                                    │
│                                                                         │
│  Escala 1s      ████████              → Ataques cortos                  │
│                 (reset cada 20 ventanas)                                │
│                                                                         │
│  Escala 10s     ████                  → Ataques medios                  │
│                 (reset cada 200 ventanas)                               │
│                                                                         │
│  Escala 1min    ██                    → Ataques sostenidos / baseline   │
│                 (reset cada 1200 ventanas)                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Features Multi-Escala (de los Sketches)

| Feature | Cálculo | Qué detecta |
|---------|---------|-------------|
| `top_ip_pps_50ms` | top1(sketch_50ms) / 0.05s | Heavy-hitter instantáneo |
| `top_ip_pps_1s` | top1(sketch_1s) / 1s | Heavy-hitter sostenido |
| `top_ip_pps_1min` | top1(sketch_1min) / 60s | Baseline de atacante |
| `ratio_50ms_1min` | pps_50ms / pps_1min | **BURST DETECTION** |
| `ip_concentration` | top1 / total | Ataque concentrado vs distribuido |
| `num_heavy_hitters` | count(IPs > threshold) | Número de atacantes |

### Detección de Bursts

```c
/* Si actividad instantánea es 5x mayor que el histórico → burst */
if (ratio_50ms_1min > 5.0 && top_ip_pps_50ms > 1000) {
    alert("BURST: %.1fx spike vs 1min baseline", ratio_50ms_1min);
}
```

**Memoria:** ~40 MB (4 escalas × 15 sketches × ~650 KB)

---

## 5. Features Extendidas (42 → 56)

### Features Base (1-42) - Sin cambios

| # | Categoría | Features |
|---|-----------|----------|
| 1-10 | Contadores básicos | packets, bytes, tcp, udp, icmp, syn, http, dns, baseline, attack |
| 11-14 | Ratios básicos | udp/tcp, syn/total, baseline/attack, bytes/packet |
| 15-36 | Protocolos | NTP, DNS, SNMP, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP |
| 37-42 | Ratios avanzados | amplification, query/response, fragmentation, syn/ack |

### Features Temporales (43-47) - NUEVAS (Ring Buffer)

| # | Feature | Descripción |
|---|---------|-------------|
| 43 | `delta_pps_5w` | Cambio de PPS en 250ms |
| 44 | `delta_pps_10w` | Cambio de PPS en 500ms |
| 45 | `pps_variance` | Varianza (estabilidad) |
| 46 | `pps_baseline` | Media móvil del ring buffer |
| 47 | `ratio_vs_baseline` | Ratio actual/baseline |

### Features Multi-Escala (48-56) - NUEVAS (Sketches)

| # | Feature | Descripción |
|---|---------|-------------|
| 48 | `top_ip_pps_50ms` | Top attacker (instantáneo) |
| 49 | `top_ip_pps_1s` | Top attacker (1 segundo) |
| 50 | `top_ip_pps_1min` | Top attacker (1 minuto) |
| 51 | `ratio_50ms_1min` | Burst ratio |
| 52 | `num_heavy_hitters` | IPs sobre threshold |
| 53 | `ip_concentration` | Top1 / total |
| 54 | `new_ips_ratio` | Placeholder para IPs nuevas |
| 55 | `attack_entropy` | 1 - concentration |
| 56 | `adaptive_threshold` | Threshold calculado (solo para ML) |

---

## 6. Detecciones Nuevas

### 6.1 Detección de Tendencias (Ring Buffer)

Detecta ataques que escalan gradualmente:

```
Ejemplo: Ataque que sube de 5K a 50K pps en 1 segundo

t=0.0s:  5,000 pps  (bajo threshold)
t=0.25s: 15,000 pps (bajo threshold)
t=0.5s:  25,000 pps → TREND ALERT: +20,000 pps in 500ms
t=0.75s: 40,000 pps
t=1.0s:  50,000 pps → THRESHOLD ALERT: UDP > 20K
```

**Beneficio:** Detecta el ataque 500ms antes que solo thresholds.

### 6.2 Detección de Bursts (Multi-Scale)

Detecta spikes súbitos comparando con histórico:

```
Ejemplo: IP que normalmente envía 100 pps, de repente envía 5000 pps

sketch_1min: IP 10.10.3.45 → 100 pps (baseline)
sketch_50ms: IP 10.10.3.45 → 5000 pps (instantáneo)

ratio = 5000 / 100 = 50x → BURST ALERT
```

**Beneficio:** Detecta ataques aunque estén bajo el threshold global.

---

## 7. Uso de Memoria

| Componente | Tamaño | Descripción |
|------------|--------|-------------|
| Ring Buffer | ~19 KB | 100 ventanas × 188 bytes |
| Sketches base | ~10 MB | 15 sketches × 650 KB |
| Multi-scale | ~40 MB | 4 escalas × 15 sketches × 650 KB |
| **Total** | **~50 MB** | Aceptable para servidor |

---

## 8. Comparación: Antes vs Después

| Aspecto | Detector Original | Detector Mejorado |
|---------|-------------------|-------------------|
| Features para ML | 42 | **56** |
| Detección temporal | ❌ No | ✅ Tendencias (delta) |
| Detección burst | ❌ No | ✅ Ratio 50ms/1min |
| Escalas temporales | 1 (50ms) | **4** (50ms, 1s, 10s, 1min) |
| Heavy-hitters | 1 escala | **4 escalas** |
| Thresholds | Fijos | Fijos (sin cambio) |
| Memoria extra | 0 | ~50 MB |

---

## 9. Plan Experimental

### Estructura de un Run (900 segundos)

```
Tiempo (segundos)
    0         300                                      895   900
    │         │                                        │     │
    ▼         ▼                                        ▼     ▼

    ├─────────────────────────────────────────────────────────┤
    │           BASELINE (Controller - 895s)                  │
    │           benigno desde 0s hasta 895s                   │
    ├─────────────────────────────────────────────────────────┤

                ├──────────────────────────────────────┤
                │            ATAQUE (TG)               │
                │       desde 300s hasta 895s          │
                │          (595 segundos)              │
                ├──────────────────────────────────────┤

    │◄─ WARM-UP ─►│◄────────── ATAQUE + BASELINE ────────────►│
    │   (0-300s)   │              (300-895s)                   │
    │  Ring buffer │                                           │
    │  se llena    │                                           │
```

### Por qué 300 segundos de warm-up

- Ring buffer necesita llenarse (5 segundos mínimo)
- Multi-scale sketch de 1min necesita 60 segundos
- 300 segundos da margen para estabilizar todas las métricas

### Ejecución

```bash
# Monitor (900s)
sudo timeout 900 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | \
    sudo tee ../ml_system/datasets/raw_logs/2/udp_flood_run1.log

# Controller - Baseline (895s, empieza en t=0)
sudo timeout 895 ./benign_sender ... --rate 2000

# TG - Ataque (595s, empieza en t=300)
sleep 300 && sudo timeout 595 ./attack_sender ... --rate 10000
```

---

## 10. Archivos Modificados

| Archivo | Cambios |
|---------|---------|
| `mira_ddos_detector.c` | +400 líneas (ring buffer, multi-scale, features) |
| `octosketch.h` | +1 array `ip_addrs[65536]` para IPs reales |

---

## 11. Trabajo Futuro

1. **Optimizar memoria** - Reducir tamaño de sketches multi-escala
2. **Más features temporales** - Autocorrelación, FFT para patrones periódicos
3. **Online learning** - Actualizar modelo ML en tiempo real
4. **Exportar ring buffer** - Dump periódico para análisis offline

Run1 (DNS + SYN + ICMP):                                                                                                                                                                         
                                                                                                                                                                                                   
  - DNS 50% (≥45.6%)                                                                                                                                                                               
  - SYN 40% (≥38%)                                                                                                                                                                                 
  - ICMP 10% (≥10.6% → pon 11% si quieres margen)                                                                                                                                                  
                                                                                                                                                                                                   
  Run2 (NTP + SNMP + SSDP):                                                                                                                                                                        
                                                                                                                                                                                                   
  - NTP 34%                                                                                                                                                                                        
  - SNMP 33%                                                                                                                                                                                       
  - SSDP 33%                                                                                                                                                                                       
    (Todos ≥30.4%)                                                                                                                                                                                 
                                                                                                                                                                                                   
  Run3 (Portmap + NetBIOS + LDAP):                                                                                                                                                                 
                                                                                                                                                                                                   
  - Portmap 34%                                                                                                                                                                                    
  - NetBIOS 33%                                                                                                                                                                                    
  - LDAP 33%                                                                                                                                                                                       
    (Todos ≥30.4%)                                                                                                                                                                                 
                                                                                                                                                                                                   
  Run4 (WebDDOS + TFTP + ICMP):                                                                                                                                                                    
  - TFTP 20% (≥15.2%)
  - ICMP 15% (≥10.6%)