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


  Ahora tengo todo el contexto. Te lo desgloso paso a paso, archivo por archivo.                                                                                                                                                                                                                                                                                                                      
  ---                                                                                                                                                                                                Plan concreto en 3 fases
                                                                                                                                                                                                   
  Fase 1: Ablation Study con las 56 features actuales (SOLO Python, sin tocar el detector)

  Esto lo puedes hacer ya mismo sin modificar nada en C. Los datos ya existen en los logs. Solo necesitas un script de comparación.

  Un solo archivo nuevo: ml_system/02_training/ablation_study.py

  Lógica:

  # Definir los 3 grupos de features sobre los CSVs que ya tienes

  DPI_FEATURES = [
      # Features 1-42: contadores + DPI protocolar + ratios derivados
      'total_packets', 'total_bytes', 'udp_packets', 'tcp_packets', 'icmp_packets',
      'syn_packets', 'http_requests', 'dns_queries',
      'baseline_packets', 'attack_packets',
      'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio', 'bytes_per_packet',
      'ntp_monlist_queries', 'ntp_responses', 'avg_ntp_response_size',
      'dns_any_queries', 'dns_txt_queries', 'dns_responses', 'avg_dns_response_size',
      'snmp_getbulk_requests', 'snmp_responses', 'avg_snmp_response_size',
      'ssdp_msearch_packets', 'ssdp_responses',
      'portmap_getport_calls', 'portmap_dump_calls',
      'netbios_name_queries', 'netbios_dgram_packets',
      'ldap_bind_requests', 'ldap_search_requests',
      'mssql_sqlbatch_packets', 'mssql_rpc_packets',
      'tftp_rrq_packets', 'tftp_wrq_packets',
      'ntp_amplification_factor', 'dns_amplification_factor', 'snmp_amplification_factor',
      'query_response_ratio', 'fragmentation_ratio', 'syn_ack_ratio',
  ]

  SKETCH_FEATURES = [
      # Features 43-56: ring buffer temporal + multi-escala sketch
      'delta_pps_5w', 'delta_pps_10w', 'pps_variance',
      'pps_baseline', 'ratio_vs_baseline',
      'top_ip_pps_50ms', 'top_ip_pps_1s', 'top_ip_pps_1min',
      'ratio_50ms_1min', 'num_heavy_hitters', 'ip_concentration',
      'new_ips_ratio', 'attack_entropy', 'adaptive_threshold',
  ]

  ALL_FEATURES = DPI_FEATURES + SKETCH_FEATURES

  Entrenas 3 modelos LightGBM idénticos (mismos hiperparámetros, mismo train/val/test split), cada uno con un subset de columnas:
  ┌──────────┬─────────────────┬──────────────┬──────────────────────────────────────┐
  │  Modelo  │    Features     │ Num features │               Qué mide               │
  ├──────────┼─────────────────┼──────────────┼──────────────────────────────────────┤
  │ Modelo A │ DPI_FEATURES    │ 42           │ Valor de la inspección profunda sola │
  ├──────────┼─────────────────┼──────────────┼──────────────────────────────────────┤
  │ Modelo B │ SKETCH_FEATURES │ 14           │ Valor del sketch + temporal solo     │
  ├──────────┼─────────────────┼──────────────┼──────────────────────────────────────┤
  │ Modelo C │ ALL_FEATURES    │ 56           │ Combinación (baseline actual)        │
  └──────────┴─────────────────┴──────────────┴──────────────────────────────────────┘
  Resultado: Una tabla comparativa con accuracy, F1, precision, recall por clase para cada modelo. Esta tabla ya es una contribución publicable para tu TFM.

  Lo que espero que salga:
  - Modelo A (DPI): ~98-99% (casi todo el poder predictivo)
  - Modelo B (Sketch): ~40-60% multi-clase, ~85-90% binario
  - Modelo C (Todo): ~99% (marginal mejora sobre A)

  Esto demuestra que las features DPI dominan, pero abre la puerta a la pregunta: "¿Podemos hacer que las features de sketch aporten más?" - que es exactamente la Fase 2.

  ---
  Fase 2: Ampliar features de sketch (sin nuevos sketches, solo extraer más de lo que ya tienes)

  Tu g_merged_sketch_attack ya tiene la matriz counters[8][4096] y el array ip_counts[65536]. Solo estás extrayendo 9 features de ahí. Se pueden sacar muchas más.

  Cambios en mira_ddos_detector.c:

  a) Nuevos campos en struct feature_window (línea ~390):

  /* Extended sketch statistics (NEW) */
  float sketch_nonzero_ratio;       /* Fracción de buckets no-cero (sparsidad) */
  float sketch_max_bucket;          /* Valor máximo en cualquier bucket */
  float sketch_bucket_entropy;      /* Entropía Shannon de la distribución de buckets */
  float hh_total_pps;               /* Suma PPS de todos los heavy-hitters */
  float hh_pps_spread;              /* max_hh / min_hh (dispersión) */
  float top5_concentration;         /* top5_count / total (vs top1 actual) */
  float ratio_1s_10s;               /* Burst ratio escala 1s vs 10s */
  float ratio_10s_1min;             /* Burst ratio escala 10s vs 1min */
  float scale_consistency;          /* Mismos IPs son HH en todas las escalas? */

  b) Nueva función de cálculo (después de calculate_multiscale_features, línea ~774):

  static void calculate_extended_sketch_features(struct feature_window *current)
  {
      struct octosketch *sk = &g_merged_sketch_attack;

      /* Sparsity: qué fracción de buckets están activos */
      int nonzero = 0;
      uint32_t max_val = 0;
      double sum = 0, sum_sq = 0;
      for (int i = 0; i < SKETCH_ROWS; i++) {
          for (int j = 0; j < SKETCH_COLS; j++) {
              uint32_t v = sk->counters[i][j];
              if (v > 0) nonzero++;
              if (v > max_val) max_val = v;
              sum += v;
              sum_sq += (double)v * v;
          }
      }
      int total_buckets = SKETCH_ROWS * SKETCH_COLS;  // 32768
      current->sketch_nonzero_ratio = (float)nonzero / total_buckets;
      current->sketch_max_bucket = (float)max_val;

      /* Entropía Shannon de la distribución de buckets (row 0 como muestra) */
      double entropy = 0;
      double row_total = 0;
      for (int j = 0; j < SKETCH_COLS; j++) row_total += sk->counters[0][j];
      if (row_total > 0) {
          for (int j = 0; j < SKETCH_COLS; j++) {
              if (sk->counters[0][j] > 0) {
                  double p = sk->counters[0][j] / row_total;
                  entropy -= p * log2(p);
              }
          }
      }
      current->sketch_bucket_entropy = (float)entropy;

      /* Heavy-hitter aggregates */
      struct heavy_hitter top5[5];
      octosketch_top_k(sk, 5, top5);
      float hh_sum = 0, hh_min = FLT_MAX, hh_max = 0;
      for (int i = 0; i < 5; i++) {
          if (top5[i].count > 0) {
              hh_sum += top5[i].count;
              if (top5[i].count > hh_max) hh_max = top5[i].count;
              if (top5[i].count < hh_min) hh_min = top5[i].count;
          }
      }
      current->hh_total_pps = hh_sum;
      current->hh_pps_spread = (hh_min > 0) ? hh_max / hh_min : 0;
      uint64_t total = octosketch_get_total(sk);
      current->top5_concentration = (total > 0) ? hh_sum / total : 0;

      /* Cross-scale ratios */
      // Ya tienes top_ip_pps_1s y top_ip_pps_1min calculados
      struct heavy_hitter top_10s[1];
      octosketch_top_k(&g_merged_multiscale.sketch_10s, 1, top_10s);
      float top_10s_pps = (top_10s[0].count > 0) ?
          (float)top_10s[0].count / 10.0f : 0;

      current->ratio_1s_10s = (top_10s_pps > 0) ?
          current->top_ip_pps_1s / top_10s_pps : 1.0f;
      current->ratio_10s_1min = (current->top_ip_pps_1min > 0) ?
          top_10s_pps / current->top_ip_pps_1min : 1.0f;
  }

  c) Llamar la nueva función en el coordinador (línea ~1348):

  calculate_multiscale_features(&current_window, window_sec);
  calculate_extended_sketch_features(&current_window);  /* NEW */

  d) Loguear los nuevos valores en la sección de log (línea ~1845), para que feature_extractor.py los pueda parsear.

  e) Actualizar feature_extractor.py con los nuevos regex patterns para las nuevas features.

  Total: ~9 features nuevas de sketch, sin crear ningún sketch nuevo. Solo extraes más información de lo que ya tienes en memoria.

  Las features de 56 pasarían a ~65.

  ---
  Fase 3: Sketches por protocolo

  Aquí es donde se crea un segundo nivel de granularidad. En vez de un solo sketch que cuenta "paquetes de la IP X", creas sketches separados por protocolo.

  Cambios en mira_ddos_detector.c:

  a) Nuevas estructuras por worker (línea ~514):

  /* Per-protocol sketches - por worker (sin atomics) */
  static struct octosketch g_worker_sketch_udp[NUM_RX_QUEUES] __rte_cache_aligned;
  static struct octosketch g_worker_sketch_tcp[NUM_RX_QUEUES] __rte_cache_aligned;
  static struct octosketch g_worker_sketch_syn[NUM_RX_QUEUES] __rte_cache_aligned;
  static struct octosketch g_worker_sketch_dns[NUM_RX_QUEUES] __rte_cache_aligned;

  /* Merged per-protocol sketches (coordinator) */
  static struct octosketch g_merged_sketch_udp __rte_cache_aligned;
  static struct octosketch g_merged_sketch_tcp __rte_cache_aligned;
  static struct octosketch g_merged_sketch_syn __rte_cache_aligned;
  static struct octosketch g_merged_sketch_dns __rte_cache_aligned;

  Coste de memoria:
  4 nuevos sketches × 14 workers = 56 sketches nuevos
  sizeof(octosketch) ≈ 656 KB
  56 × 656 KB ≈ 36 MB adicionales
  Total: ~45 MB actual + 36 MB = ~81 MB (viable con hugepages de DPDK)

  b) Update en el worker loop (línea ~2279), dentro del bloque de sampling que ya existe:

  /* Donde ya haces: */
  octosketch_update_ip(my_sketch, src_ip, SKETCH_SAMPLE_RATE);

  /* Añadir DEBAJO, dentro del mismo if (sample): */
  if (proto == IPPROTO_UDP) {
      octosketch_update_ip(&g_worker_sketch_udp[queue_id], src_ip, SKETCH_SAMPLE_RATE);
  } else if (proto == IPPROTO_TCP) {
      octosketch_update_ip(&g_worker_sketch_tcp[queue_id], src_ip, SKETCH_SAMPLE_RATE);
      if (is_syn) {
          octosketch_update_ip(&g_worker_sketch_syn[queue_id], src_ip, SKETCH_SAMPLE_RATE);
      }
  }
  if (is_dns) {  /* ya tienes esta flag calculada arriba en el worker */
      octosketch_update_ip(&g_worker_sketch_dns[queue_id], src_ip, SKETCH_SAMPLE_RATE);
  }

  Overhead CPU: ~4 hash computations extra (ya estás en slow-path de sampling, que solo entra 1/N paquetes). El coste real es mínimo porque los updates son O(1) y el sampling ya filtra ~99% de   
  paquetes.

  c) Merge en el coordinator (línea ~1246):

  /* Donde ya haces merge del sketch general, añadir: */
  struct octosketch *udp_sketches[NUM_RX_QUEUES];
  struct octosketch *tcp_sketches[NUM_RX_QUEUES];
  struct octosketch *syn_sketches[NUM_RX_QUEUES];
  struct octosketch *dns_sketches[NUM_RX_QUEUES];
  for (int i = 0; i < NUM_RX_QUEUES; i++) {
      udp_sketches[i] = &g_worker_sketch_udp[i];
      tcp_sketches[i] = &g_worker_sketch_tcp[i];
      syn_sketches[i] = &g_worker_sketch_syn[i];
      dns_sketches[i] = &g_worker_sketch_dns[i];
  }
  octosketch_merge(&g_merged_sketch_udp, udp_sketches, NUM_RX_QUEUES);
  octosketch_merge(&g_merged_sketch_tcp, tcp_sketches, NUM_RX_QUEUES);
  octosketch_merge(&g_merged_sketch_syn, syn_sketches, NUM_RX_QUEUES);
  octosketch_merge(&g_merged_sketch_dns, dns_sketches, NUM_RX_QUEUES);

  d) Nuevas features de los sketches por protocolo:

  /* En feature_window, añadir: */
  float sketch_udp_concentration;   /* top1_udp / total_udp */
  float sketch_udp_heavy_hitters;   /* IPs con >threshold UDP pps */
  float sketch_udp_top_pps;         /* Top IP por UDP */
  float sketch_syn_concentration;
  float sketch_syn_heavy_hitters;
  float sketch_syn_top_pps;
  float sketch_tcp_concentration;
  float sketch_dns_concentration;
  float sketch_dns_heavy_hitters;
  float sketch_dns_top_pps;
  float sketch_proto_diversity;     /* Cuántos proto-sketches tienen HH activos */
  float sketch_udp_tcp_ratio;       /* total_udp_sketch / total_tcp_sketch */

  Esto te da ~12 features nuevas de los sketches por protocolo. Total pasaría a ~77 features.

  e) Reset de los sketches por protocolo al final de la ventana (línea ~1390):

  for (int i = 0; i < NUM_RX_QUEUES; i++) {
      octosketch_reset(&g_worker_sketch_attack[i]);
      octosketch_reset(&g_worker_sketch_udp[i]);   /* NEW */
      octosketch_reset(&g_worker_sketch_tcp[i]);    /* NEW */
      octosketch_reset(&g_worker_sketch_syn[i]);    /* NEW */
      octosketch_reset(&g_worker_sketch_dns[i]);    /* NEW */
  }

  ---
  Ablation Study final (repetir Fase 1 con las features nuevas)

  Con las ~77 features totales, ahora tienes 4 grupos para comparar:
  ┌────────┬─────────────────────────────────┬──────────────────┬─────────────────────────────────────────┐
  │ Modelo │            Features             │       Num        │                Hipótesis                │
  ├────────┼─────────────────────────────────┼──────────────────┼─────────────────────────────────────────┤
  │ A      │ DPI solo                        │ 42               │ Baseline DPI                            │
  ├────────┼─────────────────────────────────┼──────────────────┼─────────────────────────────────────────┤
  │ B      │ Sketch genérico                 │ 14 original      │ Sketch actual (pobre multi-clase)       │
  ├────────┼─────────────────────────────────┼──────────────────┼─────────────────────────────────────────┤
  │ C      │ Sketch ampliado + por protocolo │ 14 + 9 + 12 = 35 │ ¿Puede el sketch solo competir con DPI? │
  ├────────┼─────────────────────────────────┼──────────────────┼─────────────────────────────────────────┤
  │ D      │ DPI + Sketch ampliado completo  │ 77               │ ¿Mejora sobre el baseline actual?       │
  └────────┴─────────────────────────────────┴──────────────────┴─────────────────────────────────────────┘
  La tabla que publicarías:
  ┌───────────────────┬──────────┬───────────────┬────────────┬───────────────┬───────────────────┐
  │      Modelo       │ Accuracy │ F1 (weighted) │ F1 (macro) │ Benign recall │ WebDDoS precision │
  ├───────────────────┼──────────┼───────────────┼────────────┼───────────────┼───────────────────┤
  │ A (DPI)           │ 99.14%   │ 0.992         │ 0.99       │ 0.95          │ 0.90              │
  ├───────────────────┼──────────┼───────────────┼────────────┼───────────────┼───────────────────┤
  │ B (Sketch 14)     │ ¿?       │ ¿?            │ ¿?         │ ¿?            │ ¿?                │
  ├───────────────────┼──────────┼───────────────┼────────────┼───────────────┼───────────────────┤
  │ C (Sketch 35)     │ ¿?       │ ¿?            │ ¿?         │ ¿?            │ ¿?                │
  ├───────────────────┼──────────┼───────────────┼────────────┼───────────────┼───────────────────┤
  │ D (DPI+Sketch 77) │ ¿?       │ ¿?            │ ¿?         │ ¿?            │ ¿?                │
  └───────────────────┴──────────┴───────────────┴────────────┴───────────────┴───────────────────┘
  ---
  Resumen: qué tocar en cada fase
  ┌────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────┬────────────┐
  │  Fase  │                                             Archivos a modificar                                              │  Esfuerzo  │
  ├────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Fase 1 │ 1 archivo Python nuevo (ablation_study.py)                                                                    │ ~2 horas   │
  ├────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Fase 2 │ mira_ddos_detector.c (struct + función + log) + feature_extractor.py (nuevos regex)                           │ ~4-6 horas │
  ├────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────┼────────────┤
  │ Fase 3 │ mira_ddos_detector.c (sketches + merge + reset + features) + feature_extractor.py + rehacer ablation_study.py │ ~6-8 horas │
  └────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────┴────────────┘
  La Fase 1 la puedes hacer inmediatamente con los datos que ya tienes. Las Fases 2 y 3 requieren recompilar el detector, re-ejecutar los experimentos en CloudLab, y reentrenar los modelos. 