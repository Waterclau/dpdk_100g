# Mejoras del Detector MIRA - Febrero 2026

## Resumen Ejecutivo

Se han implementado tres mejoras principales al detector:

1. **Ring Buffer** - Análisis temporal sin I/O a disco
2. **Multi-Scale Sketches** - Detección a múltiples escalas temporales
3. **Detección Adaptativa** - Thresholds que se ajustan al baseline real

---

## 1. Arquitectura Anterior vs Nueva

### Antes (Solo Thresholds Fijos)

```
┌─────────────────────────────────────────────────────────────┐
│  Paquete → Contadores → if (pps > 20000) → ALERTA          │
│                                                             │
│  Problemas:                                                 │
│  - Thresholds fijos (¿y si el baseline es 18000?)          │
│  - No detecta tendencias (ataque escalando)                │
│  - No distingue ráfagas de ataques sostenidos              │
│  - Log a disco = I/O bloqueante                            │
└─────────────────────────────────────────────────────────────┘
```

### Ahora (Ring Buffer + Multi-Scale + Adaptativo)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │  Sketch     │     │  Sketch     │     │  Sketch     │               │
│  │  50ms       │     │  1s         │     │  1min       │               │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘               │
│         │                   │                   │                       │
│         └───────────────────┼───────────────────┘                       │
│                             │                                           │
│                             ▼                                           │
│                    ┌─────────────────┐                                  │
│                    │  RING BUFFER    │                                  │
│                    │  (100 ventanas) │                                  │
│                    └────────┬────────┘                                  │
│                             │                                           │
│         ┌───────────────────┼───────────────────┐                       │
│         │                   │                   │                       │
│         ▼                   ▼                   ▼                       │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐               │
│  │  Threshold  │     │  Adaptive   │     │  Trend      │               │
│  │  Fijo       │     │  (3-sigma)  │     │  Detection  │               │
│  └─────────────┘     └─────────────┘     └─────────────┘               │
│                             │                                           │
│                             ▼                                           │
│                      ┌─────────────┐                                    │
│                      │  56 Features│ → ML (LightGBM)                   │
│                      └─────────────┘                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Ring Buffer - Análisis Temporal

### Estructura

```c
#define RING_BUFFER_SIZE 100  // 100 ventanas × 50ms = 5 segundos

struct ring_buffer {
    struct feature_window windows[100];  // Historial circular
    uint32_t write_idx;                  // Índice de escritura
    double sum_pps, sum_pps_sq;          // Para cálculo de varianza
};
```

### Funcionamiento

```
Tiempo →  [t-99][t-98]...[t-5][t-4][t-3][t-2][t-1][t-0]
              │                   │         │         │
              │                   │         │         └── Ventana actual
              │                   │         └──────────── Hace 50ms
              │                   └────────────────────── Hace 250ms
              └────────────────────────────────────────── Hace 5 segundos

Operaciones O(1):
  - ring_buffer_get(-5)  → Ventana de hace 250ms
  - ring_buffer_push()   → Añadir nueva ventana
  - Baseline = sum_pps / count
  - Varianza = (sum_pps_sq / count) - baseline²
```

### Features Temporales Derivadas

| Feature | Cálculo | Uso |
|---------|---------|-----|
| `delta_pps_5w` | pps[0] - pps[-5] | Tendencia 250ms |
| `delta_pps_10w` | pps[0] - pps[-10] | Tendencia 500ms |
| `pps_variance` | Varianza últimas 20 ventanas | Estabilidad |
| `pps_baseline` | Media móvil | Baseline adaptativo |
| `ratio_vs_baseline` | pps / baseline | Anomalía |

---

## 3. Multi-Scale Sketches

### Concepto

Mantener 4 sketches a diferentes escalas temporales para detectar ataques de cualquier duración:

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

### Estructura

```c
struct multiscale_sketches {
    struct octosketch sketch_50ms;    // Heavy-hitters instantáneos
    struct octosketch sketch_1s;      // Heavy-hitters último segundo
    struct octosketch sketch_10s;     // Heavy-hitters últimos 10s
    struct octosketch sketch_1min;    // Baseline de IPs
};
```

### Features Multi-Escala Derivadas

| Feature | Cálculo | Detecta |
|---------|---------|---------|
| `top_ip_pps_50ms` | Top1 count / 0.05s | Heavy-hitter instantáneo |
| `top_ip_pps_1s` | Top1 count / 1s | Heavy-hitter sostenido |
| `top_ip_pps_1min` | Top1 count / 60s | Baseline de atacante |
| `ratio_50ms_1min` | pps_50ms / pps_1min | **Burst detection** |
| `ip_concentration` | top1 / total | Ataque concentrado vs distribuido |

### Detección de Burst

```
Si ratio_50ms_1min > 5.0:
    → "IP X tiene 5x más actividad en 50ms que su promedio de 1min"
    → BURST DETECTADO (ataque comenzando)
```

---

## 4. Threshold Adaptativo (3-Sigma)

### Problema con Thresholds Fijos

```
Threshold fijo = 20,000 pps

Escenario A: Baseline = 500 pps
  → 5,000 pps es claramente un ataque (10x baseline)
  → Pero NO se detecta (< 20,000)

Escenario B: Baseline = 18,000 pps
  → 19,000 pps es tráfico normal
  → Pero casi dispara falsa alarma
```

### Solución: Threshold Adaptativo

```
threshold = baseline + 3 × stddev

Donde:
  baseline = media(últimas 100 ventanas)
  stddev = desviación_estándar(últimas 100 ventanas)

Ejemplo:
  baseline = 5,000 pps
  stddev = 1,000 pps
  threshold = 5,000 + 3×1,000 = 8,000 pps

  → 8,500 pps dispara alarma (> 8,000)
  → 7,000 pps es normal (< 8,000)
```

### Implementación

```c
static inline float calculate_adaptive_threshold(void)
{
    if (g_ring_buffer.count < 20) {
        return ATTACK_TOTAL_PPS_THRESHOLD;  // Fijo hasta tener datos
    }

    double mean = g_ring_buffer.sum_pps / g_ring_buffer.count;
    double variance = (g_ring_buffer.sum_pps_sq / g_ring_buffer.count) - (mean * mean);
    double stddev = sqrt(variance);

    return (float)(mean + 3.0 * stddev);
}
```

---

## 5. Nuevas Detecciones

### 5.1 Detección Adaptativa

```c
if (attack_pps > adaptive_threshold) {
    // ALERTA: PPS supera 3-sigma del baseline
    alert("ADAPTIVE: %.0f pps > %.0f (3σ)", attack_pps, adaptive_threshold);
}
```

### 5.2 Detección de Tendencia

```c
if (delta_pps_5w > 10000 && delta_pps_10w > 20000) {
    // ALERTA: Ataque escalando rápidamente
    alert("TREND: attack rising (+%.0f/250ms)", delta_pps_5w);
}
```

### 5.3 Detección de Burst

```c
if (ratio_50ms_1min > 5.0 && top_ip_pps_50ms > 1000) {
    // ALERTA: Spike súbito de una IP
    alert("BURST: %.1fx spike vs 1min baseline", ratio_50ms_1min);
}
```

---

## 6. Features Extendidas (42 → 56)

### Features Base (1-42)

| # | Feature | Tipo |
|---|---------|------|
| 1-10 | Contadores básicos | packets, bytes, tcp, udp, icmp, syn, http, dns, baseline, attack |
| 11-14 | Ratios básicos | udp/tcp, syn/total, baseline/attack, bytes/packet |
| 15-36 | Protocolos específicos | NTP, DNS, SNMP, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP |
| 37-42 | Ratios avanzados | amplification factors, query/response, fragmentation, syn/ack |

### Features Temporales (43-47) - DEL RING BUFFER

| # | Feature | Descripción |
|---|---------|-------------|
| 43 | `delta_pps_5w` | Cambio en 250ms |
| 44 | `delta_pps_10w` | Cambio en 500ms |
| 45 | `pps_variance` | Varianza (estabilidad) |
| 46 | `pps_baseline` | Media móvil |
| 47 | `ratio_vs_baseline` | Anomalía vs baseline |

### Features Multi-Escala (48-56) - DE LOS SKETCHES

| # | Feature | Descripción |
|---|---------|-------------|
| 48 | `top_ip_pps_50ms` | Top attacker (instantáneo) |
| 49 | `top_ip_pps_1s` | Top attacker (1 segundo) |
| 50 | `top_ip_pps_1min` | Top attacker (1 minuto) |
| 51 | `ratio_50ms_1min` | Burst ratio |
| 52 | `num_heavy_hitters` | IPs sobre threshold |
| 53 | `ip_concentration` | Top1 / total |
| 54 | `new_ips_ratio` | IPs nuevas (placeholder) |
| 55 | `attack_entropy` | 1 - concentration |
| 56 | `adaptive_threshold` | Threshold actual |

---

## 7. Uso de Memoria

| Componente | Tamaño | Descripción |
|------------|--------|-------------|
| Ring Buffer | ~19 KB | 100 ventanas × 188 bytes |
| Sketches base | ~10 MB | 15 sketches × 655 KB |
| Multi-scale | ~40 MB | 4 escalas × 15 sketches × 655 KB |
| **Total** | **~50 MB** | Aceptable para servidor |

---

## 8. Flujo de Detección Completo

```
┌─────────────────────────────────────────────────────────────────────────┐
│  WORKER (por cada paquete de ataque, sampled 1/32)                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  // Actualizar sketches originales                                      │
│  octosketch_update_ip(&sketch_attack, src_ip, 32);                     │
│                                                                         │
│  // Actualizar multi-scale sketches                                     │
│  octosketch_update_ip(&sketch_50ms, src_ip, 32);                       │
│  octosketch_update_ip(&sketch_1s, src_ip, 32);                         │
│  octosketch_update_ip(&sketch_10s, src_ip, 32);                        │
│  octosketch_update_ip(&sketch_1min, src_ip, 32);                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  COORDINATOR (cada 50ms)                                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. DETECCIÓN POR THRESHOLDS FIJOS                                     │
│     if (udp_pps > 20000) → UDP_FLOOD                                   │
│     if (syn_pps > 30000) → SYN_FLOOD                                   │
│     if (dns_amp_pps > 2000) → DNS_AMP                                  │
│     ...                                                                 │
│                                                                         │
│  2. MERGE MULTI-SCALE SKETCHES                                         │
│     merge_multiscale_sketches();                                       │
│                                                                         │
│  3. CALCULAR FEATURES TEMPORALES                                       │
│     calculate_temporal_features(&window);                              │
│     → delta_pps_5w, delta_pps_10w, variance, baseline                  │
│                                                                         │
│  4. CALCULAR FEATURES MULTI-ESCALA                                     │
│     calculate_multiscale_features(&window);                            │
│     → top_ip_pps per scale, burst ratio, concentration                 │
│                                                                         │
│  5. DETECCIÓN ADAPTATIVA                                               │
│     if (pps > baseline + 3*stddev) → ADAPTIVE_ALERT                    │
│                                                                         │
│  6. DETECCIÓN DE TENDENCIA                                             │
│     if (delta_5w > 10K && delta_10w > 20K) → TREND_ALERT              │
│                                                                         │
│  7. DETECCIÓN DE BURST                                                 │
│     if (ratio_50ms_1min > 5x) → BURST_ALERT                           │
│                                                                         │
│  8. GUARDAR EN RING BUFFER                                             │
│     ring_buffer_push(&window);  // 56 features                         │
│                                                                         │
│  9. RESET SKETCHES SEGÚN ESCALA                                        │
│     reset_multiscale_sketches_if_needed();                             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Comparación: Antes vs Después

| Aspecto | Antes | Después |
|---------|-------|---------|
| Features para ML | 42 | **56** |
| Thresholds | Fijos | **Fijos + Adaptativos** |
| Detección temporal | No | **Sí (tendencias)** |
| Detección burst | No | **Sí (ratio 50ms/1min)** |
| Escalas temporales | 1 (50ms) | **4 (50ms, 1s, 10s, 1min)** |
| I/O a disco | Sí (log) | **Opcional (ring buffer)** |
| Heavy-hitters | 1 escala | **4 escalas** |

---

## 10. Archivos Modificados

| Archivo | Cambios |
|---------|---------|
| `mira_ddos_detector.c` | +400 líneas (ring buffer, multi-scale, detecciones) |
| `octosketch.h` | +1 array `ip_addrs[65536]` para IPs reales |

---

## 11. Compilación

```bash
# En CloudLab (nodo monitor)
cd /path/to/detector_system
make clean && make

# Verificar que compila sin errores
./mira_detector --help
```

---

## 12. Trabajo Futuro

1. **Online Learning** - Actualizar modelo ML en tiempo real
2. **Exportar ring buffer** - Dump periódico para reentrenamiento
3. **Optimizar memoria** - Reducir tamaño de sketches si es necesario
4. **Features adicionales** - Tracking de IPs nuevas, entropía real

┌─────────────────────────────────────────────────────────────────────────┐ 
  │  SIN BASELINE (solo ataque):                                            │
  │                                                                         │
  │  Ring Buffer: [atk][atk][atk][atk][atk]...                             │
  │  Baseline calculado = promedio(ataque) = 50,000 pps                    │
  │  Adaptive threshold = 50,000 + 3σ = 53,000 pps                         │
  │                                                                         │
  │  → El ataque de 50K pps NO se detecta (está bajo el threshold)         │
  │  → Los deltas son ~0 (no hay cambio)                                   │
  │  → ratio_vs_baseline ≈ 1.0 (no hay anomalía)                           │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │  CON BASELINE (benigno + ataque):                                       │
  │                                                                         │
  │  Ring Buffer: [ben][ben][ben][atk][atk][atk]...                        │
  │  Baseline calculado = promedio(benigno) = 2,000 pps                    │
  │  Adaptive threshold = 2,000 + 3σ = 5,000 pps                           │
  │                                                                         │
  │  → El ataque de 50K pps SÍ se detecta (>> 5,000)                       │
  │  → delta_pps = +48,000 (cambio enorme)                                 │
  │  → ratio_vs_baseline = 25x (anomalía clara)                            │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ---
  Plan Experimental Completo

  Estructura de Cada Run

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                          ESTRUCTURA DE UN RUN                           │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Tiempo:    0s ──────── 60s ──────── 120s ──────── 180s                │
  │             │           │            │             │                    │
  │             ▼           ▼            ▼             ▼                    │
  │                                                                         │
  │  Baseline:  ████████████████████████████████████████                   │
  │             (Controller envía benigno TODO el tiempo)                  │
  │                                                                         │
  │  Ataque:                ████████████████████                            │
  │                         (TG envía ataque del segundo 60 al 120)        │
  │                                                                         │
  │  Fases:     [BASELINE]  [MIXED]      [RECOVERY]                        │
  │             calibrar    ataque       post-ataque                        │
  │             ring buffer + benigno                                       │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  Runs Necesarios
  ┌───────────────┬─────────┬───────────────────────────────────────┐
  │     Tipo      │  Runs   │              Descripción              │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ Pure Baseline │ 4       │ Solo tráfico benigno (clase "benign") │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ Mixed         │ 4       │ Benigno + múltiples ataques mezclados │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ UDP Flood     │ 4       │ Benigno + UDP flood                   │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ SYN Flood     │ 4       │ Benigno + SYN flood                   │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ ICMP Flood    │ 4       │ Benigno + ICMP flood                  │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ DNS Amp       │ 4       │ Benigno + DNS amplification           │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ NTP Amp       │ 4       │ Benigno + NTP amplification           │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ SNMP Amp      │ 4       │ Benigno + SNMP amplification          │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ SSDP          │ 4       │ Benigno + SSDP                        │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ PortMap       │ 4       │ Benigno + PortMap                     │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ NetBIOS       │ 4       │ Benigno + NetBIOS                     │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ LDAP          │ 4       │ Benigno + LDAP                        │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ MSSQL         │ 4       │ Benigno + MSSQL                       │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ TFTP          │ 4       │ Benigno + TFTP                        │
  ├───────────────┼─────────┼───────────────────────────────────────┤
  │ Total         │ 56 runs │ ~3 horas de captura                   │
  └───────────────┴─────────┴───────────────────────────────────────┘
  ---
  Script de Experimento

  #!/bin/bash
  # experiment_plan.sh
  # Ejecutar desde el nodo de control (o tu laptop con SSH)

  MONITOR="monitor.cloudlab.us"
  CONTROLLER="controller.cloudlab.us"
  TG="tg.cloudlab.us"

  DETECTOR_PATH="/path/to/mira/detector_system"
  SENDER_PATH="/path/to/mira/senders"
  PCAP_PATH="/path/to/mira/pcaps"
  OUTPUT_PATH="/path/to/mira/data/feb_experiment"

  BASELINE_RATE=2000      # pps de tráfico benigno
  ATTACK_RATE=10000       # pps de tráfico de ataque
  BASELINE_DURATION=180   # segundos totales
  ATTACK_START=60         # segundo en que empieza el ataque
  ATTACK_DURATION=60      # duración del ataque

  ATTACKS=("udp_flood" "syn_flood" "icmp_flood" "dns_amp" "ntp_amp"
           "snmp_amp" "ssdp" "portmap" "netbios" "ldap" "mssql" "tftp")

  # Función para ejecutar un run
  run_experiment() {
      local attack_type=$1
      local run_number=$2
      local session_name="${attack_type}_run${run_number}"

      echo "=========================================="
      echo "Starting: $session_name"
      echo "=========================================="

      # 1. Iniciar detector en Monitor
      echo "[1/4] Starting detector..."
      ssh $MONITOR "cd $DETECTOR_PATH && \
          sudo ./mira_detector -l 0-15 -n 4 -- -p 0x1 \
          --log ${OUTPUT_PATH}/${session_name}.log" &
      DETECTOR_PID=$!
      sleep 5

      # 2. Iniciar tráfico benigno en Controller (TODO el tiempo)
      echo "[2/4] Starting baseline traffic..."
      ssh $CONTROLLER "cd $SENDER_PATH && \
          sudo ./benign_sender -l 0-1 -n 4 -- \
          --pcap ${PCAP_PATH}/benign_mixed.pcap \
          --rate $BASELINE_RATE \
          --duration $BASELINE_DURATION" &
      BASELINE_PID=$!

      # 3. Esperar fase de calibración (60s de solo baseline)
      echo "[3/4] Calibration phase (${ATTACK_START}s)..."
      sleep $ATTACK_START

      # 4. Iniciar ataque (si no es pure baseline)
      if [ "$attack_type" != "baseline" ]; then
          echo "[4/4] Starting attack: $attack_type..."
          ssh $TG "cd $SENDER_PATH && \
              sudo ./attack_sender -l 0-3 -n 4 -- \
              --pcap ${PCAP_PATH}/${attack_type}.pcap \
              --rate $ATTACK_RATE \
              --duration $ATTACK_DURATION"
      else
          echo "[4/4] Pure baseline - no attack"
          sleep $ATTACK_DURATION
      fi

      # 5. Esperar fase de recovery (60s post-ataque)
      echo "Recovery phase..."
      sleep 60

      # 6. Detener todo
      echo "Stopping..."
      ssh $MONITOR "sudo pkill -f mira_detector" 2>/dev/null
      ssh $CONTROLLER "sudo pkill -f benign_sender" 2>/dev/null

      # 7. Verificar log
      echo "Verifying log..."
      ssh $MONITOR "wc -l ${OUTPUT_PATH}/${session_name}.log"

      echo "Completed: $session_name"
      echo ""
      sleep 5  # Pausa entre runs
  }

  # ============ EJECUTAR EXPERIMENTO ============

  mkdir -p $OUTPUT_PATH

  echo "============================================"
  echo "MIRA Experiment - February 2026"
  echo "============================================"
  echo ""

  # Pure Baseline (4 runs)
  echo ">>> PHASE 1: Pure Baseline <<<"
  for run in 1 2 3 4; do
      run_experiment "baseline" $run
  done

  # Mixed attacks (4 runs)
  echo ">>> PHASE 2: Mixed Attacks <<<"
  for run in 1 2 3 4; do
      run_experiment "mixed" $run
  done

  # Individual attacks (4 runs each)
  echo ">>> PHASE 3: Individual Attacks <<<"
  for attack in "${ATTACKS[@]}"; do
      echo "--- Attack type: $attack ---"
      for run in 1 2 3 4; do
          run_experiment $attack $run
      done
  done

  echo "============================================"
  echo "EXPERIMENT COMPLETE"
  echo "Logs saved to: $OUTPUT_PATH"
  echo "============================================"

  ---
  Diagrama Temporal de un Run

  Tiempo (segundos)
      0         30        60        90        120       150       180
      │         │         │         │         │         │         │
      ▼         ▼         ▼         ▼         ▼         ▼         ▼

      ├─────────────────────────────────────────────────────────────┤
      │                    BASELINE (benigno)                       │
      │  Controller envía 2,000 pps durante TODO el run             │
      ├─────────────────────────────────────────────────────────────┤

                          ├─────────────────────┤
                          │      ATAQUE         │
                          │  TG envía 10K pps   │
                          │  (solo 60-120s)     │
                          ├─────────────────────┤

      │◄─── CALIBRACIÓN ──►│◄───── MIXED ──────►│◄─── RECOVERY ───►│
      │   Ring buffer se    │  Ataque + Benigno  │  Solo benigno    │
      │   llena con normal  │  Labels: attack    │  Labels: benign  │
      │   Labels: benign    │                    │                  │

      Ventanas: 0-1200       1200-2400            2400-3600
                (benign)     (attack_type)        (benign)

  ---
  Etiquetado Automático

  El detector etiqueta automáticamente por IP de origen:

  // En el detector
  #define BASELINE_NETWORK 0x0A0A0200  // 10.10.2.x → label: benign
  #define ATTACK_NETWORK   0x0A0A0300  // 10.10.3.x → label: attack_type

  // Las ventanas se etiquetan según qué tráfico predomina

  Etiquetas en el log:
  ┌──────────┬───────────┬─────────────────────────────────┐
  │   Fase   │ Ventanas  │            Etiqueta             │
  ├──────────┼───────────┼─────────────────────────────────┤
  │ 0-60s    │ 0-1200    │ benign                          │
  ├──────────┼───────────┼─────────────────────────────────┤
  │ 60-120s  │ 1200-2400 │ udp_flood (o el tipo de ataque) │
  ├──────────┼───────────┼─────────────────────────────────┤
  │ 120-180s │ 2400-3600 │ benign                          │
  └──────────┴───────────┴─────────────────────────────────┘
  ---
  Resumen del Plan

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  PLAN DE EXPERIMENTO - 56 RUNS TOTALES                                  │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  1. BASELINE PURO (4 runs)                                             │
  │     - Solo Controller enviando benigno                                  │
  │     - 180 segundos por run                                              │
  │     - Clase: "benign"                                                   │
  │                                                                         │
  │  2. MIXED (4 runs)                                                      │
  │     - Controller: benigno (0-180s)                                      │
  │     - TG: múltiples ataques (60-120s)                                  │
  │     - Clase: "mixed"                                                    │
  │                                                                         │
  │  3. ATAQUES INDIVIDUALES (12 tipos × 4 runs = 48 runs)                 │
  │     - Controller: benigno (0-180s) ← SIEMPRE                           │
  │     - TG: ataque específico (60-120s)                                  │
  │     - Clase: nombre del ataque                                          │
  │                                                                         │
  │  TOTAL: 56 runs × 180s = 2.8 horas de captura                          │
  │  Datos: ~3600 ventanas × 56 runs = 201,600 muestras                    │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ---
  Respuesta Directa a tu Pregunta

  Sí, debes correr el baseline con cada ataque porque:

  1. Threshold adaptativo necesita saber qué es "normal"
  2. Delta/tendencias necesitan ver el cambio de normal → ataque
  3. Multi-scale sketches necesitan baseline en el sketch de 1min
  4. Es más realista - en producción siempre hay tráfico legítimo

✻ Churned for 1m 5s      

❯ Vale pero antes las runs eran cada una de 900 segunodos el monitor y 895 los otros pero claro habra que adapatar el plan para los umbrales                                                                                                                                                                                                                                                        
● Tienes razón, con runs de 900 segundos (15 minutos) hay que adaptar el plan. El ring buffer solo guarda 5 segundos, así que la fase de calibración no necesita ser muy larga, pero sí necesita estar presente.                                                
  
  ---                                                                                                                                                                                                                                                             Plan Adaptado para Runs de 900 segundos
                                                                                                                                                                                                                                                                
  Estructura de un Run (900s total)

  Tiempo (segundos)
      0         120       300                            895   900
      │         │         │                              │     │
      ▼         ▼         ▼                              ▼     ▼

      ├─────────────────────────────────────────────────────────┤
      │           BASELINE (Controller - 895s)                  │
      │           benigno desde 0s hasta 895s                   │
      ├─────────────────────────────────────────────────────────┤

                          ├──────────────────────────────┤
                          │         ATAQUE (TG)          │
                          │    desde 300s hasta 895s     │
                          │        (595 segundos)        │
                          ├──────────────────────────────┤

      │◄── CALIBRACIÓN ──►│◄────────── MIXED ───────────►│
      │    (0-300s)        │       (300-895s)             │
      │    Solo benigno    │    Benigno + Ataque          │
      │    Ring buffer     │    Detección activa          │
      │    se calibra      │                              │

  ¿Por qué 300 segundos de calibración?

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  CALIBRACIÓN DEL THRESHOLD ADAPTATIVO                                   │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  Ring buffer = 100 ventanas × 50ms = 5 segundos de historial           │
  │                                                                         │
  │  Pero el threshold adaptativo usa:                                      │
  │    - sum_pps (suma acumulada)                                          │
  │    - sum_pps_sq (suma de cuadrados)                                    │
  │    - Estas se actualizan CADA VENTANA                                  │
  │                                                                         │
  │  Con 300s de baseline:                                                  │
  │    - 6000 ventanas de datos "normales"                                 │
  │    - Media y varianza muy estables                                      │
  │    - El sketch de 1min tiene 5 resets completos                        │
  │                                                                         │
  │  Mínimo recomendado: 120 segundos (2400 ventanas)                      │
  │  Óptimo: 300 segundos (6000 ventanas)                                  │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ---
  Script Adaptado (900 segundos)

  #!/bin/bash
  # experiment_900s.sh

  MONITOR="monitor.cloudlab.us"
  CONTROLLER="controller.cloudlab.us"
  TG="tg.cloudlab.us"

  DETECTOR_PATH="/path/to/mira/detector_system"
  SENDER_PATH="/path/to/mira/senders"
  PCAP_PATH="/path/to/mira/pcaps"
  OUTPUT_PATH="/path/to/mira/data/feb_experiment"

  # Tiempos (en segundos)
  MONITOR_DURATION=900    # Detector corre 900s
  SENDER_DURATION=895     # Senders corren 895s (5s menos)
  CALIBRATION_TIME=300    # 5 minutos de calibración (solo baseline)
  ATTACK_DURATION=595     # Ataque desde 300s hasta 895s

  BASELINE_RATE=2000      # pps benigno
  ATTACK_RATE=10000       # pps ataque

  ATTACKS=("udp_flood" "syn_flood" "icmp_flood" "dns_amp" "ntp_amp"
           "snmp_amp" "ssdp" "portmap" "netbios" "ldap" "mssql" "tftp")

  run_experiment() {
      local attack_type=$1
      local run_number=$2
      local session_name="${attack_type}_run${run_number}"

      echo "=========================================="
      echo "Starting: $session_name (900s run)"
      echo "=========================================="

      # 1. Iniciar detector (900 segundos)
      echo "[1/4] Starting detector (${MONITOR_DURATION}s)..."
      ssh $MONITOR "cd $DETECTOR_PATH && \
          nohup sudo ./mira_detector -l 0-15 -n 4 -- -p 0x1 \
          --log ${OUTPUT_PATH}/${session_name}.log \
          > /dev/null 2>&1 &"
      sleep 5

      # 2. Iniciar baseline (895 segundos, empieza en t=0)
      echo "[2/4] Starting baseline (${SENDER_DURATION}s)..."
      ssh $CONTROLLER "cd $SENDER_PATH && \
          nohup sudo ./benign_sender -l 0-1 -n 4 -- \
          --pcap ${PCAP_PATH}/benign_mixed.pcap \
          --rate $BASELINE_RATE \
          --duration $SENDER_DURATION \
          > /dev/null 2>&1 &"

      # 3. Esperar calibración (300 segundos de solo baseline)
      echo "[3/4] Calibration phase (${CALIBRATION_TIME}s of pure baseline)..."
      echo "      Ring buffer filling with normal traffic..."
      echo "      Adaptive threshold calibrating..."
      sleep $CALIBRATION_TIME

      # 4. Iniciar ataque (si no es pure baseline)
      if [ "$attack_type" != "baseline" ]; then
          echo "[4/4] Starting attack: $attack_type (${ATTACK_DURATION}s)..."
          ssh $TG "cd $SENDER_PATH && \
              sudo ./attack_sender -l 0-3 -n 4 -- \
              --pcap ${PCAP_PATH}/${attack_type}.pcap \
              --rate $ATTACK_RATE \
              --duration $ATTACK_DURATION"
      else
          echo "[4/4] Pure baseline run - waiting ${ATTACK_DURATION}s..."
          sleep $ATTACK_DURATION
      fi

      # 5. Esperar a que termine el detector
      echo "Waiting for detector to finish..."
      sleep 10

      # 6. Detener todo (por si acaso)
      ssh $MONITOR "sudo pkill -f mira_detector" 2>/dev/null
      ssh $CONTROLLER "sudo pkill -f benign_sender" 2>/dev/null

      # 7. Verificar log
      echo "Verifying log..."
      LINES=$(ssh $MONITOR "wc -l < ${OUTPUT_PATH}/${session_name}.log")
      echo "  Log lines: $LINES (expected ~18000)"

      echo "Completed: $session_name"
      echo ""
      sleep 10  # Pausa entre runs
  }

  # ============ MAIN ============

  mkdir -p $OUTPUT_PATH

  echo "============================================"
  echo "MIRA Experiment - February 2026"
  echo "900 second runs with adaptive thresholds"
  echo "============================================"

  # Baseline puro (4 runs)
  for run in 1 2 3 4; do
      run_experiment "baseline" $run
  done

  # Mixed (4 runs)
  for run in 1 2 3 4; do
      run_experiment "mixed" $run
  done

  # Ataques individuales (12 × 4 = 48 runs)
  for attack in "${ATTACKS[@]}"; do
      for run in 1 2 3 4; do
          run_experiment "$attack" $run
      done
  done

  echo "============================================"
  echo "EXPERIMENT COMPLETE"
  echo "Total runs: 56"
  echo "============================================"

  ---
  Diagrama de Fases (900 segundos)

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                        RUN DE 900 SEGUNDOS                              │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  MONITOR (Detector):                                                    │
  │  ════════════════════════════════════════════════════════════════════  │
  │  0s                                                              900s   │
  │  │◄─────────────────────── 900 segundos ─────────────────────────►│    │
  │                                                                         │
  │  CONTROLLER (Baseline):                                                 │
  │  ═══════════════════════════════════════════════════════════════════   │
  │  0s                                                         895s        │
  │  │◄───────────────────── 895 segundos ──────────────────────►│         │
  │                                                                         │
  │  TG (Ataque):                                                           │
  │                    ═══════════════════════════════════════════          │
  │                    300s                                  895s           │
  │                    │◄────────── 595 segundos ───────────►│             │
  │                                                                         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                                                                         │
  │  FASES:                                                                 │
  │                                                                         │
  │  │◄──── CALIBRACIÓN ────►│◄─────────── ATAQUE + BASELINE ──────────►│  │
  │  │      (0 - 300s)        │            (300 - 895s)                  │  │
  │  │                        │                                          │  │
  │  │  - Solo benigno        │  - Benigno continúa                     │  │
  │  │  - Ring buffer se      │  - Ataque se suma                       │  │
  │  │    llena               │  - Detección activa                     │  │
  │  │  - Threshold se        │  - Features temporales                  │  │
  │  │    calibra             │    detectan el cambio                   │  │
  │  │  - Baseline de 1min    │  - Burst ratio alto                     │  │
  │  │    se establece        │                                          │  │
  │  │                        │                                          │  │
  │  │  Labels: "benign"      │  Labels: "attack_type"                  │  │
  │  │  Ventanas: 0-6000      │  Ventanas: 6000-17900                   │  │
  │                                                                         │
  └─────────────────────────────────────────────────────────────────────────┘

  ---
  Ventanas por Fase
  ┌─────────────┬────────────┬─────────────────┬─────────────┐
  │    Fase     │   Tiempo   │ Ventanas (50ms) │  Etiqueta   │
  ├─────────────┼────────────┼─────────────────┼─────────────┤
  │ Calibración │ 0 - 300s   │ 0 - 6,000       │ benign      │
  ├─────────────┼────────────┼─────────────────┼─────────────┤
  │ Ataque      │ 300 - 895s │ 6,000 - 17,900  │ attack_type │
  ├─────────────┼────────────┼─────────────────┼─────────────┤
  │ Total       │ 900s       │ ~18,000         │ -           │
  └─────────────┴────────────┴─────────────────┴─────────────┘
  Por run: ~18,000 ventanas
  Total (56 runs): ~1,000,000 ventanas

  ---
  Qué pasa en cada fase

  Fase 1: Calibración (0-300s)

  Ring Buffer después de 300s:
  ┌─────────────────────────────────────────────────────────────┐
  │  [ben][ben][ben]...[ben][ben]  (100 ventanas de benigno)   │
  └─────────────────────────────────────────────────────────────┘

  Métricas:
    - baseline_pps = ~2,000 (tráfico benigno)
    - variance = baja (tráfico estable)
    - adaptive_threshold = 2,000 + 3σ ≈ 5,000 pps
    - delta_pps = ~0 (sin cambios)
    - ratio_50ms_1min = ~1.0 (sin bursts)

  Fase 2: Ataque (300-895s)

  Ring Buffer en t=305s (5s después de empezar ataque):
  ┌─────────────────────────────────────────────────────────────┐
  │  [ben]...[ben][MIX][MIX][MIX][ATK][ATK][ATK]               │
  └─────────────────────────────────────────────────────────────┘

  Métricas:
    - current_pps = ~12,000 (benigno + ataque)
    - baseline_pps = ~2,000 (histórico de calibración)
    - adaptive_threshold = 5,000 pps
    - delta_pps = +10,000 (cambio enorme vs 5s antes)
    - ratio_vs_baseline = 6x (muy alto)
    - ratio_50ms_1min = 5-10x (burst detectado)

  Alertas generadas:
    ✓ ADAPTIVE: 12,000 pps > 5,000 (3σ)
    ✓ TREND: attack rising (+10,000/250ms)
    ✓ BURST: 6x spike vs 1min baseline
    ✓ THRESHOLD: UDP pps > 20,000 (si aplica)

  ---
  Resumen
  ┌─────────────────────────────┬─────────────────────┐
  │          Parámetro          │        Valor        │
  ├─────────────────────────────┼─────────────────────┤
  │ Duración monitor            │ 900s                │
  ├─────────────────────────────┼─────────────────────┤
  │ Duración senders            │ 895s                │
  ├─────────────────────────────┼─────────────────────┤
  │ Calibración (solo baseline) │ 0 - 300s (5 min)    │
  ├─────────────────────────────┼─────────────────────┤
  │ Ataque + baseline           │ 300 - 895s (10 min) │
  ├─────────────────────────────┼─────────────────────┤
  │ Ventanas por run            │ ~18,000             │
  ├─────────────────────────────┼─────────────────────┤
  │ Runs totales                │ 56                  │
  ├─────────────────────────────┼─────────────────────┤
  │ Datos totales               │ ~1,000,000 ventanas │