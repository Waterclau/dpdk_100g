# Cómo Añadir ML al Detector Original

Este documento explica **EXACTAMENTE** qué cambiar en `detector_system/mira_ddos_detector.c` para crear la versión con ML.

## Paso 1: Copiar el Detector Original

```bash
cd /local/dpdk_100g/mira/detector_system_ml
cp ../detector_system/mira_ddos_detector.c ./mira_ddos_detector_ml.c
cp ../detector_system/octosketch.h ./
```

## Paso 2: Modificaciones en mira_ddos_detector_ml.c

### Modificación 1: Añadir include de ML (línea 44, después de #include "octosketch.h")

```c
#include "octosketch.h"
#include "ml_inference.h"  // ← AÑADIR ESTA LÍNEA
```

### Modificación 2: Añadir variable global de ML (línea 233, después de g_merged_sketch_attack)

```c
static struct octosketch g_merged_sketch_attack __rte_cache_aligned;

/* ======== ML INTEGRATION: Global model handle ======== */
static ml_model_handle g_ml_model = NULL;
#define ML_CONFIDENCE_THRESHOLD 0.75f
/* ===================================================== */

/* Sampling configuration */
```

### Modificación 3: Modificar detect_attacks() - Añadir ML (línea 306-498)

Reemplazar la función `detect_attacks()` completa con esta versión que incluye ML:

```c
static void detect_attacks(uint64_t cur_tsc, uint64_t hz)
{
    double elapsed = (double)(cur_tsc - g_stats.last_fast_detection_tsc) / hz;

    if (elapsed >= FAST_DETECTION_INTERVAL) {
        g_stats.last_fast_detection_tsc = cur_tsc;
        g_stats.alert_level = ALERT_NONE;
        memset(g_stats.alert_reason, 0, sizeof(g_stats.alert_reason));

        uint64_t window_duration = cur_tsc - g_stats.window_start_tsc;
        double window_sec = (double)window_duration / hz;

        if (window_sec < 0.1) return;

        bool attack_detected = false;

        /* AGGREGATE DETECTION - Use worker stats (exact counters) */
        uint64_t window_base_pkts = 0, window_att_pkts = 0;
        uint64_t window_syn_pkts = 0, window_udp_pkts = 0, window_icmp_pkts = 0;
        uint64_t window_http_reqs = 0, window_dns_queries = 0;
        uint64_t window_total_bytes = 0;

        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_base_pkts += window_baseline_pkts[i];
            window_att_pkts += window_attack_pkts[i];
            window_total_bytes += window_baseline_bytes[i] + window_attack_bytes[i];
        }

        /* Aggregate protocol stats from workers */
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_syn_pkts += g_worker_stats[i].syn_packets;
            window_udp_pkts += g_worker_stats[i].udp_packets;
            window_icmp_pkts += g_worker_stats[i].icmp_packets;
            window_http_reqs += g_worker_stats[i].http_requests;
            window_dns_queries += g_worker_stats[i].dns_queries;
        }

        uint64_t window_total_pkts = window_base_pkts + window_att_pkts;

        /* Calculate PPS rates */
        double attack_pps = (double)window_att_pkts / window_sec;
        double baseline_pps = (double)window_base_pkts / window_sec;
        double syn_pps = (double)window_syn_pkts / window_sec;
        double udp_pps = (double)window_udp_pkts / window_sec;
        double icmp_pps = (double)window_icmp_pkts / window_sec;
        double http_pps = (double)window_http_reqs / window_sec;

        /* ======== THRESHOLD DETECTION (mantener igual que original) ======== */
        bool threshold_alert = false;

        if (window_att_pkts > 0 && attack_pps > 50000) {
            if (udp_pps > 20000) {
                g_stats.udp_flood_detections++;
                g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "UDP FLOOD detected: %.0f UDP pps | ", udp_pps);
                threshold_alert = true;
            }

            if (syn_pps > 30000) {
                g_stats.syn_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "SYN FLOOD detected: %.0f SYN pps | ", syn_pps);
                threshold_alert = true;
            }

            if (icmp_pps > 10000) {
                g_stats.icmp_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "ICMP FLOOD detected: %.0f ICMP pps | ", icmp_pps);
                threshold_alert = true;
            }

            if (http_pps > 15000) {
                g_stats.http_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "HTTP FLOOD detected: %.0f HTTP rps | ", http_pps);
                threshold_alert = true;
            }

            int attack_types = 0;
            if (udp_pps > 10000) attack_types++;
            if (syn_pps > 10000) attack_types++;
            if (icmp_pps > 5000) attack_types++;

            if (attack_types >= 2 && !threshold_alert) {
                g_stats.total_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "MULTI-ATTACK detected: %.0f attack pps (%d attack types) | ",
                        attack_pps, attack_types);
                threshold_alert = true;
            }
        }

        /* ======== ML PREDICTION ======== */
        bool ml_alert = false;
        const char *ml_class_name = "unknown";
        float ml_confidence = 0.0f;
        struct ml_prediction ml_pred;

        if (g_ml_model != NULL && window_total_pkts > 100) {
            // Build features
            struct ml_features features;
            ml_build_features(&features,
                window_total_pkts, window_total_bytes,
                window_udp_pkts, g_worker_stats[0].tcp_packets /* aggregate todos */,
                window_icmp_pkts, window_syn_pkts, window_http_reqs,
                window_base_pkts, window_att_pkts);

            // Run prediction (LOCAL, in-process)
            int ret = ml_predict(g_ml_model, &features, &ml_pred);

            if (ret == 0) {
                ml_class_name = ml_get_class_name(ml_pred.predicted_class);
                ml_confidence = ml_pred.confidence;

                // ML detects attack if NOT benign and confidence high
                if (ml_pred.predicted_class != 0 && ml_confidence >= ML_CONFIDENCE_THRESHOLD) {
                    ml_alert = true;
                }
            }
        }

        /* ======== HYBRID DECISION ======== */
        attack_detected = threshold_alert || ml_alert;

        if (attack_detected) {
            // Determine alert priority
            const char *alert_type = "UNKNOWN";
            if (threshold_alert && ml_alert) {
                alert_type = "CRITICAL";  // Both agree
            } else if (threshold_alert && !ml_alert) {
                alert_type = "HIGH";      // Only thresholds
            } else if (!threshold_alert && ml_alert) {
                alert_type = "ANOMALY";   // Only ML
            }

            if (g_ml_model) {
                // Log ML prediction
                printf("\n[%s ALERT] ", alert_type);
                printf("Threshold: %s | ML: %s (%.2f%%)\n",
                       threshold_alert ? "DETECT" : "NONE",
                       ml_class_name, ml_confidence * 100);
            }
        }

        /* ======== Mantener tracking original de detecciones ======== */
        if (attack_detected) {
            g_stats.total_detection_events++;

            double current_latency_ms = 0.0;
            if (g_stats.first_attack_packet_tsc > 0) {
                uint64_t latency_cycles = cur_tsc - g_stats.first_attack_packet_tsc;
                current_latency_ms = (double)latency_cycles * 1000.0 / hz;
            }

            if (!g_stats.detection_triggered) {
                g_stats.first_detection_tsc = cur_tsc;
                g_stats.last_detection_tsc = cur_tsc;
                g_stats.detection_triggered = true;
                g_stats.packets_until_detection = g_stats.total_packets;
                g_stats.bytes_until_detection = g_stats.total_bytes;
                g_stats.detection_latency_ms = current_latency_ms;
                g_stats.min_detection_latency_ms = current_latency_ms;
                g_stats.max_detection_latency_ms = current_latency_ms;
                g_stats.sum_detection_latencies_ms = current_latency_ms;
            } else {
                uint64_t inter_detection_cycles = cur_tsc - g_stats.last_detection_tsc;
                double inter_detection_ms = (double)inter_detection_cycles * 1000.0 / hz;

                if (inter_detection_ms < g_stats.min_detection_latency_ms) {
                    g_stats.min_detection_latency_ms = inter_detection_ms;
                }
                if (inter_detection_ms > g_stats.max_detection_latency_ms) {
                    g_stats.max_detection_latency_ms = inter_detection_ms;
                }

                g_stats.sum_detection_latencies_ms += inter_detection_ms;

                if (inter_detection_ms < 20.0) {
                    g_stats.detections_under_20ms++;
                } else if (inter_detection_ms < 30.0) {
                    g_stats.detections_20_30ms++;
                } else if (inter_detection_ms < 40.0) {
                    g_stats.detections_30_40ms++;
                } else if (inter_detection_ms < 50.0) {
                    g_stats.detections_40_50ms++;
                } else {
                    g_stats.detections_over_50ms++;
                }

                g_stats.last_detection_tsc = cur_tsc;
            }
        }

        /* OctoSketch merge (mantener igual) */
        if (window_att_pkts > 0) {
            struct octosketch *worker_sketches[NUM_RX_QUEUES];
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                worker_sketches[i] = &g_worker_sketch_attack[i];
            }
            octosketch_merge(&g_merged_sketch_attack, worker_sketches, NUM_RX_QUEUES);
        }

        /* Reset detection window */
        if (window_sec >= DETECTION_WINDOW_SEC) {
            g_stats.window_start_tsc = cur_tsc;

            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                octosketch_reset(&g_worker_sketch_attack[i]);
            }
        }
    }
}
```

### Modificación 4: Cargar modelo en main() (línea 1226, después de inicializar OctoSketch)

```c
    printf("  Update policy:           Attack traffic only\n\n");

    /* ======== ML INTEGRATION: Load model ======== */
    printf("\n[ML] Loading machine learning model...\n");
    g_ml_model = ml_init("./lightgbm_model.txt");
    if (!g_ml_model) {
        printf("[ML] Warning: Model failed to load, continuing without ML\n");
    } else {
        printf("[ML] Model loaded successfully - ML-enhanced detection enabled\n");
    }
    /* ============================================= */

    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
```

### Modificación 5: Cleanup en signal_handler (línea 257, dentro de signal_handler)

```c
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);

        /* ======== ML INTEGRATION: Cleanup ======== */
        if (g_ml_model) {
            ml_cleanup(g_ml_model);
            g_ml_model = NULL;
        }
        /* ========================================= */

        force_quit = true;
    }
}
```

## Paso 3: Crear Makefile

Crear `detector_system_ml/Makefile`:

```makefile
# Detectar system
```bash
PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)

# ML integration
CFLAGS += -I/usr/local/include
LDFLAGS_SHARED += -L/usr/local/lib -l_lightgbm

# Source files
SRCS = mira_ddos_detector_ml.c ml_inference.c
OBJS = $(SRCS:.c=.o)

TARGET = mira_ddos_detector_ml

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS_SHARED)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
```

## Paso 4: Compilar

```bash
cd /local/dpdk_100g/mira/detector_system_ml
make clean
make
```

## Paso 5: Ejecutar

```bash
# Primero entrenar y exportar modelo
cd /local/dpdk_100g/mira/ml_system/02_training
python3 export_lightgbm_model.py \
    --train ../datasets/splits/train.csv \
    --output ../../detector_system_ml/lightgbm_model.txt

# Luego ejecutar detector con ML
cd /local/dpdk_100g/mira/detector_system_ml
sudo ./mira_ddos_detector_ml -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0
```

## Resumen de Cambios

1. ✅ **Include ML**: Añadir `#include "ml_inference.h"`
2. ✅ **Variable global**: `ml_model_handle g_ml_model = NULL`
3. ✅ **Modificar detect_attacks()**: Añadir predicción ML después de thresholds
4. ✅ **Cargar modelo**: `ml_init()` en `main()`
5. ✅ **Cleanup**: `ml_cleanup()` en `signal_handler()`

**Total de líneas añadidas: ~150**
**Total de líneas modificadas: ~200**
**Detector original: INTACTO (solo extensiones)**
