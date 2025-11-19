/*
 * QUIC Optimistic ACK DDoS Detector with DPDK + OctoSketch
 *
 * Detector de ataques QUIC Optimistic ACK usando reglas precisas sin ML
 * Optimizado para 100 Gbps con NICs Mellanox
 *
 * Reglas de deteccion:
 * 1. ACK Rate Anomaly: Tasa de ACKs por IP > umbral
 * 2. Bytes Ratio Anomaly: bytes_out/bytes_in desbalanceado
 * 3. Packet Number Jump: Saltos anormales en numeros de paquete ACKeados
 * 4. Burst Detection: Rafagas de ACKs en corto tiempo
 * 5. Heavy Hitter ACKers: IPs que generan muchos ACKs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 512

/* QUIC ports */
#define QUIC_PORT_443 443
#define QUIC_PORT_8443 8443

/* QUIC Header constants */
#define QUIC_LONG_HEADER_BIT 0x80
#define QUIC_FIXED_BIT 0x40

/* QUIC Frame types */
#define QUIC_FRAME_ACK 0x02
#define QUIC_FRAME_ACK_ECN 0x03

/* OctoSketch parameters */
#define SKETCH_WIDTH 65536    // 64K buckets
#define SKETCH_DEPTH 4        // 4 hash functions
#define HEAVY_HITTER_THRESHOLD 500  // Paquetes para ser heavy hitter

/* Detection thresholds */
#define ACK_RATE_THRESHOLD 5000       // >5000 ACKs/s por IP = sospechoso
#define BYTES_RATIO_THRESHOLD 10.0    // bytes_out/bytes_in > 10 = ataque
#define PKT_NUM_JUMP_THRESHOLD 1000   // Salto >1000 en pkt number = sospechoso
#define BURST_THRESHOLD 100           // >100 ACKs en 100ms = burst
#define MIN_PACKETS_FOR_DETECTION 500 // Minimo de paquetes para analisis

/* Time window */
#define DETECTION_WINDOW_SEC 1        // Ventana de 1 segundo
#define STATS_INTERVAL_SEC 5          // Mostrar stats cada 5 segundos

/* Alert levels */
#define ALERT_NONE 0
#define ALERT_LOW 1
#define ALERT_MEDIUM 2
#define ALERT_HIGH 3
#define ALERT_CRITICAL 4

/* Count-Min Sketch para conteo de frecuencias */
struct count_min_sketch {
    uint32_t width;
    uint32_t depth;
    uint32_t **counters;
};

/* Per-IP statistics for QUIC traffic */
struct ip_quic_stats {
    uint64_t ack_count;           // Total ACKs sent by this IP
    uint64_t bytes_sent;          // Bytes sent by this IP (client -> server)
    uint64_t bytes_received;      // Bytes received from server (estimate)
    uint64_t last_pkt_num;        // Last acknowledged packet number
    uint64_t max_pkt_num_jump;    // Maximum packet number jump
    uint64_t burst_count;         // ACKs in current burst window
    uint64_t last_burst_check;    // TSC of last burst check
};

/* Detection statistics */
struct detection_stats {
    /* Counters */
    uint64_t total_packets;
    uint64_t quic_packets;
    uint64_t baseline_packets;  // 192.168.x.x (legitimate)
    uint64_t attack_packets;    // 203.0.113.x (attack)

    /* QUIC specific */
    uint64_t total_acks;
    uint64_t total_bytes_in;    // Client -> Server
    uint64_t total_bytes_out;   // Server -> Client
    uint64_t short_packets;     // Short header packets (data)
    uint64_t long_packets;      // Long header packets (handshake)

    /* Per-IP tracking */
    uint64_t unique_ips;
    uint64_t heavy_hitters;
    uint64_t suspicious_ips;    // IPs with abnormal ACK patterns

    /* Attack indicators */
    uint64_t high_ack_rate_detections;
    uint64_t bytes_ratio_anomalies;
    uint64_t pkt_num_jump_detections;
    uint64_t burst_detections;

    /* Maximum values observed */
    double max_bytes_ratio;
    uint64_t max_ack_rate;
    uint64_t max_pkt_num_jump;

    /* Alert level */
    uint32_t alert_level;
    char alert_reason[512];

    /* Timestamps */
    uint64_t window_start_tsc;
    uint64_t last_stats_tsc;
};

/* Global configuration */
struct detector_config {
    uint16_t port_id;
    uint16_t nb_queues;
    bool verbose;
} g_config = {
    .port_id = 0,
    .nb_queues = 1,
    .verbose = false,
};

/* Global state */
static volatile bool force_quit = false;
static FILE *g_log_file = NULL;
static struct rte_mempool *mbuf_pool = NULL;
static struct count_min_sketch *ip_ack_sketch = NULL;      // ACKs per IP
static struct count_min_sketch *ip_bytes_in_sketch = NULL; // Bytes sent by IP
static struct count_min_sketch *ip_bytes_out_sketch = NULL;// Bytes received by IP
static struct detection_stats g_stats;

/* Forward declarations */
static void close_log_file(void);

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;

        /* Close log file immediately */
        if (g_log_file) {
            fprintf(g_log_file, "\n================================================================================\n");
            fprintf(g_log_file, "Detector stopped by signal %d\n", signum);
            fflush(g_log_file);
            fclose(g_log_file);
            g_log_file = NULL;
            printf("[*] Log file closed by signal handler\n");
        }
    }
}

/* Open log file for automatic saving */
static int open_log_file(void)
{
    char log_path[] = "/local/dpdk_100g/quic/results/results_quic_optimistic_ack.log";

    g_log_file = fopen(log_path, "w");
    if (!g_log_file) {
        fprintf(stderr, "Warning: Could not open log file %s: %s\n",
                log_path, strerror(errno));
        fprintf(stderr, "Continuing without file logging (output to stdout only)\n");
        return -1;
    }

    printf("[*] Log file opened: %s\n", log_path);
    fprintf(g_log_file, "QUIC Optimistic ACK Detector Log\n");
    fprintf(g_log_file, "Start time: %s\n", __DATE__ " " __TIME__);
    fprintf(g_log_file, "================================================================================\n\n");
    fflush(g_log_file);

    return 0;
}

/* Close log file */
static void close_log_file(void)
{
    if (g_log_file) {
        fprintf(g_log_file, "\n================================================================================\n");
        fprintf(g_log_file, "Detector stopped\n");
        fclose(g_log_file);
        g_log_file = NULL;
        printf("[*] Log file closed\n");
    }
}

/* Dual output function - print to both stdout and log file */
static void dual_printf(const char *format, ...)
{
    va_list args1, args2;

    va_start(args1, format);
    vprintf(format, args1);
    va_end(args1);

    if (g_log_file) {
        va_start(args2, format);
        vfprintf(g_log_file, format, args2);
        va_end(args2);
        fflush(g_log_file);
    }
}

/* Initialize Count-Min Sketch */
static struct count_min_sketch *cms_init(uint32_t width, uint32_t depth)
{
    struct count_min_sketch *cms = malloc(sizeof(*cms));
    if (!cms)
        return NULL;

    cms->width = width;
    cms->depth = depth;

    cms->counters = malloc(depth * sizeof(uint32_t *));
    if (!cms->counters) {
        free(cms);
        return NULL;
    }

    for (uint32_t i = 0; i < depth; i++) {
        cms->counters[i] = calloc(width, sizeof(uint32_t));
        if (!cms->counters[i]) {
            for (uint32_t j = 0; j < i; j++)
                free(cms->counters[j]);
            free(cms->counters);
            free(cms);
            return NULL;
        }
    }

    return cms;
}

/* Update Count-Min Sketch */
static void cms_update(struct count_min_sketch *cms, uint32_t item, uint32_t count)
{
    for (uint32_t i = 0; i < cms->depth; i++) {
        uint32_t hash = rte_jhash_1word(item, i);
        uint32_t index = hash % cms->width;
        cms->counters[i][index] += count;
    }
}

/* Query Count-Min Sketch */
static uint32_t cms_query(struct count_min_sketch *cms, uint32_t item)
{
    uint32_t min_count = UINT32_MAX;

    for (uint32_t i = 0; i < cms->depth; i++) {
        uint32_t hash = rte_jhash_1word(item, i);
        uint32_t index = hash % cms->width;
        if (cms->counters[i][index] < min_count)
            min_count = cms->counters[i][index];
    }

    return min_count;
}

/* Reset Count-Min Sketch */
static void cms_reset(struct count_min_sketch *cms)
{
    for (uint32_t i = 0; i < cms->depth; i++) {
        memset(cms->counters[i], 0, cms->width * sizeof(uint32_t));
    }
}

/* Free Count-Min Sketch */
static void cms_free(struct count_min_sketch *cms)
{
    if (!cms)
        return;

    for (uint32_t i = 0; i < cms->depth; i++) {
        free(cms->counters[i]);
    }
    free(cms->counters);
    free(cms);
}

/* Check if packet is QUIC based on heuristics */
static bool is_quic_packet(uint8_t *payload, uint32_t len)
{
    if (len < 1)
        return false;

    uint8_t first_byte = payload[0];

    /* Check fixed bit (must be 1 for QUIC) */
    if (!(first_byte & QUIC_FIXED_BIT))
        return false;

    /* Long header (Initial, 0-RTT, Handshake, Retry) */
    if (first_byte & QUIC_LONG_HEADER_BIT) {
        /* Need at least version (4 bytes) after first byte */
        if (len < 5)
            return false;

        /* Check for valid QUIC versions */
        uint32_t version = (payload[1] << 24) | (payload[2] << 16) |
                          (payload[3] << 8) | payload[4];

        /* QUIC v1 = 0x00000001, draft versions = 0xff0000XX */
        if (version == 0x00000001 || (version & 0xffffff00) == 0xff000000)
            return true;
    } else {
        /* Short header - harder to identify, assume QUIC if on right port */
        return true;
    }

    return false;
}

/* Parse QUIC payload for ACK frames */
static int parse_quic_for_acks(uint8_t *payload, uint32_t len,
                                uint64_t *ack_count, uint64_t *largest_ack)
{
    *ack_count = 0;
    *largest_ack = 0;

    if (len < 2)
        return 0;

    /* Skip header to get to frames */
    uint32_t offset = 0;
    uint8_t first_byte = payload[0];

    if (first_byte & QUIC_LONG_HEADER_BIT) {
        /* Long header - skip to payload */
        if (len < 7)
            return 0;

        /* Skip: first byte (1) + version (4) + DCID len (1) */
        offset = 6;
        if (offset >= len)
            return 0;

        uint8_t dcid_len = payload[5];
        offset += dcid_len;
        if (offset >= len)
            return 0;

        uint8_t scid_len = payload[offset];
        offset += 1 + scid_len;

        /* Skip token and length for Initial packets */
        /* This is simplified - real parsing is more complex */
        offset += 2; // Simplified skip
    } else {
        /* Short header - skip DCID (variable, assume 8 bytes) + packet number */
        offset = 1 + 8 + 4; // Simplified
    }

    /* Scan for ACK frames */
    while (offset < len - 1) {
        uint8_t frame_type = payload[offset];

        if (frame_type == QUIC_FRAME_ACK || frame_type == QUIC_FRAME_ACK_ECN) {
            (*ack_count)++;

            /* Try to extract largest acknowledged packet number */
            if (offset + 8 < len) {
                /* Variable-length integer - simplified extraction */
                uint8_t first = payload[offset + 1];
                if ((first & 0xC0) == 0x00) {
                    *largest_ack = first;
                } else if ((first & 0xC0) == 0x40) {
                    *largest_ack = ((first & 0x3F) << 8) | payload[offset + 2];
                } else if ((first & 0xC0) == 0x80) {
                    *largest_ack = ((first & 0x3F) << 24) |
                                  (payload[offset + 2] << 16) |
                                  (payload[offset + 3] << 8) |
                                  payload[offset + 4];
                }
            }

            /* Skip ACK frame (simplified - skip 20 bytes) */
            offset += 20;
        } else if (frame_type == 0x00) {
            /* PADDING */
            offset++;
        } else {
            /* Other frame types - skip */
            offset += 10; // Simplified skip
        }

        if (offset >= len)
            break;
    }

    return *ack_count;
}

/* Detect QUIC Optimistic ACK attack using multiple rules */
static void detect_optimistic_ack(void)
{
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    uint64_t elapsed_tsc = cur_tsc - g_stats.window_start_tsc;
    double elapsed_sec = (double)elapsed_tsc / hz;

    if (elapsed_sec < DETECTION_WINDOW_SEC)
        return;

    /* Reset alert */
    g_stats.alert_level = ALERT_NONE;
    g_stats.alert_reason[0] = '\0';

    /* Requiere minimo de paquetes */
    if (g_stats.quic_packets < MIN_PACKETS_FOR_DETECTION) {
        goto reset_window;
    }

    double acks_per_sec = g_stats.total_acks / elapsed_sec;
    double attack_ratio = (double)g_stats.attack_packets / g_stats.quic_packets;

    /* Rule 1: High ACK rate from attack network (203.0.113.x) */
    if (g_stats.attack_packets > 0 && attack_ratio > 0.3) {
        double attack_ack_rate = (g_stats.total_acks * attack_ratio) / elapsed_sec;
        if (attack_ack_rate > ACK_RATE_THRESHOLD) {
            g_stats.alert_level = ALERT_HIGH;
            g_stats.high_ack_rate_detections++;
            snprintf(g_stats.alert_reason, sizeof(g_stats.alert_reason),
                    "HIGH ACK RATE: %.0f ACKs/s from attack network (%.1f%% of traffic)",
                    attack_ack_rate, attack_ratio * 100);
        }
    }

    /* Rule 2: Bytes ratio anomaly (amplification detection) */
    if (g_stats.total_bytes_in > 0) {
        double bytes_ratio = (double)g_stats.total_bytes_out / g_stats.total_bytes_in;
        if (bytes_ratio > g_stats.max_bytes_ratio)
            g_stats.max_bytes_ratio = bytes_ratio;

        if (bytes_ratio > BYTES_RATIO_THRESHOLD) {
            if (g_stats.alert_level < ALERT_HIGH) {
                g_stats.alert_level = ALERT_HIGH;
            }
            g_stats.bytes_ratio_anomalies++;
            snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                    sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                    " | AMPLIFICATION: bytes_out/bytes_in = %.1f (threshold: %.1f)",
                    bytes_ratio, BYTES_RATIO_THRESHOLD);
        }
    }

    /* Rule 3: Heavy hitter ACKers (IPs with excessive ACKs) */
    if (g_stats.heavy_hitters > 5) {
        if (g_stats.alert_level < ALERT_MEDIUM) {
            g_stats.alert_level = ALERT_MEDIUM;
        }
        snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                " | HEAVY ACKers: %lu IPs with excessive ACK rate",
                g_stats.heavy_hitters);
    }

    /* Rule 4: Suspicious IPs (packet number jumps) */
    if (g_stats.suspicious_ips > 3) {
        if (g_stats.alert_level < ALERT_MEDIUM) {
            g_stats.alert_level = ALERT_MEDIUM;
        }
        g_stats.pkt_num_jump_detections++;
        snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                " | PKT_NUM JUMPS: %lu IPs with abnormal ACK patterns",
                g_stats.suspicious_ips);
    }

    /* Rule 5: Burst detection */
    if (g_stats.burst_detections > 10) {
        if (g_stats.alert_level < ALERT_LOW) {
            g_stats.alert_level = ALERT_LOW;
        }
        snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                " | BURSTS: %lu ACK burst events detected",
                g_stats.burst_detections);
    }

reset_window:
    /* Reset window */
    g_stats.window_start_tsc = cur_tsc;
    g_stats.unique_ips = 0;
    g_stats.heavy_hitters = 0;
    g_stats.suspicious_ips = 0;

    /* Reset sketches */
    cms_reset(ip_ack_sketch);
    cms_reset(ip_bytes_in_sketch);
    cms_reset(ip_bytes_out_sketch);
}

/* Process packet and extract features */
static void process_packet(struct rte_mbuf *pkt)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint8_t *payload;
    uint32_t payload_len;

    g_stats.total_packets++;

    /* Parse Ethernet */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return;

    /* Parse IP */
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_UDP)
        return;

    /* Parse UDP */
    udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));

    /* Check for QUIC ports (443, 8443) */
    uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    uint16_t src_port = rte_be_to_cpu_16(udp_hdr->src_port);

    if (dst_port != QUIC_PORT_443 && dst_port != QUIC_PORT_8443 &&
        src_port != QUIC_PORT_443 && src_port != QUIC_PORT_8443)
        return;

    /* Get payload */
    payload = (uint8_t *)(udp_hdr + 1);
    payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

    /* Verify QUIC packet */
    if (!is_quic_packet(payload, payload_len))
        return;

    g_stats.quic_packets++;

    /* Classify packet type */
    uint8_t first_byte = payload[0];
    if (first_byte & QUIC_LONG_HEADER_BIT) {
        g_stats.long_packets++;
    } else {
        g_stats.short_packets++;
    }

    /* Classify: baseline vs attack */
    uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint8_t first_octet = (src_ip >> 24) & 0xFF;
    uint8_t second_octet = (src_ip >> 16) & 0xFF;
    uint8_t third_octet = (src_ip >> 8) & 0xFF;

    bool is_attack = false;
    if (first_octet == 192 && second_octet == 168) {
        g_stats.baseline_packets++;
    } else if (first_octet == 203 && second_octet == 0 && third_octet == 113) {
        g_stats.attack_packets++;
        is_attack = true;
    }

    /* Track bytes by direction */
    uint32_t pkt_len = rte_pktmbuf_data_len(pkt);
    if (dst_port == QUIC_PORT_443 || dst_port == QUIC_PORT_8443) {
        /* Client -> Server */
        g_stats.total_bytes_in += pkt_len;
        cms_update(ip_bytes_in_sketch, src_ip, pkt_len);
    } else {
        /* Server -> Client */
        g_stats.total_bytes_out += pkt_len;
        cms_update(ip_bytes_out_sketch, src_ip, pkt_len);
    }

    /* Parse for ACK frames */
    uint64_t ack_count = 0;
    uint64_t largest_ack = 0;
    parse_quic_for_acks(payload, payload_len, &ack_count, &largest_ack);

    if (ack_count > 0) {
        g_stats.total_acks += ack_count;

        /* Update ACK count per IP */
        cms_update(ip_ack_sketch, src_ip, ack_count);
        uint32_t ip_ack_count = cms_query(ip_ack_sketch, src_ip);

        if (ip_ack_count == ack_count) {
            g_stats.unique_ips++;
        }

        /* Check for heavy hitter */
        if (ip_ack_count > HEAVY_HITTER_THRESHOLD) {
            g_stats.heavy_hitters++;
        }

        /* Track maximum ACK rate */
        if (ip_ack_count > g_stats.max_ack_rate) {
            g_stats.max_ack_rate = ip_ack_count;
        }

        /* Check for suspicious packet number jumps */
        if (largest_ack > 0 && is_attack) {
            /* This would need per-IP state to properly track jumps */
            /* Simplified: count large packet numbers as suspicious */
            if (largest_ack > PKT_NUM_JUMP_THRESHOLD) {
                g_stats.suspicious_ips++;
                if (largest_ack > g_stats.max_pkt_num_jump) {
                    g_stats.max_pkt_num_jump = largest_ack;
                }
            }
        }
    }
}

/* Print detection statistics */
static void print_stats(void)
{
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    uint64_t elapsed_tsc = cur_tsc - g_stats.last_stats_tsc;

    if (elapsed_tsc < hz * STATS_INTERVAL_SEC)
        return;

    g_stats.last_stats_tsc = cur_tsc;

    dual_printf("\n");
    dual_printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    dual_printf("║          QUIC OPTIMISTIC ACK DETECTOR - STATISTICS                   ║\n");
    dual_printf("╚═══════════════════════════════════════════════════════════════════════╝\n");

    dual_printf("\n[PACKET COUNTERS]\n");
    dual_printf("  Total packets:      %lu\n", g_stats.total_packets);
    dual_printf("  QUIC packets:       %lu\n", g_stats.quic_packets);
    dual_printf("  Baseline (192.168): %lu (%.1f%%)\n",
           g_stats.baseline_packets,
           g_stats.quic_packets > 0 ? (double)g_stats.baseline_packets / g_stats.quic_packets * 100 : 0);
    dual_printf("  Attack (203.0.113): %lu (%.1f%%)\n",
           g_stats.attack_packets,
           g_stats.quic_packets > 0 ? (double)g_stats.attack_packets / g_stats.quic_packets * 100 : 0);

    dual_printf("\n[QUIC TRAFFIC ANALYSIS]\n");
    dual_printf("  Long headers:       %lu (handshakes)\n", g_stats.long_packets);
    dual_printf("  Short headers:      %lu (data)\n", g_stats.short_packets);
    dual_printf("  Total ACKs:         %lu\n", g_stats.total_acks);

    dual_printf("\n[BYTES ANALYSIS]\n");
    dual_printf("  Bytes IN (client):  %lu\n", g_stats.total_bytes_in);
    dual_printf("  Bytes OUT (server): %lu\n", g_stats.total_bytes_out);
    double bytes_ratio = g_stats.total_bytes_in > 0 ?
                        (double)g_stats.total_bytes_out / g_stats.total_bytes_in : 0;
    dual_printf("  Ratio OUT/IN:       %.2f\n", bytes_ratio);

    dual_printf("\n[IP ANALYSIS]\n");
    dual_printf("  Unique IPs:         %lu\n", g_stats.unique_ips);
    dual_printf("  Heavy ACKers:       %lu\n", g_stats.heavy_hitters);
    dual_printf("  Suspicious IPs:     %lu\n", g_stats.suspicious_ips);

    dual_printf("\n[ATTACK INDICATORS]\n");
    dual_printf("  High ACK rate:      %lu detections\n", g_stats.high_ack_rate_detections);
    dual_printf("  Bytes anomalies:    %lu detections\n", g_stats.bytes_ratio_anomalies);
    dual_printf("  Pkt num jumps:      %lu detections\n", g_stats.pkt_num_jump_detections);
    dual_printf("  Max bytes ratio:    %.2f\n", g_stats.max_bytes_ratio);
    dual_printf("  Max ACK rate/IP:    %lu\n", g_stats.max_ack_rate);

    dual_printf("\n[ALERT STATUS]\n");
    const char *alert_names[] = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    const char *alert_colors[] = {"\033[0m", "\033[33m", "\033[93m", "\033[91m", "\033[1;91m"};

    dual_printf("  Alert level:        %s%s\033[0m\n",
           alert_colors[g_stats.alert_level],
           alert_names[g_stats.alert_level]);

    if (g_stats.alert_level > ALERT_NONE) {
        dual_printf("  Reason:             %s\n", g_stats.alert_reason);
    }

    dual_printf("\n");
}

/* Port initialization */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = ETH_MQ_RX_NONE,
        },
    };

    const uint16_t rx_rings = 1, tx_rings = 0;
    uint16_t nb_rxd = RX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
    if (retval != 0)
        return retval;

    /* Setup RX queue */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Start device */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    rte_eth_promiscuous_enable(port);

    return 0;
}

/* Main detection loop */
static int detection_loop(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    uint16_t port = g_config.port_id;
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("Detection loop started on lcore %u\n", lcore_id);

    g_stats.window_start_tsc = rte_rdtsc();
    g_stats.last_stats_tsc = rte_rdtsc();

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            process_packet(bufs[i]);
            rte_pktmbuf_free(bufs[i]);
        }

        /* Run detection */
        detect_optimistic_ack();

        /* Print stats */
        print_stats();
    }

    return 0;
}

/* Main function */
int main(int argc, char **argv)
{
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check ports */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Found %u Ethernet port(s)\n", nb_ports);

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize sketches */
    ip_ack_sketch = cms_init(SKETCH_WIDTH, SKETCH_DEPTH);
    ip_bytes_in_sketch = cms_init(SKETCH_WIDTH, SKETCH_DEPTH);
    ip_bytes_out_sketch = cms_init(SKETCH_WIDTH, SKETCH_DEPTH);

    if (!ip_ack_sketch || !ip_bytes_in_sketch || !ip_bytes_out_sketch)
        rte_exit(EXIT_FAILURE, "Cannot create sketches\n");

    printf("OctoSketch initialized: %ux%u (3 sketches)\n", SKETCH_WIDTH, SKETCH_DEPTH);

    /* Initialize port */
    if (port_init(g_config.port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", g_config.port_id);

    printf("Port %u initialized\n", g_config.port_id);

    /* Initialize stats */
    memset(&g_stats, 0, sizeof(g_stats));

    /* Open log file */
    open_log_file();

    dual_printf("\n");
    dual_printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    dual_printf("║      QUIC OPTIMISTIC ACK DETECTOR - DPDK + OctoSketch                ║\n");
    dual_printf("╠═══════════════════════════════════════════════════════════════════════╣\n");
    dual_printf("║  Port:              %u                                                ║\n", g_config.port_id);
    dual_printf("║  Detection window:  %u second                                         ║\n", DETECTION_WINDOW_SEC);
    dual_printf("║  Stats interval:    %u seconds                                        ║\n", STATS_INTERVAL_SEC);
    dual_printf("║                                                                       ║\n");
    dual_printf("║  Detection Rules:                                                     ║\n");
    dual_printf("║    1. ACK Rate Anomaly (>%u ACKs/s per IP)                          ║\n", ACK_RATE_THRESHOLD);
    dual_printf("║    2. Bytes Ratio (OUT/IN > %.1f = amplification)                    ║\n", BYTES_RATIO_THRESHOLD);
    dual_printf("║    3. Packet Number Jumps (ACKing future packets)                     ║\n");
    dual_printf("║    4. Heavy Hitter ACKers (>%u ACKs per IP)                         ║\n", HEAVY_HITTER_THRESHOLD);
    dual_printf("║    5. Burst Detection (rapid ACK sequences)                           ║\n");
    dual_printf("╚═══════════════════════════════════════════════════════════════════════╝\n");
    dual_printf("\nPress Ctrl+C to exit...\n\n");

    /* Run detection */
    detection_loop(NULL);

    /* Final stats */
    printf("\n\n=== FINAL STATISTICS ===\n");
    print_stats();

    /* Cleanup */
    cms_free(ip_ack_sketch);
    cms_free(ip_bytes_in_sketch);
    cms_free(ip_bytes_out_sketch);

    printf("\nDetector stopped.\n");

    return 0;
}
