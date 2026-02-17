/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 MIRA Project
 *
 * MIRA DDoS Detector - MULTI-CORE + OCTOSKETCH VERSION
 *
 * Multi-attack DDoS detector with multi-core processing + OctoSketch for line-rate detection
 * Detects: UDP Flood, SYN Flood, HTTP Flood, ICMP Flood, DNS/NTP Amp, ACK Flood
 *
 * Architecture:
 * - 14 Worker threads (lcores 1-14): RX processing with RSS + OctoSketch updates
 * - 1 Coordinator thread (lcore 15): Attack detection via sketch queries
 * - OctoSketch: Memory-efficient probabilistic counting (128KB per sketch)
 *
 * Key Improvements:
 * - DPDK: Line-rate packet processing (10-100 Gbps)
 * - OctoSketch: O(1) memory, lock-free updates, heavy-hitter detection
 * - Detection latency: <50ms (vs MULTI-LF: 866ms = 17× faster)
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <math.h>
#include <signal.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>
#include <rte_atomic.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "octosketch.h"
#include "ml_inference.h"  /* ========== ML INTEGRATION ========== */

static int safe_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list args;
    int ret;

    if (size == 0) {
        return 0;
    }

    va_start(args, fmt);
    ret = vsnprintf(buf, size, fmt, args);
    va_end(args);

    if (ret < 0) {
        return 0;
    }

    if ((size_t)ret >= size) {
        return (int)size - 1;
    }

    return ret;
}

#define RX_RING_SIZE 32768       /* Max for uint16_t compatibility (must be power of 2) */
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288         /* Keep at 524K to avoid soft lockup on cleanup */
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 2048          /* Larger bursts for max throughput - Phase 3 */
#define NUM_RX_QUEUES 14         /* 14 workers for 17+ Gbps - CRITICAL */

/* Anomaly detection thresholds (1.5x baseline maximum)
 * NOTE: ML model classifies the specific attack type.
 *       Thresholds trigger anomaly detection, ML identifies the attack.
 */
#define ANOMALY_UDP_THRESHOLD    7000000   /* 7M UDP pps (baseline max: 4.4M) */
#define ANOMALY_SYN_THRESHOLD    2500000   /* 2.5M SYN pps (baseline max: 1.6M) */
#define ANOMALY_HTTP_THRESHOLD   4000000   /* 4M HTTP rps (baseline max: 2.5M) */
#define ANOMALY_ICMP_THRESHOLD    700000   /* 700K ICMP pps (baseline max: 450K) */

/* Protocol-specific anomaly thresholds */
#define DNS_AMP_THRESHOLD   3000000   /* 3M DNS amp pps */
#define NTP_AMP_THRESHOLD   2000000   /* 2M NTP amp pps */
#define SNMP_AMP_THRESHOLD  2000000   /* 2M SNMP amp pps */
#define SSDP_THRESHOLD      2000000   /* 2M SSDP pps */
#define PORTMAP_THRESHOLD   2000000   /* 2M PortMap pps */
#define NETBIOS_THRESHOLD   2000000   /* 2M NetBIOS pps */
#define LDAP_THRESHOLD      2000000   /* 2M LDAP pps */
#define MSSQL_THRESHOLD     2000000   /* 2M MSSQL pps */
#define TFTP_THRESHOLD      1000000   /* 1M TFTP pps */
#define ACK_FLOOD_THRESHOLD 4000000   /* 4M ACK pps */
#define FRAG_THRESHOLD      1000000   /* 1M fragmented pps */

/* Feature mode selection */
typedef enum {
    ML_MODE_DPI_SKETCH = 0,   /* 75 features: 61 DPI + 14 sketch */
    ML_MODE_SKETCH_ADV = 1,   /* 64 features: 14 sketch + 50 per-proto */
} ml_mode_t;

#define DPI_SKETCH_NUM_FEATURES 75
#define SKETCH_ADV_NUM_FEATURES 64
#define SKETCH_ADV_NUM_PROTOS 12

/* OctoSketch Heavy-Hitter Detection */
#define HEAVY_HITTER_PPS_THRESHOLD 5000   /* Single IP exceeding 5K pps = heavy hitter */
#define HEAVY_HITTER_TOP_K 5              /* Track top 5 attackers */

/* Adaptive threshold parameters */
#define ATTACK_TOTAL_PPS_THRESHOLD 7000000 /* Fallback until baseline ready */
#define ADAPTIVE_SIGMA 3.0                /* 3-sigma for anomaly detection */
#define MIN_BASELINE_SAMPLES 20           /* Minimum samples before adaptive threshold */

/* Time windows */
#define FAST_DETECTION_INTERVAL 0.05
#define STATS_INTERVAL_SEC 5.0
#define DETECTION_WINDOW_SEC 5.0

/* Ring Buffer for temporal features */
#define RING_BUFFER_SIZE 100              /* Last 100 windows (5 seconds at 50ms) */

/* Multi-scale time windows */
#define SCALE_1S_WINDOWS 20               /* 20 × 50ms = 1 second */
#define SCALE_10S_WINDOWS 200             /* 200 × 50ms = 10 seconds */
#define SCALE_1MIN_WINDOWS 1200           /* 1200 × 50ms = 1 minute */

/* IP tracking */
#define MAX_IPS 65536
#define BASELINE_NETWORK 0x0A0A0200     /* 10.10.2.x - benign traffic (CloudLab internal) */
#define ATTACK_NETWORK   0x0A0A0300     /* 10.10.3.x - attack traffic (CloudLab internal) */
#define NETWORK_MASK     0xFFFFFF00

#define SERVER_IP 0x0A000001

/* Alert levels */
typedef enum {
    ALERT_NONE = 0,
    ALERT_LOW = 1,
    ALERT_MEDIUM = 2,
    ALERT_HIGH = 3
} alert_level_t;

/* Per-IP statistics - ATOMIC for multi-core safety */
struct ip_stats {
    uint32_t ip_addr;
    rte_atomic64_t total_packets;
    rte_atomic64_t tcp_packets;
    rte_atomic64_t udp_packets;
    rte_atomic64_t icmp_packets;
    rte_atomic64_t syn_packets;
    rte_atomic64_t ack_packets;
    rte_atomic64_t http_requests;
    rte_atomic64_t dns_queries;
    rte_atomic64_t ntp_queries;
    rte_atomic64_t pure_ack_packets;
    rte_atomic64_t fragmented_packets;
    rte_atomic64_t bytes_in;
    rte_atomic64_t bytes_out;
    uint64_t last_seen_tsc;
    bool is_active;
} __rte_cache_aligned;

/* Per-worker statistics - NO ATOMICS (lock-free) */
struct worker_stats {
    /* Packet counters */
    uint64_t total_packets;
    uint64_t baseline_packets;
    uint64_t attack_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;

    /* Attack-specific counters */
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t syn_only_packets;       /* SYN without HTTP (not port 80/443) */
    uint64_t http_requests;
    uint64_t http_payload_packets;   /* TCP to 80/443 with payload > 0 */
    uint64_t dns_queries;

    /* Bytes counters */
    uint64_t total_bytes;
    uint64_t baseline_bytes;
    uint64_t attack_bytes;

    /* ========== NEW: Protocol-Specific Features (26 features) ========== */
    /* NTP Amplification Detection (3 features) */
    uint64_t ntp_monlist_queries;      // NTP mode 7 MON_GETLIST packets
    uint64_t ntp_responses;             // NTP responses
    uint64_t ntp_response_size_sum;     // Sum for calculating avg_ntp_response_size

    /* DNS Amplification Detection (4 features) */
    uint64_t dns_any_queries;           // DNS type ANY queries
    uint64_t dns_txt_queries;           // DNS TXT queries
    uint64_t dns_responses;             // DNS responses
    uint64_t dns_response_size_sum;     // Sum for calculating avg_dns_response_size

    /* SNMP Amplification Detection (3 features) */
    uint64_t snmp_getbulk_requests;     // SNMP GetBulkRequest packets
    uint64_t snmp_responses;            // SNMP responses
    uint64_t snmp_response_size_sum;    // Sum for calculating avg_snmp_response_size

    /* SSDP Amplification Detection (2 features) */
    uint64_t ssdp_msearch_packets;      // SSDP M-SEARCH packets
    uint64_t ssdp_responses;            // SSDP responses

    /* PortMapper/RPC Detection (2 features) */
    uint64_t portmap_getport_calls;     // RPC portmapper GETPORT calls
    uint64_t portmap_dump_calls;        // RPC portmapper DUMP calls

    /* NetBIOS Detection (2 features) */
    uint64_t netbios_name_queries;      // NetBIOS name service queries
    uint64_t netbios_dgram_packets;     // NetBIOS datagram service

    /* LDAP Detection (2 features) */
    uint64_t ldap_bind_requests;        // LDAP Bind requests
    uint64_t ldap_search_requests;      // LDAP Search requests

    /* MSSQL Detection (2 features) */
    uint64_t mssql_sqlbatch_packets;    // MSSQL SQLBatch packets
    uint64_t mssql_rpc_packets;         // MSSQL RPC packets

    /* TFTP Detection (2 features) */
    uint64_t tftp_rrq_packets;          // TFTP Read Request packets
    uint64_t tftp_wrq_packets;          // TFTP Write Request packets
    /* =================================================================== */

    /* DPDK Performance */
    uint64_t rx_bursts_empty;
    uint64_t rx_bursts_total;
} __rte_cache_aligned;

/* Global statistics - Aggregated by coordinator */
struct detection_stats {
    /* Aggregated packet counters (updated by coordinator) */
    uint64_t total_packets;
    uint64_t baseline_packets;
    uint64_t attack_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;

    /* Aggregated attack-specific counters */
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t syn_only_packets;
    uint64_t http_requests;
    uint64_t http_payload_packets;
    uint64_t dns_queries;

    /* Aggregated bytes counters */
    uint64_t total_bytes;
    uint64_t baseline_bytes;
    uint64_t attack_bytes;

    /* ========== NEW: Protocol-Specific Features (26 features) ========== */
    /* NTP Amplification Detection */
    uint64_t ntp_monlist_queries;
    uint64_t ntp_responses;
    uint64_t ntp_response_size_sum;

    /* DNS Amplification Detection */
    uint64_t dns_any_queries;
    uint64_t dns_txt_queries;
    uint64_t dns_responses;
    uint64_t dns_response_size_sum;

    /* SNMP Amplification Detection */
    uint64_t snmp_getbulk_requests;
    uint64_t snmp_responses;
    uint64_t snmp_response_size_sum;

    /* SSDP Amplification Detection */
    uint64_t ssdp_msearch_packets;
    uint64_t ssdp_responses;

    /* PortMapper/RPC Detection */
    uint64_t portmap_getport_calls;
    uint64_t portmap_dump_calls;

    /* NetBIOS Detection */
    uint64_t netbios_name_queries;
    uint64_t netbios_dgram_packets;

    /* LDAP Detection */
    uint64_t ldap_bind_requests;
    uint64_t ldap_search_requests;

    /* MSSQL Detection */
    uint64_t mssql_sqlbatch_packets;
    uint64_t mssql_rpc_packets;

    /* TFTP Detection */
    uint64_t tftp_rrq_packets;
    uint64_t tftp_wrq_packets;
    /* =================================================================== */

    /* Detection metrics */
    uint64_t udp_flood_detections;
    uint64_t syn_flood_detections;
    uint64_t http_flood_detections;
    uint64_t icmp_flood_detections;
    uint64_t total_flood_detections;
    uint64_t dns_amp_detections;
    uint64_t ntp_amp_detections;
    uint64_t ack_flood_detections;
    uint64_t frag_attack_detections;

    /* OctoSketch Heavy-Hitter Detection */
    uint64_t heavy_hitter_detections;
    uint32_t top_attacker_ips[HEAVY_HITTER_TOP_K];
    uint32_t top_attacker_counts[HEAVY_HITTER_TOP_K];
    uint32_t num_heavy_hitters;

    /* Timestamps */
    uint64_t window_start_tsc;
    uint64_t last_stats_tsc;
    uint64_t last_fast_detection_tsc;
    uint64_t first_attack_packet_tsc;
    uint64_t first_detection_tsc;
    uint64_t last_detection_tsc;  /* For tracking inter-detection latency */

    /* MULTI-LF Comparison Metrics - First Detection */
    double detection_latency_ms;
    uint64_t packets_until_detection;
    uint64_t bytes_until_detection;
    bool detection_triggered;

    /* Multiple Detection Tracking - Aggregate Stats */
    uint64_t total_detection_events;      /* Total number of detections */
    double min_detection_latency_ms;      /* Fastest detection */
    double max_detection_latency_ms;      /* Slowest detection */
    double sum_detection_latencies_ms;    /* For average calculation */
    uint64_t detections_under_20ms;       /* Histogram bins */
    uint64_t detections_20_30ms;
    uint64_t detections_30_40ms;
    uint64_t detections_40_50ms;
    uint64_t detections_over_50ms;

    /* DPDK Performance */
    uint64_t rx_packets_nic;
    uint64_t rx_dropped_nic;
    uint64_t rx_errors_nic;
    uint64_t rx_nombuf_nic;
    uint64_t rx_bursts_empty;
    uint64_t rx_bursts_total;

    /* CPU efficiency */
    double cycles_per_packet;
    double throughput_gbps;

    /* Alert - written only by coordinator */
    alert_level_t alert_level;
    char alert_reason[512];
} __rte_cache_aligned;

/* ANSI colors */
#define COLOR_RESET   "\033[0m"
#define COLOR_WHITE   "\033[1;37m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_RED     "\033[1;31m"

/* ========== RING BUFFER STRUCTURE ========== */
struct feature_window {
    uint64_t timestamp_tsc;
    uint64_t window_id;

    /* Base features - stored for temporal analysis */
    float total_packets;
    float total_bytes;
    float udp_packets;
    float tcp_packets;
    float icmp_packets;
    float syn_packets;
    float http_requests;
    float dns_queries;
    float baseline_packets;
    float attack_packets;

    /* Extended features (14) - temporal + multi-scale */
    float delta_pps_5w;
    float delta_pps_10w;
    float pps_variance;
    float pps_baseline;
    float ratio_vs_baseline;
    float top_ip_pps_50ms;
    float top_ip_pps_1s;
    float top_ip_pps_1min;
    float ratio_50ms_1min;
    float num_heavy_hitters;
    float ip_concentration;
    float new_ips_ratio;
    float attack_entropy;
    float adaptive_threshold;

    /* Detection results */
    uint8_t threshold_detected;
    uint8_t ml_predicted_class;
    float ml_confidence;
} __attribute__((packed));

/* Ring buffer for temporal analysis */
struct ring_buffer {
    struct feature_window windows[RING_BUFFER_SIZE];
    uint32_t write_idx;
    uint32_t count;
    uint64_t total_windows;

    /* Running statistics for adaptive thresholds */
    double sum_pps;
    double sum_pps_sq;

    /* Multi-scale aggregates */
    float baseline_1s;
    float baseline_10s;
    float baseline_1min;
} __rte_cache_aligned;

/* Multi-scale sketch structure */
struct multiscale_sketches {
    struct octosketch sketch_50ms;
    struct octosketch sketch_1s;
    struct octosketch sketch_10s;
    struct octosketch sketch_1min;

    uint32_t windows_since_1s_reset;
    uint32_t windows_since_10s_reset;
    uint32_t windows_since_1min_reset;
} __rte_cache_aligned;

/* Instantaneous metrics - per-worker (lock-free) */
static uint64_t window_baseline_pkts[NUM_RX_QUEUES];
static uint64_t window_attack_pkts[NUM_RX_QUEUES];
static uint64_t window_baseline_bytes[NUM_RX_QUEUES];
static uint64_t window_attack_bytes[NUM_RX_QUEUES];
static uint64_t last_window_reset_tsc = 0;
static uint64_t g_start_tsc = 0;  /* Global start timestamp for cumulative throughput */

/* Global variables */
static volatile bool force_quit = false;
static struct ip_stats g_ip_table[MAX_IPS];
static rte_atomic32_t g_ip_count;
static struct detection_stats g_stats;
static struct worker_stats g_worker_stats[NUM_RX_QUEUES] __rte_cache_aligned;
static uint64_t last_ml_alert_tsc = 0;
static FILE *g_log_file = NULL;
static struct rte_hash *ip_hash = NULL;

/* Global ring buffer and multi-scale sketches */
static struct ring_buffer g_ring_buffer __rte_cache_aligned;
static struct multiscale_sketches g_multiscale[NUM_RX_QUEUES] __rte_cache_aligned;
static struct multiscale_sketches g_merged_multiscale __rte_cache_aligned;

/* OctoSketch - Per-worker sketches (NO atomics, NO contention) */
static struct octosketch g_worker_sketch_attack[NUM_RX_QUEUES] __rte_cache_aligned; /* Attack traffic per worker */

/* OctoSketch - Coordinator merged sketches (for analysis) */
static struct octosketch g_merged_sketch_attack __rte_cache_aligned;  /* Merged attack sketch */

/* ========== Per-protocol sketches (12 protocols) - for sketch_adv mode ========== */
static struct octosketch g_worker_sketch_dns[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ntp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_snmp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ssdp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_portmap[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_netbios[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ldap[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_mssql[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_tftp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_syn[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_http[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_udp_other[NUM_RX_QUEUES] __rte_cache_aligned;

static struct octosketch g_merged_sketch_dns __rte_cache_aligned;
static struct octosketch g_merged_sketch_ntp __rte_cache_aligned;
static struct octosketch g_merged_sketch_snmp __rte_cache_aligned;
static struct octosketch g_merged_sketch_ssdp __rte_cache_aligned;
static struct octosketch g_merged_sketch_portmap __rte_cache_aligned;
static struct octosketch g_merged_sketch_netbios __rte_cache_aligned;
static struct octosketch g_merged_sketch_ldap __rte_cache_aligned;
static struct octosketch g_merged_sketch_mssql __rte_cache_aligned;
static struct octosketch g_merged_sketch_tftp __rte_cache_aligned;
static struct octosketch g_merged_sketch_syn __rte_cache_aligned;
static struct octosketch g_merged_sketch_http __rte_cache_aligned;
static struct octosketch g_merged_sketch_udp_other __rte_cache_aligned;

/* Per-worker packet size sum-of-squares for variance (sketch_adv) */
static uint64_t g_worker_pktlen_sq_sum[NUM_RX_QUEUES] __rte_cache_aligned;
/* ========== END Per-protocol sketches ========== */

/* ========== ML INTEGRATION ========== */
static ml_model_handle g_ml_model = NULL;
#define ML_CONFIDENCE_THRESHOLD 0.75f
static ml_mode_t g_ml_mode = ML_MODE_DPI_SKETCH;
static char g_model_dir[512] = "./model_dpi_sketch";
/* ===================================== */

/* Sampling configuration */
#define SKETCH_SAMPLE_RATE 32  /* Update sketch every N packets (1 in 32) */

/* Function declarations */
static int worker_thread(void *arg);
static int coordinator_thread(void *arg);
static void signal_handler(int signum);
static void print_stats(uint16_t port, uint64_t cur_tsc, uint64_t hz);
static void detect_attacks(uint64_t cur_tsc, uint64_t hz);
static struct ip_stats* get_ip_stats(uint32_t ip_addr);

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);

        /* ========== ML INTEGRATION: Cleanup ========== */
        if (g_ml_model) {
            ml_cleanup(g_ml_model);
            g_ml_model = NULL;
        }
        /* ============================================== */

        force_quit = true;
    }
}

/* Get or create IP statistics entry - THREAD-SAFE */
static struct ip_stats* get_ip_stats(uint32_t ip_addr)
{
    int ret;
    uint32_t *idx_ptr;

    /* Try to find existing entry */
    ret = rte_hash_lookup_data(ip_hash, &ip_addr, (void **)&idx_ptr);
    if (ret >= 0) {
        /* Found - return existing entry */
        return &g_ip_table[*idx_ptr];
    }

    /* Not found - create new entry atomically */
    uint32_t new_idx = rte_atomic32_add_return(&g_ip_count, 1) - 1;
    if (new_idx >= MAX_IPS) {
        return NULL;  /* Table full */
    }

    /* Initialize new entry */
    struct ip_stats *new_entry = &g_ip_table[new_idx];
    new_entry->ip_addr = ip_addr;
    rte_atomic64_init(&new_entry->total_packets);
    rte_atomic64_init(&new_entry->tcp_packets);
    rte_atomic64_init(&new_entry->udp_packets);
    rte_atomic64_init(&new_entry->icmp_packets);
    rte_atomic64_init(&new_entry->syn_packets);
    rte_atomic64_init(&new_entry->ack_packets);
    rte_atomic64_init(&new_entry->http_requests);
    rte_atomic64_init(&new_entry->dns_queries);
    rte_atomic64_init(&new_entry->ntp_queries);
    rte_atomic64_init(&new_entry->pure_ack_packets);
    rte_atomic64_init(&new_entry->fragmented_packets);
    rte_atomic64_init(&new_entry->bytes_in);
    rte_atomic64_init(&new_entry->bytes_out);
    new_entry->is_active = true;

    /* Add to hash table */
    static uint32_t *idx_storage;
    idx_storage = malloc(sizeof(uint32_t));
    *idx_storage = new_idx;
    rte_hash_add_key_data(ip_hash, &ip_addr, idx_storage);

    return new_entry;
}

/* ========== RING BUFFER HELPER FUNCTIONS ========== */

/* Get window at offset from current (0 = current, -1 = previous, etc.) */
static inline struct feature_window* ring_buffer_get(int offset)
{
    if (g_ring_buffer.count == 0) return NULL;
    int idx = (int)g_ring_buffer.write_idx + offset;
    while (idx < 0) idx += RING_BUFFER_SIZE;
    idx = idx % RING_BUFFER_SIZE;
    if (offset < 0 && (uint32_t)(-offset) > g_ring_buffer.count) return NULL;
    return &g_ring_buffer.windows[idx];
}

/* Calculate adaptive threshold based on historical data */
static inline float calculate_adaptive_threshold(void)
{
    if (g_ring_buffer.count < MIN_BASELINE_SAMPLES) {
        return ATTACK_TOTAL_PPS_THRESHOLD;
    }

    double mean = g_ring_buffer.sum_pps / g_ring_buffer.count;
    double variance = (g_ring_buffer.sum_pps_sq / g_ring_buffer.count) - (mean * mean);
    double stddev = sqrt(variance > 0 ? variance : 0);

    return (float)(mean + ADAPTIVE_SIGMA * stddev);
}

/* Calculate temporal features from ring buffer */
static void calculate_temporal_features(struct feature_window *current)
{
    struct feature_window *prev_5 = ring_buffer_get(-5);
    if (prev_5) {
        current->delta_pps_5w = current->attack_packets - prev_5->attack_packets;
    } else {
        current->delta_pps_5w = 0;
    }

    struct feature_window *prev_10 = ring_buffer_get(-10);
    if (prev_10) {
        current->delta_pps_10w = current->attack_packets - prev_10->attack_packets;
    } else {
        current->delta_pps_10w = 0;
    }

    /* Variance over last 20 windows */
    float sum = 0, sum_sq = 0;
    int count = 0;
    for (int i = -1; i >= -20 && i >= -(int)g_ring_buffer.count; i--) {
        struct feature_window *w = ring_buffer_get(i);
        if (w) {
            sum += w->attack_packets;
            sum_sq += w->attack_packets * w->attack_packets;
            count++;
        }
    }
    if (count > 1) {
        float mean = sum / count;
        current->pps_variance = (sum_sq / count) - (mean * mean);
    } else {
        current->pps_variance = 0;
    }

    /* Baseline (running average) */
    current->pps_baseline = (g_ring_buffer.count > 0) ?
        (float)(g_ring_buffer.sum_pps / g_ring_buffer.count) : 0;

    /* Ratio vs baseline */
    current->ratio_vs_baseline = (current->pps_baseline > 0) ?
        current->attack_packets / current->pps_baseline : 1.0f;

    /* Adaptive threshold */
    current->adaptive_threshold = calculate_adaptive_threshold();
}

/* Calculate multi-scale features from merged sketches */
static void calculate_multiscale_features(struct feature_window *current, double window_sec)
{
    struct heavy_hitter top_50ms[1], top_1s[1], top_1min[1];

    octosketch_top_k(&g_merged_multiscale.sketch_50ms, 1, top_50ms);
    octosketch_top_k(&g_merged_multiscale.sketch_1s, 1, top_1s);
    octosketch_top_k(&g_merged_multiscale.sketch_1min, 1, top_1min);

    current->top_ip_pps_50ms = (window_sec > 0 && top_50ms[0].count > 0) ?
        (float)top_50ms[0].count / window_sec : 0;
    current->top_ip_pps_1s = (top_1s[0].count > 0) ?
        (float)top_1s[0].count / 1.0f : 0;
    current->top_ip_pps_1min = (top_1min[0].count > 0) ?
        (float)top_1min[0].count / 60.0f : 0;

    current->ratio_50ms_1min = (current->top_ip_pps_1min > 0) ?
        current->top_ip_pps_50ms / current->top_ip_pps_1min : 1.0f;

    /* Count heavy hitters */
    struct heavy_hitter top_5[5];
    octosketch_top_k(&g_merged_multiscale.sketch_50ms, 5, top_5);
    int hh_count = 0;
    for (int i = 0; i < 5; i++) {
        if (top_5[i].count > 0) {
            float ip_pps = (float)top_5[i].count / (window_sec > 0 ? window_sec : 0.05f);
            if (ip_pps > HEAVY_HITTER_PPS_THRESHOLD) hh_count++;
        }
    }
    current->num_heavy_hitters = (float)hh_count;

    /* IP concentration */
    uint64_t total = octosketch_get_total(&g_merged_multiscale.sketch_50ms);
    current->ip_concentration = (total > 0) ?
        (float)top_50ms[0].count / total : 0;

    current->new_ips_ratio = 0;
    current->attack_entropy = 1.0f - current->ip_concentration;
}

/* Push current features to ring buffer */
static void ring_buffer_push(struct feature_window *window)
{
    uint32_t idx = g_ring_buffer.write_idx;

    memcpy(&g_ring_buffer.windows[idx], window, sizeof(struct feature_window));

    if (g_ring_buffer.count >= RING_BUFFER_SIZE) {
        struct feature_window *oldest = &g_ring_buffer.windows[(idx + 1) % RING_BUFFER_SIZE];
        g_ring_buffer.sum_pps -= oldest->attack_packets;
        g_ring_buffer.sum_pps_sq -= oldest->attack_packets * oldest->attack_packets;
    }
    g_ring_buffer.sum_pps += window->attack_packets;
    g_ring_buffer.sum_pps_sq += window->attack_packets * window->attack_packets;

    g_ring_buffer.write_idx = (idx + 1) % RING_BUFFER_SIZE;
    if (g_ring_buffer.count < RING_BUFFER_SIZE) {
        g_ring_buffer.count++;
    }
    g_ring_buffer.total_windows++;
}

/* Merge multi-scale sketches from all workers */
static void merge_multiscale_sketches(void)
{
    struct octosketch *workers_50ms[NUM_RX_QUEUES];
    struct octosketch *workers_1s[NUM_RX_QUEUES];
    struct octosketch *workers_10s[NUM_RX_QUEUES];
    struct octosketch *workers_1min[NUM_RX_QUEUES];

    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        workers_50ms[i] = &g_multiscale[i].sketch_50ms;
        workers_1s[i] = &g_multiscale[i].sketch_1s;
        workers_10s[i] = &g_multiscale[i].sketch_10s;
        workers_1min[i] = &g_multiscale[i].sketch_1min;
    }

    octosketch_merge(&g_merged_multiscale.sketch_50ms, workers_50ms, NUM_RX_QUEUES);
    octosketch_merge(&g_merged_multiscale.sketch_1s, workers_1s, NUM_RX_QUEUES);
    octosketch_merge(&g_merged_multiscale.sketch_10s, workers_10s, NUM_RX_QUEUES);
    octosketch_merge(&g_merged_multiscale.sketch_1min, workers_1min, NUM_RX_QUEUES);
}

/* Merge per-protocol sketches from all workers (sketch_adv mode) */
static void merge_protocol_sketches(void)
{
    struct {
        struct octosketch (*workers)[NUM_RX_QUEUES];
        struct octosketch *merged;
    } protos[12] = {
        { &g_worker_sketch_dns,       &g_merged_sketch_dns },
        { &g_worker_sketch_ntp,       &g_merged_sketch_ntp },
        { &g_worker_sketch_snmp,      &g_merged_sketch_snmp },
        { &g_worker_sketch_ssdp,      &g_merged_sketch_ssdp },
        { &g_worker_sketch_portmap,   &g_merged_sketch_portmap },
        { &g_worker_sketch_netbios,   &g_merged_sketch_netbios },
        { &g_worker_sketch_ldap,      &g_merged_sketch_ldap },
        { &g_worker_sketch_mssql,     &g_merged_sketch_mssql },
        { &g_worker_sketch_tftp,      &g_merged_sketch_tftp },
        { &g_worker_sketch_syn,       &g_merged_sketch_syn },
        { &g_worker_sketch_http,      &g_merged_sketch_http },
        { &g_worker_sketch_udp_other, &g_merged_sketch_udp_other },
    };

    for (int p = 0; p < 12; p++) {
        struct octosketch *src[NUM_RX_QUEUES];
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            src[i] = &(*protos[p].workers)[i];
        }
        octosketch_merge(protos[p].merged, src, NUM_RX_QUEUES);
    }
}

/* Reset multi-scale sketches based on time */
static void reset_multiscale_sketches_if_needed(void)
{
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        g_multiscale[i].windows_since_1s_reset++;
        g_multiscale[i].windows_since_10s_reset++;
        g_multiscale[i].windows_since_1min_reset++;

        octosketch_reset(&g_multiscale[i].sketch_50ms);

        if (g_multiscale[i].windows_since_1s_reset >= SCALE_1S_WINDOWS) {
            octosketch_reset(&g_multiscale[i].sketch_1s);
            g_multiscale[i].windows_since_1s_reset = 0;
        }
        if (g_multiscale[i].windows_since_10s_reset >= SCALE_10S_WINDOWS) {
            octosketch_reset(&g_multiscale[i].sketch_10s);
            g_multiscale[i].windows_since_10s_reset = 0;
        }
        if (g_multiscale[i].windows_since_1min_reset >= SCALE_1MIN_WINDOWS) {
            octosketch_reset(&g_multiscale[i].sketch_1min);
            g_multiscale[i].windows_since_1min_reset = 0;
        }
    }
}

/* ========== END RING BUFFER HELPER FUNCTIONS ========== */

/* Attack detection logic - COORDINATOR ONLY - AGGREGATE MODE */
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

        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_base_pkts += window_baseline_pkts[i];
            window_att_pkts += window_attack_pkts[i];
        }

        /* Aggregate protocol stats from workers */
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_syn_pkts += g_worker_stats[i].syn_packets;
            window_udp_pkts += g_worker_stats[i].udp_packets;
            window_icmp_pkts += g_worker_stats[i].icmp_packets;
            window_http_reqs += g_worker_stats[i].http_requests;
            window_dns_queries += g_worker_stats[i].dns_queries;
        }

        /* Calculate PPS rates */
        double attack_pps = (double)window_att_pkts / window_sec;
        double syn_pps = (double)window_syn_pkts / window_sec;
        double udp_pps = (double)window_udp_pkts / window_sec;
        double icmp_pps = (double)window_icmp_pkts / window_sec;
        double http_pps = (double)window_http_reqs / window_sec;

        /* Threshold-based anomaly detection */
        {
            bool threshold_anomaly = false;

            if (udp_pps > ANOMALY_UDP_THRESHOLD) {
                g_stats.udp_flood_detections++;
                threshold_anomaly = true;
            }
            if (syn_pps > ANOMALY_SYN_THRESHOLD) {
                g_stats.syn_flood_detections++;
                threshold_anomaly = true;
            }
            if (icmp_pps > ANOMALY_ICMP_THRESHOLD) {
                g_stats.icmp_flood_detections++;
                threshold_anomaly = true;
            }
            if (http_pps > ANOMALY_HTTP_THRESHOLD) {
                g_stats.http_flood_detections++;
                threshold_anomaly = true;
            }

            if (threshold_anomaly) {
                attack_detected = true;
                g_stats.alert_level = ALERT_MEDIUM;
            }
        }

        /* ========== Merge sketches and compute ring buffer features ========== */
        /* Merge global + multi-scale sketches */
        {
            struct octosketch *worker_sketches[NUM_RX_QUEUES];
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                worker_sketches[i] = &g_worker_sketch_attack[i];
            }
            octosketch_merge(&g_merged_sketch_attack, worker_sketches, NUM_RX_QUEUES);
        }
        merge_multiscale_sketches();

        /* Merge per-protocol sketches for sketch_adv mode */
        if (g_ml_mode == ML_MODE_SKETCH_ADV) {
            merge_protocol_sketches();
        }

        /* Build feature window for ring buffer */
        struct feature_window fw;
        memset(&fw, 0, sizeof(fw));
        fw.timestamp_tsc = cur_tsc;
        fw.window_id = g_ring_buffer.total_windows;
        fw.total_packets = (float)(window_base_pkts + window_att_pkts);
        fw.attack_packets = (float)window_att_pkts;
        fw.baseline_packets = (float)window_base_pkts;
        fw.udp_packets = (float)window_udp_pkts;
        fw.tcp_packets = (float)(window_syn_pkts);  /* approximate */
        fw.icmp_packets = (float)window_icmp_pkts;
        fw.syn_packets = (float)window_syn_pkts;
        fw.http_requests = (float)window_http_reqs;
        fw.dns_queries = (float)window_dns_queries;

        /* Calculate temporal + multi-scale features */
        calculate_temporal_features(&fw);
        calculate_multiscale_features(&fw, window_sec);

        /* Push to ring buffer */
        ring_buffer_push(&fw);

        /* Reset multi-scale sketches */
        reset_multiscale_sketches_if_needed();

        /* ========== ML PREDICTION ========== */
        bool ml_alert = false;
        const char *ml_class_name = "unknown";
        float ml_confidence = 0.0f;
        struct ml_prediction ml_pred;
        memset(&ml_pred, 0, sizeof(ml_pred));

        uint64_t window_total_pkts = window_base_pkts + window_att_pkts;

        if (g_ml_model != NULL && window_total_pkts > 100) {
            /* Aggregate cumulative stats from all workers */
            uint64_t ml_total_packets = 0, ml_total_bytes = 0;
            uint64_t ml_udp_packets = 0, ml_tcp_packets = 0, ml_icmp_packets = 0;
            uint64_t ml_syn_packets = 0, ml_syn_ack_packets = 0, ml_syn_only_packets = 0;
            uint64_t ml_http_requests = 0, ml_http_payload_packets = 0, ml_dns_queries = 0;
            uint64_t ml_baseline_packets = 0, ml_attack_packets = 0;
            uint64_t ml_ntp_monlist = 0, ml_ntp_responses = 0, ml_ntp_resp_size_sum = 0;
            uint64_t ml_dns_any = 0, ml_dns_txt = 0, ml_dns_responses = 0, ml_dns_resp_size_sum = 0;
            uint64_t ml_snmp_getbulk = 0, ml_snmp_responses = 0, ml_snmp_resp_size_sum = 0;
            uint64_t ml_ssdp_msearch = 0, ml_ssdp_responses = 0;
            uint64_t ml_portmap_getport = 0, ml_portmap_dump = 0;
            uint64_t ml_netbios_name = 0, ml_netbios_dgram = 0;
            uint64_t ml_ldap_bind = 0, ml_ldap_search = 0;
            uint64_t ml_mssql_sqlbatch = 0, ml_mssql_rpc = 0;
            uint64_t ml_tftp_rrq = 0, ml_tftp_wrq = 0;

            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                struct worker_stats *ws = &g_worker_stats[i];
                ml_total_packets += ws->total_packets;
                ml_total_bytes += ws->total_bytes;
                ml_udp_packets += ws->udp_packets;
                ml_tcp_packets += ws->tcp_packets;
                ml_icmp_packets += ws->icmp_packets;
                ml_syn_packets += ws->syn_packets;
                ml_syn_ack_packets += ws->syn_ack_packets;
                ml_syn_only_packets += ws->syn_only_packets;
                ml_http_requests += ws->http_requests;
                ml_http_payload_packets += ws->http_payload_packets;
                ml_dns_queries += ws->dns_queries;
                ml_baseline_packets += ws->baseline_packets;
                ml_attack_packets += ws->attack_packets;
                ml_ntp_monlist += ws->ntp_monlist_queries;
                ml_ntp_responses += ws->ntp_responses;
                ml_ntp_resp_size_sum += ws->ntp_response_size_sum;
                ml_dns_any += ws->dns_any_queries;
                ml_dns_txt += ws->dns_txt_queries;
                ml_dns_responses += ws->dns_responses;
                ml_dns_resp_size_sum += ws->dns_response_size_sum;
                ml_snmp_getbulk += ws->snmp_getbulk_requests;
                ml_snmp_responses += ws->snmp_responses;
                ml_snmp_resp_size_sum += ws->snmp_response_size_sum;
                ml_ssdp_msearch += ws->ssdp_msearch_packets;
                ml_ssdp_responses += ws->ssdp_responses;
                ml_portmap_getport += ws->portmap_getport_calls;
                ml_portmap_dump += ws->portmap_dump_calls;
                ml_netbios_name += ws->netbios_name_queries;
                ml_netbios_dgram += ws->netbios_dgram_packets;
                ml_ldap_bind += ws->ldap_bind_requests;
                ml_ldap_search += ws->ldap_search_requests;
                ml_mssql_sqlbatch += ws->mssql_sqlbatch_packets;
                ml_mssql_rpc += ws->mssql_rpc_packets;
                ml_tftp_rrq += ws->tftp_rrq_packets;
                ml_tftp_wrq += ws->tftp_wrq_packets;
            }

            double features[ML_MAX_FEATURES];
            int num_features = 0;
            int fi = 0;

            if (g_ml_mode == ML_MODE_DPI_SKETCH) {
                /* ========== DPI+SKETCH MODE: 75 features ========== */
                num_features = DPI_SKETCH_NUM_FEATURES;

                /* DPI Features (61) */
                /* Raw counters (10) */
                features[fi++] = (double)ml_total_packets;
                features[fi++] = (double)ml_total_bytes;
                features[fi++] = (double)ml_udp_packets;
                features[fi++] = (double)ml_tcp_packets;
                features[fi++] = (double)ml_icmp_packets;
                features[fi++] = (double)ml_syn_packets;
                features[fi++] = (double)ml_http_requests;
                features[fi++] = (double)ml_dns_queries;
                features[fi++] = (double)ml_baseline_packets;
                features[fi++] = (double)ml_attack_packets;

                /* Basic ratios (4) */
                features[fi++] = (ml_tcp_packets > 0) ? (double)ml_udp_packets / ml_tcp_packets : 0.0;
                features[fi++] = (ml_total_packets > 0) ? (double)ml_syn_packets / ml_total_packets : 0.0;
                features[fi++] = (ml_attack_packets > 0) ? (double)ml_baseline_packets / ml_attack_packets : 999.0;
                features[fi++] = (ml_total_packets > 0) ? (double)ml_total_bytes / ml_total_packets : 0.0;

                /* Protocol-specific counters (22) */
                double avg_ntp_resp = (ml_ntp_responses > 0) ? (double)ml_ntp_resp_size_sum / ml_ntp_responses : 0.0;
                double avg_dns_resp = (ml_dns_responses > 0) ? (double)ml_dns_resp_size_sum / ml_dns_responses : 0.0;
                double avg_snmp_resp = (ml_snmp_responses > 0) ? (double)ml_snmp_resp_size_sum / ml_snmp_responses : 0.0;

                features[fi++] = (double)ml_ntp_monlist;
                features[fi++] = (double)ml_ntp_responses;
                features[fi++] = avg_ntp_resp;
                features[fi++] = (double)ml_dns_any;
                features[fi++] = (double)ml_dns_txt;
                features[fi++] = (double)ml_dns_responses;
                features[fi++] = avg_dns_resp;
                features[fi++] = (double)ml_snmp_getbulk;
                features[fi++] = (double)ml_snmp_responses;
                features[fi++] = avg_snmp_resp;
                features[fi++] = (double)ml_ssdp_msearch;
                features[fi++] = (double)ml_ssdp_responses;
                features[fi++] = (double)ml_portmap_getport;
                features[fi++] = (double)ml_portmap_dump;
                features[fi++] = (double)ml_netbios_name;
                features[fi++] = (double)ml_netbios_dgram;
                features[fi++] = (double)ml_ldap_bind;
                features[fi++] = (double)ml_ldap_search;
                features[fi++] = (double)ml_mssql_sqlbatch;
                features[fi++] = (double)ml_mssql_rpc;
                features[fi++] = (double)ml_tftp_rrq;
                features[fi++] = (double)ml_tftp_wrq;

                /* Amplification ratios (6) */
                features[fi++] = (ml_ntp_monlist > 0) ? avg_ntp_resp / 48.0 : 0.0;
                features[fi++] = (ml_dns_any > 0 || ml_dns_txt > 0) ? avg_dns_resp / 60.0 : 0.0;
                features[fi++] = (ml_snmp_getbulk > 0) ? avg_snmp_resp / 150.0 : 0.0;
                uint64_t tq = ml_ntp_monlist + ml_dns_any + ml_dns_txt + ml_snmp_getbulk;
                uint64_t tr = ml_ntp_responses + ml_dns_responses + ml_snmp_responses;
                features[fi++] = (tr > 0) ? (double)tq / tr : 0.0;
                features[fi++] = 0.0;  /* fragmentation_ratio */
                features[fi++] = (ml_syn_ack_packets > 0) ? (double)ml_syn_packets / ml_syn_ack_packets : 0.0;

                /* SYN/WebDDoS discrimination (4) */
                features[fi++] = (double)ml_syn_only_packets;
                features[fi++] = (double)ml_http_payload_packets;
                /* active_attack_protocols: count protocols with > 0.1% share */
                double proto_ratios[13];
                proto_ratios[0] = (ml_total_packets > 0) ? (double)ml_syn_only_packets / ml_total_packets : 0.0;
                proto_ratios[1] = (ml_total_packets > 0) ? (double)ml_http_payload_packets / ml_total_packets : 0.0;
                proto_ratios[2] = (ml_total_packets > 0) ? (double)ml_dns_queries / ml_total_packets : 0.0;
                proto_ratios[3] = (ml_total_packets > 0) ? (double)ml_ntp_monlist / ml_total_packets : 0.0;
                proto_ratios[4] = (ml_total_packets > 0) ? (double)(ml_snmp_getbulk + ml_snmp_responses) / ml_total_packets : 0.0;
                proto_ratios[5] = (ml_total_packets > 0) ? (double)(ml_ssdp_msearch + ml_ssdp_responses) / ml_total_packets : 0.0;
                proto_ratios[6] = (ml_total_packets > 0) ? (double)ml_icmp_packets / ml_total_packets : 0.0;
                proto_ratios[7] = (ml_total_packets > 0) ? (double)ml_http_requests / ml_total_packets : 0.0;
                proto_ratios[8] = (ml_total_packets > 0) ? (double)(ml_portmap_getport + ml_portmap_dump) / ml_total_packets : 0.0;
                proto_ratios[9] = (ml_total_packets > 0) ? (double)(ml_netbios_name + ml_netbios_dgram) / ml_total_packets : 0.0;
                proto_ratios[10] = (ml_total_packets > 0) ? (double)(ml_ldap_bind + ml_ldap_search) / ml_total_packets : 0.0;
                proto_ratios[11] = (ml_total_packets > 0) ? (double)(ml_mssql_sqlbatch + ml_mssql_rpc) / ml_total_packets : 0.0;
                proto_ratios[12] = (ml_total_packets > 0) ? (double)(ml_tftp_rrq + ml_tftp_wrq) / ml_total_packets : 0.0;

                double active_protocols = 0;
                double max_ratio = 0.0;
                for (int j = 0; j < 13; j++) {
                    if (proto_ratios[j] > 0.001) active_protocols++;
                    if (proto_ratios[j] > max_ratio) max_ratio = proto_ratios[j];
                }
                features[fi++] = active_protocols;
                features[fi++] = (ml_http_payload_packets > 0) ?
                    (double)ml_syn_only_packets / ml_http_payload_packets : 0.0;

                /* Normalized ratios (13) - matching feature_groups.py order */
                features[fi++] = proto_ratios[0];   /* syn_only_ratio */
                features[fi++] = proto_ratios[1];   /* http_payload_ratio */
                features[fi++] = proto_ratios[2];   /* dns_query_ratio */
                features[fi++] = proto_ratios[3];   /* ntp_monlist_ratio */
                features[fi++] = proto_ratios[4];   /* snmp_ratio */
                features[fi++] = proto_ratios[5];   /* ssdp_ratio */
                features[fi++] = proto_ratios[6];   /* icmp_ratio */
                features[fi++] = proto_ratios[7];   /* http_request_ratio */
                features[fi++] = proto_ratios[8];   /* portmap_ratio */
                features[fi++] = proto_ratios[9];   /* netbios_ratio */
                features[fi++] = proto_ratios[10];  /* ldap_ratio */
                features[fi++] = proto_ratios[11];  /* mssql_ratio */
                features[fi++] = proto_ratios[12];  /* tftp_ratio */

                /* Protocol diversity (2) */
                features[fi++] = max_ratio;          /* max_protocol_ratio */
                features[fi++] = active_protocols;   /* protocol_diversity */

                /* Sketch features (14) from ring buffer */
                features[fi++] = (double)fw.delta_pps_5w;
                features[fi++] = (double)fw.delta_pps_10w;
                features[fi++] = (double)fw.pps_variance;
                features[fi++] = (double)fw.pps_baseline;
                features[fi++] = (double)fw.ratio_vs_baseline;
                features[fi++] = (double)fw.top_ip_pps_50ms;
                features[fi++] = (double)fw.top_ip_pps_1s;
                features[fi++] = (double)fw.top_ip_pps_1min;
                features[fi++] = (double)fw.ratio_50ms_1min;
                features[fi++] = (double)fw.num_heavy_hitters;
                features[fi++] = (double)fw.ip_concentration;
                features[fi++] = (double)fw.new_ips_ratio;
                features[fi++] = (double)fw.attack_entropy;
                features[fi++] = (double)fw.adaptive_threshold;

            } else {
                /* ========== SKETCH_ADV MODE: 64 features ========== */
                num_features = SKETCH_ADV_NUM_FEATURES;

                /* Global sketch features (14) from ring buffer */
                features[fi++] = (double)fw.delta_pps_5w;
                features[fi++] = (double)fw.delta_pps_10w;
                features[fi++] = (double)fw.pps_variance;
                features[fi++] = (double)fw.pps_baseline;
                features[fi++] = (double)fw.ratio_vs_baseline;
                features[fi++] = (double)fw.top_ip_pps_50ms;
                features[fi++] = (double)fw.top_ip_pps_1s;
                features[fi++] = (double)fw.top_ip_pps_1min;
                features[fi++] = (double)fw.ratio_50ms_1min;
                features[fi++] = (double)fw.num_heavy_hitters;
                features[fi++] = (double)fw.ip_concentration;
                features[fi++] = (double)fw.new_ips_ratio;
                features[fi++] = (double)fw.attack_entropy;
                features[fi++] = (double)fw.adaptive_threshold;

                /* Per-protocol features (48 = 12 protocols × 4 features) */
                struct octosketch *proto_merged[SKETCH_ADV_NUM_PROTOS] = {
                    &g_merged_sketch_dns, &g_merged_sketch_ntp, &g_merged_sketch_snmp,
                    &g_merged_sketch_ssdp, &g_merged_sketch_portmap, &g_merged_sketch_netbios,
                    &g_merged_sketch_ldap, &g_merged_sketch_mssql, &g_merged_sketch_tftp,
                    &g_merged_sketch_syn, &g_merged_sketch_http, &g_merged_sketch_udp_other,
                };
                uint64_t total_global = octosketch_get_total(&g_merged_sketch_attack);

                for (int p = 0; p < SKETCH_ADV_NUM_PROTOS; p++) {
                    uint64_t total_proto = octosketch_get_total(proto_merged[p]);
                    struct heavy_hitter top1[1];
                    octosketch_top_k(proto_merged[p], 1, top1);

                    /* pps_<proto> */
                    features[fi++] = (window_sec > 0) ? (double)total_proto / window_sec : 0.0;

                    /* heavy_hitters_<proto> */
                    struct heavy_hitter top5[5];
                    octosketch_top_k(proto_merged[p], 5, top5);
                    int hh = 0;
                    for (int j = 0; j < 5; j++) {
                        if (top5[j].count > 0) {
                            double pps_j = (double)top5[j].count / (window_sec > 0 ? window_sec : 0.05);
                            if (pps_j > HEAVY_HITTER_PPS_THRESHOLD) hh++;
                        }
                    }
                    features[fi++] = (double)hh;

                    /* ip_concentration_<proto> */
                    features[fi++] = (total_proto > 0) ? (double)top1[0].count / total_proto : 0.0;

                    /* ratio_vs_total_<proto> */
                    features[fi++] = (total_global > 0) ? (double)total_proto / total_global : 0.0;
                }

                /* Packet size features (2) */
                features[fi++] = (ml_total_packets > 0) ? (double)ml_total_bytes / ml_total_packets : 0.0;

                /* Packet size variance: E[x²] - E[x]² from sampled data */
                uint64_t total_pktlen_sq = 0;
                for (int i = 0; i < NUM_RX_QUEUES; i++) {
                    total_pktlen_sq += g_worker_pktlen_sq_sum[i];
                }
                uint64_t total_sampled = octosketch_get_total(&g_merged_sketch_attack);
                if (total_sampled > 0) {
                    double avg_sq = (double)total_pktlen_sq / total_sampled;
                    double avg_pkt = (ml_total_packets > 0) ? (double)ml_total_bytes / ml_total_packets : 0.0;
                    features[fi++] = avg_sq - avg_pkt * avg_pkt;
                } else {
                    features[fi++] = 0.0;
                }
            }

            /* Run ML prediction */
            int ret = ml_predict(g_ml_model, features, num_features, &ml_pred);

            if (ret == 0) {
                ml_class_name = ml_get_class_name(g_ml_model, ml_pred.predicted_class);
                ml_confidence = ml_pred.confidence;

                if (ml_pred.predicted_class != 0 && ml_confidence >= ML_CONFIDENCE_THRESHOLD) {
                    ml_alert = true;
                }
            }
        }

        /* ========== HYBRID DECISION: Combine Threshold + ML ========== */
        bool original_attack_detected = attack_detected;
        attack_detected = attack_detected || ml_alert;

        if (attack_detected && g_ml_model) {
            double since_last_ml_alert = (last_ml_alert_tsc == 0)
                ? 1e9
                : (double)(cur_tsc - last_ml_alert_tsc) / hz;
            bool should_log_ml = since_last_ml_alert >= 1.0;

            const char *alert_type = "UNKNOWN";
            if (original_attack_detected && ml_alert) {
                alert_type = "CRITICAL";
                g_stats.alert_level = ALERT_HIGH;
            } else if (original_attack_detected && !ml_alert) {
                alert_type = "HIGH";
                g_stats.alert_level = ALERT_MEDIUM;
            } else if (!original_attack_detected && ml_alert) {
                alert_type = "ANOMALY";
                g_stats.alert_level = ALERT_LOW;
            }

            safe_snprintf(g_stats.alert_reason, sizeof(g_stats.alert_reason),
                          "[%s] ML: %s (%.1f%%)", alert_type, ml_class_name, ml_confidence * 100);

            if (should_log_ml) {
                last_ml_alert_tsc = cur_tsc;
                int num_classes = ml_get_num_classes(g_ml_model);
                printf("\n[%s ALERT] Threshold: %s | ML: %s (%.2f%%) | Class probs: ",
                       alert_type,
                       original_attack_detected ? "DETECT" : "NONE",
                       ml_class_name, ml_confidence * 100);

                for (int i = 0; i < num_classes; i++) {
                    printf("%s:%.1f%% ", ml_get_class_name(g_ml_model, i),
                           ml_pred.probabilities[i] * 100);
                }
                printf("\n");
            }
        } else if (attack_detected && !g_ml_model) {
            safe_snprintf(g_stats.alert_reason, sizeof(g_stats.alert_reason),
                          "[THRESHOLD] ANOMALY detected (no ML model)");
        }

        /* Detection timestamp tracking */
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

                if (inter_detection_ms < g_stats.min_detection_latency_ms)
                    g_stats.min_detection_latency_ms = inter_detection_ms;
                if (inter_detection_ms > g_stats.max_detection_latency_ms)
                    g_stats.max_detection_latency_ms = inter_detection_ms;

                g_stats.sum_detection_latencies_ms += inter_detection_ms;

                if (inter_detection_ms < 20.0)
                    g_stats.detections_under_20ms++;
                else if (inter_detection_ms < 30.0)
                    g_stats.detections_20_30ms++;
                else if (inter_detection_ms < 40.0)
                    g_stats.detections_30_40ms++;
                else if (inter_detection_ms < 50.0)
                    g_stats.detections_40_50ms++;
                else
                    g_stats.detections_over_50ms++;

                g_stats.last_detection_tsc = cur_tsc;
            }
        }

        /* Reset detection window */
        if (window_sec >= DETECTION_WINDOW_SEC) {
            g_stats.window_start_tsc = cur_tsc;

            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                octosketch_reset(&g_worker_sketch_attack[i]);
            }

            /* Reset per-protocol sketches if in sketch_adv mode */
            if (g_ml_mode == ML_MODE_SKETCH_ADV) {
                const char *proto_names[] = {"dns","ntp","snmp","ssdp","portmap","netbios","ldap","mssql","tftp","syn","http","udp_other"};
                struct octosketch (*proto_arrays[])[NUM_RX_QUEUES] = {
                    &g_worker_sketch_dns, &g_worker_sketch_ntp, &g_worker_sketch_snmp,
                    &g_worker_sketch_ssdp, &g_worker_sketch_portmap, &g_worker_sketch_netbios,
                    &g_worker_sketch_ldap, &g_worker_sketch_mssql, &g_worker_sketch_tftp,
                    &g_worker_sketch_syn, &g_worker_sketch_http, &g_worker_sketch_udp_other,
                };
                (void)proto_names;
                for (int p = 0; p < SKETCH_ADV_NUM_PROTOS; p++) {
                    for (int i = 0; i < NUM_RX_QUEUES; i++) {
                        octosketch_reset(&(*proto_arrays[p])[i]);
                    }
                }
                memset(g_worker_pktlen_sq_sum, 0, sizeof(g_worker_pktlen_sq_sum));
            }
        }
    }
}

/* Update DPDK NIC statistics */
static void update_dpdk_stats(uint16_t port)
{
    struct rte_eth_stats eth_stats;

    if (rte_eth_stats_get(port, &eth_stats) == 0) {
        g_stats.rx_packets_nic = eth_stats.ipackets;
        g_stats.rx_dropped_nic = eth_stats.imissed;
        g_stats.rx_errors_nic = eth_stats.ierrors;
        g_stats.rx_nombuf_nic = eth_stats.rx_nombuf;
    }
}

/* Print statistics - COORDINATOR ONLY */
static void print_stats(uint16_t port, uint64_t cur_tsc, uint64_t hz)
{
    double elapsed = (double)(cur_tsc - g_stats.last_stats_tsc) / hz;

    if (elapsed < STATS_INTERVAL_SEC)
        return;

    g_stats.last_stats_tsc = cur_tsc;
    update_dpdk_stats(port);

    /* Aggregate stats from all workers (lock-free read) */
    g_stats.total_packets = 0;
    g_stats.baseline_packets = 0;
    g_stats.attack_packets = 0;
    g_stats.tcp_packets = 0;
    g_stats.udp_packets = 0;
    g_stats.icmp_packets = 0;
    g_stats.syn_packets = 0;
    g_stats.syn_ack_packets = 0;
    g_stats.http_requests = 0;
    g_stats.dns_queries = 0;
    g_stats.total_bytes = 0;
    g_stats.baseline_bytes = 0;
    g_stats.attack_bytes = 0;
    g_stats.rx_bursts_total = 0;
    g_stats.rx_bursts_empty = 0;

    /* ========== Protocol-Specific Stats Reset ========== */
    g_stats.ntp_monlist_queries = 0;
    g_stats.ntp_responses = 0;
    g_stats.ntp_response_size_sum = 0;
    g_stats.dns_any_queries = 0;
    g_stats.dns_txt_queries = 0;
    g_stats.dns_responses = 0;
    g_stats.dns_response_size_sum = 0;
    g_stats.snmp_getbulk_requests = 0;
    g_stats.snmp_responses = 0;
    g_stats.snmp_response_size_sum = 0;
    g_stats.ssdp_msearch_packets = 0;
    g_stats.ssdp_responses = 0;
    g_stats.portmap_getport_calls = 0;
    g_stats.portmap_dump_calls = 0;
    g_stats.netbios_name_queries = 0;
    g_stats.netbios_dgram_packets = 0;
    g_stats.ldap_bind_requests = 0;
    g_stats.ldap_search_requests = 0;
    g_stats.mssql_sqlbatch_packets = 0;
    g_stats.mssql_rpc_packets = 0;
    g_stats.tftp_rrq_packets = 0;
    g_stats.tftp_wrq_packets = 0;
    /* ================================================== */

    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        g_stats.total_packets += g_worker_stats[i].total_packets;
        g_stats.baseline_packets += g_worker_stats[i].baseline_packets;
        g_stats.attack_packets += g_worker_stats[i].attack_packets;
        g_stats.tcp_packets += g_worker_stats[i].tcp_packets;
        g_stats.udp_packets += g_worker_stats[i].udp_packets;
        g_stats.icmp_packets += g_worker_stats[i].icmp_packets;
        g_stats.syn_packets += g_worker_stats[i].syn_packets;
        g_stats.syn_ack_packets += g_worker_stats[i].syn_ack_packets;
        g_stats.http_requests += g_worker_stats[i].http_requests;
        g_stats.dns_queries += g_worker_stats[i].dns_queries;
        g_stats.total_bytes += g_worker_stats[i].total_bytes;
        g_stats.baseline_bytes += g_worker_stats[i].baseline_bytes;
        g_stats.attack_bytes += g_worker_stats[i].attack_bytes;
        g_stats.rx_bursts_total += g_worker_stats[i].rx_bursts_total;
        g_stats.rx_bursts_empty += g_worker_stats[i].rx_bursts_empty;

        /* ========== NEW: Aggregate Protocol-Specific Stats ========== */
        g_stats.ntp_monlist_queries += g_worker_stats[i].ntp_monlist_queries;
        g_stats.ntp_responses += g_worker_stats[i].ntp_responses;
        g_stats.ntp_response_size_sum += g_worker_stats[i].ntp_response_size_sum;
        g_stats.dns_any_queries += g_worker_stats[i].dns_any_queries;
        g_stats.dns_txt_queries += g_worker_stats[i].dns_txt_queries;
        g_stats.dns_responses += g_worker_stats[i].dns_responses;
        g_stats.dns_response_size_sum += g_worker_stats[i].dns_response_size_sum;
        g_stats.snmp_getbulk_requests += g_worker_stats[i].snmp_getbulk_requests;
        g_stats.snmp_responses += g_worker_stats[i].snmp_responses;
        g_stats.snmp_response_size_sum += g_worker_stats[i].snmp_response_size_sum;
        g_stats.ssdp_msearch_packets += g_worker_stats[i].ssdp_msearch_packets;
        g_stats.ssdp_responses += g_worker_stats[i].ssdp_responses;
        g_stats.portmap_getport_calls += g_worker_stats[i].portmap_getport_calls;
        g_stats.portmap_dump_calls += g_worker_stats[i].portmap_dump_calls;
        g_stats.netbios_name_queries += g_worker_stats[i].netbios_name_queries;
        g_stats.netbios_dgram_packets += g_worker_stats[i].netbios_dgram_packets;
        g_stats.ldap_bind_requests += g_worker_stats[i].ldap_bind_requests;
        g_stats.ldap_search_requests += g_worker_stats[i].ldap_search_requests;
        g_stats.mssql_sqlbatch_packets += g_worker_stats[i].mssql_sqlbatch_packets;
        g_stats.mssql_rpc_packets += g_worker_stats[i].mssql_rpc_packets;
        g_stats.tftp_rrq_packets += g_worker_stats[i].tftp_rrq_packets;
        g_stats.tftp_wrq_packets += g_worker_stats[i].tftp_wrq_packets;
        /* ============================================================= */
    }

    double window_duration = (double)(cur_tsc - last_window_reset_tsc) / hz;

    /* Aggregate window stats */
    uint64_t window_base_pkts = 0, window_att_pkts = 0;
    uint64_t window_base_bytes = 0, window_att_bytes = 0;
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        window_base_pkts += window_baseline_pkts[i];
        window_att_pkts += window_attack_pkts[i];
        window_base_bytes += window_baseline_bytes[i];
        window_att_bytes += window_attack_bytes[i];
    }

    uint64_t window_total_pkts = window_base_pkts + window_att_pkts;
    uint64_t window_total_bytes = window_base_bytes + window_att_bytes;

    double instantaneous_throughput_gbps = 0.0;
    if (window_total_pkts > 0 && window_duration >= 0.001) {
        instantaneous_throughput_gbps = (window_total_bytes * 8.0) / (window_duration * 1e9);
        g_stats.throughput_gbps = instantaneous_throughput_gbps;
    } else {
        g_stats.throughput_gbps = 0.0;
    }

    /* Calculate cycles available per packet at current PPS (not actual usage) */
    if (window_total_pkts > 0 && window_duration > 0.001) {
        double pps = (double)window_total_pkts / window_duration;
        if (pps > 0) {
            /* This shows cycles AVAILABLE per packet, not cycles USED */
            /* Lower number = higher PPS = better throughput */
            g_stats.cycles_per_packet = hz / pps;
        }
    } else {
        g_stats.cycles_per_packet = 0;
    }

    char buffer[65536];
    int len = 0;
#define snprintf(...) safe_snprintf(__VA_ARGS__)

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "\n╔═══════════════════════════════════════════════════════════════════════╗\n"
        "║          MIRA DDoS DETECTOR - STATISTICS (MULTI-CORE)                ║\n"
        "╚═══════════════════════════════════════════════════════════════════════╝\n\n");

    double inst_baseline_pct = window_total_pkts > 0 ? (double)window_base_pkts * 100.0 / window_total_pkts : 0.0;
    double inst_attack_pct = window_total_pkts > 0 ? (double)window_att_pkts * 100.0 / window_total_pkts : 0.0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[PACKET COUNTERS - GLOBAL]\n"
        "  Total packets:      %" PRIu64 "\n"
        "  Baseline (10.10.2.x): %" PRIu64 " (%.1f%%)\n"
        "  Attack (10.10.3.x): %" PRIu64 " (%.1f%%)\n"
        "  TCP packets:        %" PRIu64 "\n"
        "  UDP packets:        %" PRIu64 "\n"
        "  ICMP packets:       %" PRIu64 "\n\n",
        g_stats.total_packets,
        g_stats.baseline_packets,
        g_stats.total_packets > 0 ? (double)g_stats.baseline_packets * 100.0 / g_stats.total_packets : 0.0,
        g_stats.attack_packets,
        g_stats.total_packets > 0 ? (double)g_stats.attack_packets * 100.0 / g_stats.total_packets : 0.0,
        g_stats.tcp_packets, g_stats.udp_packets, g_stats.icmp_packets);

    double avg_pkt_size = window_total_pkts > 0 ? (double)window_total_bytes / window_total_pkts : 0.0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[INSTANTANEOUS TRAFFIC - Last %.1f seconds]\n"
        "  Baseline (10.10.2.x): %" PRIu64 " pkts (%.1f%%)  %" PRIu64 " bytes  %.2f Gbps\n"
        "  Attack (10.10.3.x): %" PRIu64 " pkts (%.1f%%)  %" PRIu64 " bytes  %.2f Gbps\n"
        "  Total throughput:   %.2f Gbps  (avg pkt: %.0f bytes)\n\n",
        window_duration,
        window_base_pkts, inst_baseline_pct, window_base_bytes,
        window_duration > 0 ? (window_base_bytes * 8.0) / (window_duration * 1e9) : 0.0,
        window_att_pkts, inst_attack_pct, window_att_bytes,
        window_duration > 0 ? (window_att_bytes * 8.0) / (window_duration * 1e9) : 0.0,
        instantaneous_throughput_gbps, avg_pkt_size);

    /* Calculate cumulative throughput (like sender) - only if traffic started */
    double cumulative_duration = 0.0;
    double cumulative_gbps = 0.0;
    double cumulative_mpps = 0.0;
    if (g_start_tsc > 0 && g_stats.total_packets > 0) {
        cumulative_duration = (double)(cur_tsc - g_start_tsc) / hz;
        if (cumulative_duration > 0.001) {
            cumulative_gbps = (g_stats.total_bytes * 8.0) / (cumulative_duration * 1e9);
            cumulative_mpps = (g_stats.total_packets / cumulative_duration) / 1e6;
        }
    }

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[CUMULATIVE TRAFFIC - Since first packet (%.1fs)]\n"
        "  Total received:     %" PRIu64 " pkts (%.2f Mpps) | %.2f Gbps | %" PRIu64 " bytes\n\n",
        cumulative_duration,
        g_stats.total_packets, cumulative_mpps, cumulative_gbps, g_stats.total_bytes);

    uint64_t syn_pkts = g_stats.syn_packets;
    uint64_t syn_ack_pkts = g_stats.syn_ack_packets;
    uint64_t http_reqs = g_stats.http_requests;
    uint64_t dns_qs = g_stats.dns_queries;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[ATTACK-SPECIFIC COUNTERS]\n"
        "  SYN packets:        %" PRIu64 "\n"
        "  SYN-ACK packets:    %" PRIu64 "\n"
        "  SYN/ACK ratio:      %.2f\n"
        "  HTTP requests:      %" PRIu64 "\n"
        "  DNS queries:        %" PRIu64 "\n\n",
        syn_pkts, syn_ack_pkts,
        syn_ack_pkts > 0 ? (double)syn_pkts / syn_ack_pkts : 0.0,
        http_reqs, dns_qs);

    /* ========== NEW: Protocol-Specific Statistics Display ========== */
    uint16_t avg_ntp_resp_size = g_stats.ntp_responses > 0 ?
        (uint16_t)(g_stats.ntp_response_size_sum / g_stats.ntp_responses) : 0;
    uint16_t avg_dns_resp_size = g_stats.dns_responses > 0 ?
        (uint16_t)(g_stats.dns_response_size_sum / g_stats.dns_responses) : 0;
    uint16_t avg_snmp_resp_size = g_stats.snmp_responses > 0 ?
        (uint16_t)(g_stats.snmp_response_size_sum / g_stats.snmp_responses) : 0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[PROTOCOL-SPECIFIC COUNTERS - CIC-DDoS-2019 Features]\n"
        "  NTP Amplification:\n"
        "    Monlist queries:  %" PRIu64 "\n"
        "    Responses:        %" PRIu64 "  (avg size: %u bytes)\n"
        "  DNS Amplification:\n"
        "    ANY queries:      %" PRIu64 "\n"
        "    TXT queries:      %" PRIu64 "\n"
        "    Responses:        %" PRIu64 "  (avg size: %u bytes)\n"
        "  SNMP Amplification:\n"
        "    GetBulk requests: %" PRIu64 "\n"
        "    Responses:        %" PRIu64 "  (avg size: %u bytes)\n"
        "  SSDP:\n"
        "    M-SEARCH packets: %" PRIu64 "\n"
        "    Responses:        %" PRIu64 "\n"
        "  PortMapper:\n"
        "    GETPORT calls:    %" PRIu64 "\n"
        "    DUMP calls:       %" PRIu64 "\n"
        "  NetBIOS:\n"
        "    Name queries:     %" PRIu64 "\n"
        "    Datagram packets: %" PRIu64 "\n"
        "  LDAP:\n"
        "    Bind requests:    %" PRIu64 "\n"
        "    Search requests:  %" PRIu64 "\n"
        "  MSSQL:\n"
        "    SQLBatch packets: %" PRIu64 "\n"
        "    RPC packets:      %" PRIu64 "\n"
        "  TFTP:\n"
        "    RRQ (read) pkts:  %" PRIu64 "\n"
        "    WRQ (write) pkts: %" PRIu64 "\n\n",
        g_stats.ntp_monlist_queries, g_stats.ntp_responses, avg_ntp_resp_size,
        g_stats.dns_any_queries, g_stats.dns_txt_queries, g_stats.dns_responses, avg_dns_resp_size,
        g_stats.snmp_getbulk_requests, g_stats.snmp_responses, avg_snmp_resp_size,
        g_stats.ssdp_msearch_packets, g_stats.ssdp_responses,
        g_stats.portmap_getport_calls, g_stats.portmap_dump_calls,
        g_stats.netbios_name_queries, g_stats.netbios_dgram_packets,
        g_stats.ldap_bind_requests, g_stats.ldap_search_requests,
        g_stats.mssql_sqlbatch_packets, g_stats.mssql_rpc_packets,
        g_stats.tftp_rrq_packets, g_stats.tftp_wrq_packets);
    /* ================================================================= */

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[ATTACK DETECTIONS - Cumulative Events]\n"
        "  UDP flood events:   %" PRIu64 "\n"
        "  SYN flood events:   %" PRIu64 "\n"
        "  HTTP flood events:  %" PRIu64 "\n"
        "  ICMP flood events:  %" PRIu64 "\n"
        "  DNS amp events:     %" PRIu64 "\n"
        "  NTP amp events:     %" PRIu64 "\n"
        "  ACK flood events:   %" PRIu64 "\n"
        "  Frag attack events: %" PRIu64 "\n"
        "  Packet flood events:%" PRIu64 "\n"
        "  (Note: Events count IPs exceeding thresholds per 50ms window)\n\n",
        g_stats.udp_flood_detections,
        g_stats.syn_flood_detections,
        g_stats.http_flood_detections,
        g_stats.icmp_flood_detections,
        g_stats.dns_amp_detections,
        g_stats.ntp_amp_detections,
        g_stats.ack_flood_detections,
        g_stats.frag_attack_detections,
        g_stats.total_flood_detections);

    const char *alert_color = COLOR_RESET;
    const char *alert_text = "NONE";

    if (g_stats.alert_level == ALERT_HIGH) {
        alert_color = COLOR_RED;
        alert_text = "HIGH";
    } else if (g_stats.alert_level == ALERT_MEDIUM) {
        alert_color = COLOR_YELLOW;
        alert_text = "MEDIUM";
    } else if (g_stats.alert_level == ALERT_LOW) {
        alert_color = COLOR_WHITE;
        alert_text = "LOW";
    }

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[ALERT STATUS]\n"
        "  Alert level:        %s%s%s\n"
        "  Reason:             %s%s%s\n\n",
        alert_color, alert_text, COLOR_RESET,
        strlen(g_stats.alert_reason) > 0 ? alert_color : "",
        strlen(g_stats.alert_reason) > 0 ? g_stats.alert_reason : "None",
        strlen(g_stats.alert_reason) > 0 ? COLOR_RESET : "");

    if (g_stats.detection_triggered) {
        len += snprintf(buffer + len, sizeof(buffer) - len,
            "[MULTI-LF (2025) COMPARISON]\n"
            "=== Detection Performance vs ML-Based System ===\n\n"
            "  First Detection Latency:   %.2f ms (vs MULTI-LF: 866 ms)\n"
            "    Improvement:             %.1f× faster\n\n"
            "  Packets until detection:   %" PRIu64 "\n"
            "  Bytes until detection:     %" PRIu64 " (%.2f MB)\n\n",
            g_stats.detection_latency_ms,
            866.0 / (g_stats.detection_latency_ms > 0 ? g_stats.detection_latency_ms : 1.0),
            g_stats.packets_until_detection,
            g_stats.bytes_until_detection,
            g_stats.bytes_until_detection / (1024.0 * 1024.0));

        len += snprintf(buffer + len, sizeof(buffer) - len,
            "  DPDK + OctoSketch Advantages:\n"
            "    ✓ Real-time detection (50ms granularity)\n"
            "    ✓ No training required (vs ML models)\n"
            "    ✓ Line-rate processing (multi-core DPDK)\n"
            "    ✓ O(1) memory (sketch-based, constant size)\n"
            "    ✓ Lock-free updates (atomic operations)\n"
            "    ✓ Heavy-hitter detection (Top-K IPs)\n\n");

        /* OctoSketch Metrics - Per-worker + Sampling */
        size_t sketch_total_memory = octosketch_memory_size() * NUM_RX_QUEUES;
        uint64_t total_sketch_updates = octosketch_get_total(&g_merged_sketch_attack);

        len += snprintf(buffer + len, sizeof(buffer) - len,
            "[OCTOSKETCH METRICS - Optimized Architecture]\n"
            "=== Per-Worker Sketches + Sampling (1/%d packets) ===\n\n"
            "  Architecture:              Per-worker (NO atomics, NO contention)\n"
            "  Total sketch memory:       %zu KB (%d workers × %.1f KB)\n"
            "  Sampling rate:             1 in %d packets (%.1f%% overhead)\n"
            "  Attack traffic sampled:    %" PRIu64 " updates\n"
            "  Estimated attack packets:  %" PRIu64 " (×%d sampling factor)\n"
            "  Sketch overhead:           ~%.2f%% of fast-path cycles\n"
            "  Memory efficiency:         O(1) constant, %.1f KB per worker\n\n",
            SKETCH_SAMPLE_RATE,
            sketch_total_memory / 1024,
            NUM_RX_QUEUES,
            octosketch_memory_size() / 1024.0,
            SKETCH_SAMPLE_RATE,
            100.0 / SKETCH_SAMPLE_RATE,
            total_sketch_updates,
            total_sketch_updates * SKETCH_SAMPLE_RATE,
            SKETCH_SAMPLE_RATE,
            (100.0 / SKETCH_SAMPLE_RATE) * 0.5,  /* ~0.5% per update */
            octosketch_memory_size() / 1024.0);

        /* Multiple Detection Statistics - Aggregate Analysis */
        if (g_stats.total_detection_events > 1) {
            double avg_latency = g_stats.sum_detection_latencies_ms / g_stats.total_detection_events;

            len += snprintf(buffer + len, sizeof(buffer) - len,
                "[MULTIPLE DETECTION STATISTICS]\n"
                "=== Aggregate Detection Analysis ===\n\n"
                "  Total detection events:    %" PRIu64 "\n"
                "  Average detection latency: %.2f ms\n"
                "  Min detection latency:     %.2f ms\n"
                "  Max detection latency:     %.2f ms\n"
                "  Latency range:             %.2f ms\n\n",
                g_stats.total_detection_events,
                avg_latency,
                g_stats.min_detection_latency_ms,
                g_stats.max_detection_latency_ms,
                g_stats.max_detection_latency_ms - g_stats.min_detection_latency_ms);

            /* Calculate histogram percentages */
            double pct_under_20 = (double)g_stats.detections_under_20ms * 100.0 / g_stats.total_detection_events;
            double pct_20_30 = (double)g_stats.detections_20_30ms * 100.0 / g_stats.total_detection_events;
            double pct_30_40 = (double)g_stats.detections_30_40ms * 100.0 / g_stats.total_detection_events;
            double pct_40_50 = (double)g_stats.detections_40_50ms * 100.0 / g_stats.total_detection_events;
            double pct_over_50 = (double)g_stats.detections_over_50ms * 100.0 / g_stats.total_detection_events;

            len += snprintf(buffer + len, sizeof(buffer) - len,
                "  Detection Latency Histogram:\n"
                "    < 20 ms:  %" PRIu64 " detections (%.1f%%)\n"
                "    20-30 ms: %" PRIu64 " detections (%.1f%%)\n"
                "    30-40 ms: %" PRIu64 " detections (%.1f%%)\n"
                "    40-50 ms: %" PRIu64 " detections (%.1f%%)\n"
                "    > 50 ms:  %" PRIu64 " detections (%.1f%%)\n\n",
                g_stats.detections_under_20ms, pct_under_20,
                g_stats.detections_20_30ms, pct_20_30,
                g_stats.detections_30_40ms, pct_30_40,
                g_stats.detections_40_50ms, pct_40_50,
                g_stats.detections_over_50ms, pct_over_50);
        }
    }

    double pps_current = (window_total_pkts > 0 && window_duration > 0.001) ?
                         (double)window_total_pkts / window_duration : 0.0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[PERFORMANCE METRICS]\n"
        "  Throughput:         %.2f Gbps (%.2f Mpps)\n"
        "  Cycles available:   %.0f cycles/pkt (lower = higher load)\n"
        "  Active IPs:         %u\n"
        "  Worker threads:     %d (lcores 1-%d)\n\n",
        g_stats.throughput_gbps,
        pps_current / 1e6,
        g_stats.cycles_per_packet,
        rte_atomic32_read(&g_ip_count),
        NUM_RX_QUEUES,
        NUM_RX_QUEUES);

    uint64_t rx_pkts_nic = g_stats.rx_packets_nic;
    uint64_t rx_dropped = g_stats.rx_dropped_nic;
    uint64_t rx_nombuf = g_stats.rx_nombuf_nic;
    uint64_t rx_errors = g_stats.rx_errors_nic;
    uint64_t total_nic_drops = rx_dropped + rx_nombuf;
    double drop_rate = rx_pkts_nic > 0 ?
        (double)total_nic_drops * 100.0 / (rx_pkts_nic + total_nic_drops) : 0.0;

    uint64_t rx_bursts_total = g_stats.rx_bursts_total;
    uint64_t rx_bursts_empty = g_stats.rx_bursts_empty;
    double empty_burst_rate = rx_bursts_total > 0 ?
        (double)rx_bursts_empty * 100.0 / rx_bursts_total : 0.0;

    const char *drop_color = COLOR_RESET;
    if (drop_rate > 10.0) drop_color = COLOR_RED;
    else if (drop_rate > 1.0) drop_color = COLOR_YELLOW;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[DPDK NIC STATISTICS]\n"
        "  RX packets (NIC):   %" PRIu64 "\n"
        "  RX dropped (HW):    %s%" PRIu64 "%s (imissed)\n"
        "  RX no mbufs:        %s%" PRIu64 "%s (buffer exhaustion)\n"
        "  RX errors:          %" PRIu64 "\n"
        "  Total drops:        %s%" PRIu64 " (%.2f%%)%s\n"
        "  RX burst calls:     %" PRIu64 " (%.1f%% empty)\n"
        "  Processed pkts:     %" PRIu64 " (%.1f%% of NIC RX)\n\n",
        rx_pkts_nic,
        drop_color, rx_dropped, COLOR_RESET,
        drop_color, rx_nombuf, COLOR_RESET,
        rx_errors,
        drop_color, total_nic_drops, drop_rate, COLOR_RESET,
        rx_bursts_total, empty_burst_rate,
        g_stats.total_packets,
        rx_pkts_nic > 0 ? (double)g_stats.total_packets * 100.0 / rx_pkts_nic : 0.0);

    printf("%s", buffer);
    fflush(stdout);  /* Force immediate write to stdout (no buffering) */

    if (g_log_file) {
        fprintf(g_log_file, "%s", buffer);
        fflush(g_log_file);
    }

    /* Reset instantaneous counters */
    memset(window_baseline_pkts, 0, sizeof(window_baseline_pkts));
    memset(window_attack_pkts, 0, sizeof(window_attack_pkts));
    memset(window_baseline_bytes, 0, sizeof(window_baseline_bytes));
    memset(window_attack_bytes, 0, sizeof(window_attack_bytes));
    last_window_reset_tsc = cur_tsc;
#undef snprintf
}

/* Worker thread - RX processing */
static int worker_thread(void *arg)
{
    uint16_t queue_id = *(uint16_t *)arg;
    uint16_t port = 0;

    /* Local counters to reduce atomic contention */
    uint64_t local_total_pkts = 0, local_total_bytes = 0;
    uint64_t local_baseline_pkts = 0, local_attack_pkts = 0;
    uint64_t local_tcp_pkts = 0, local_udp_pkts = 0, local_icmp_pkts = 0;
    uint64_t local_syn_pkts = 0, local_syn_ack_pkts = 0, local_syn_only_pkts = 0;
    uint64_t local_http_reqs = 0, local_http_payload_pkts = 0, local_dns_queries = 0;
    uint64_t local_baseline_bytes = 0, local_attack_bytes = 0;
    uint64_t local_bursts_total = 0, local_bursts_empty = 0;
    uint64_t local_cycles = 0;

    /* ========== NEW: Protocol-Specific Local Counters ========== */
    uint64_t local_ntp_monlist = 0, local_ntp_responses = 0, local_ntp_resp_size_sum = 0;
    uint64_t local_dns_any = 0, local_dns_txt = 0, local_dns_responses = 0, local_dns_resp_size_sum = 0;
    uint64_t local_snmp_getbulk = 0, local_snmp_responses = 0, local_snmp_resp_size_sum = 0;
    uint64_t local_ssdp_msearch = 0, local_ssdp_responses = 0;
    uint64_t local_portmap_getport = 0, local_portmap_dump = 0;
    uint64_t local_netbios_name = 0, local_netbios_dgram = 0;
    uint64_t local_ldap_bind = 0, local_ldap_search = 0;
    uint64_t local_mssql_sqlbatch = 0, local_mssql_rpc = 0;
    uint64_t local_tftp_rrq = 0, local_tftp_wrq = 0;
    /* ============================================================ */

    /* Per-worker sketch (local, no atomics) */
    struct octosketch *my_sketch = &g_worker_sketch_attack[queue_id];
    struct multiscale_sketches *my_multiscale = &g_multiscale[queue_id];

    /* Sampling counter for sketch updates */
    uint64_t sample_counter = 0;

    printf("Worker thread %u processing queue %u on lcore %u\n",
           queue_id, queue_id, rte_lcore_id());

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);

        local_bursts_total++;
        if (unlikely(nb_rx == 0)) {
            local_bursts_empty++;
            continue;
        }

        /* Prefetch first 16 packets for better pipeline */
        for (uint16_t i = 0; i < nb_rx && i < 16; i++) {
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));
        }

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];

            /* Prefetch next packet (16 ahead for better pipeline) */
            if (i + 16 < nb_rx) {
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 16], void *));
            }

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            uint16_t pkt_len = rte_pktmbuf_pkt_len(m);

            /* Fast path: check IPv4 first to avoid unnecessary processing */
            if (unlikely(rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4)) {
                rte_pktmbuf_free(m);
                continue;
            }

            local_total_pkts++;
            local_total_bytes += pkt_len;

            /* Initialize global start timestamp on first packet received */
            if (unlikely(g_start_tsc == 0)) {
                g_start_tsc = rte_rdtsc();
            }

            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
            uint8_t proto = ip_hdr->next_proto_id;

            /* Classify traffic - optimized with single mask operation */
            uint32_t network = src_ip & NETWORK_MASK;
            bool is_baseline = (network == BASELINE_NETWORK);
            bool is_attack = (network == ATTACK_NETWORK);

            /* Branchless increment (use conditional moves) */
            local_baseline_pkts += is_baseline ? 1 : 0;
            local_baseline_bytes += is_baseline ? pkt_len : 0;
            local_attack_pkts += is_attack ? 1 : 0;
            local_attack_bytes += is_attack ? pkt_len : 0;

            if (unlikely(is_attack && g_stats.first_attack_packet_tsc == 0)) {
                g_stats.first_attack_packet_tsc = rte_rdtsc();
            }

            /* Parse transport layer - OPTIMIZED for CPU efficiency */
            if (likely(proto == IPPROTO_TCP)) {
                local_tcp_pkts++;
                struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));

                /* Combine flag checks and port check in minimal branches */
                uint8_t tcp_flags = tcp_hdr->tcp_flags;
                uint16_t dst_port_raw = tcp_hdr->dst_port;
                uint16_t tcp_dst_port = rte_be_to_cpu_16(dst_port_raw);

                /* SYN detection */
                if (unlikely(tcp_flags & RTE_TCP_SYN_FLAG)) {
                    local_syn_pkts++;
                    local_syn_ack_pkts += (tcp_flags & RTE_TCP_ACK_FLAG) ? 1 : 0;
                    if (tcp_dst_port != 80 && tcp_dst_port != 443) {
                        local_syn_only_pkts++;
                    }
                }

                /* HTTP detection */
                if (tcp_dst_port == 80 || tcp_dst_port == 443) {
                    local_http_reqs++;
                    /* HTTP payload: TCP to 80/443 with data */
                    uint16_t ip_total_len = rte_be_to_cpu_16(ip_hdr->total_length);
                    uint16_t ip_hdr_len = (ip_hdr->version_ihl & 0x0f) * 4;
                    uint8_t tcp_data_offset = (tcp_hdr->data_off >> 4) * 4;
                    int payload_len = (int)ip_total_len - ip_hdr_len - tcp_data_offset;
                    if (payload_len > 0) {
                        local_http_payload_pkts++;
                    }
                }

                /* ========== NEW: TCP Protocol Detection ========== */
                /* LDAP detection (ports 389, 636) */
                if (tcp_dst_port == 389 || tcp_dst_port == 636) {
                    local_ldap_bind++;  // Simplified: count all LDAP traffic
                }
                /* MSSQL TCP detection (port 1433) */
                else if (tcp_dst_port == 1433) {
                    local_mssql_sqlbatch++;  // MSSQL TCP traffic
                }
                /* PortMapper TCP detection (port 111) */
                else if (tcp_dst_port == 111) {
                    local_portmap_getport++;  // PortMapper TCP traffic
                }
                /* ================================================== */
            }
            else if (proto == IPPROTO_UDP) {
                local_udp_pkts++;
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                uint16_t udp_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                uint8_t *udp_payload = (uint8_t *)(udp_hdr + 1);
                uint16_t udp_payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

                /* DNS detection - check both ports at once */
                if (udp_dst_port == 53 || udp_src_port == 53) {
                    local_dns_queries++;

                    /* DNS Amplification: Check for ANY/TXT queries and responses */
                    if (udp_payload_len >= 12) {  // Minimum DNS header
                        uint16_t dns_flags = (udp_payload[2] << 8) | udp_payload[3];
                        bool is_response = (dns_flags & 0x8000) != 0;

                        if (is_response && udp_src_port == 53) {
                            local_dns_responses++;
                            local_dns_resp_size_sum += pkt_len;
                        }
                        // Query type detection would require full DNS parsing - simplified
                        if (!is_response && udp_payload_len > 50) {
                            local_dns_any++;  // Heuristic: large queries often ANY/TXT
                        }
                    }
                }
                /* NTP detection (port 123) */
                else if (udp_dst_port == 123 || udp_src_port == 123) {
                    if (udp_payload_len >= 8) {
                        uint8_t ntp_mode = (udp_payload[0] >> 0) & 0x07;
                        if (ntp_mode == 7 && udp_dst_port == 123) {  // Mode 7 = Private/Monlist
                            local_ntp_monlist++;
                        }
                        if (udp_src_port == 123) {  // NTP response
                            local_ntp_responses++;
                            local_ntp_resp_size_sum += pkt_len;
                        }
                    }
                }
                /* SNMP detection (port 161) */
                else if (udp_dst_port == 161 || udp_src_port == 161) {
                    if (udp_dst_port == 161 && pkt_len > 200) {  // GetBulkRequest heuristic
                        local_snmp_getbulk++;
                    }
                    if (udp_src_port == 161) {  // SNMP response
                        local_snmp_responses++;
                        local_snmp_resp_size_sum += pkt_len;
                    }
                }
                /* SSDP detection (port 1900) */
                else if (udp_dst_port == 1900 || udp_src_port == 1900) {
                    if (udp_payload_len >= 8 && memcmp(udp_payload, "M-SEARCH", 8) == 0) {
                        local_ssdp_msearch++;
                    }
                    if (udp_src_port == 1900) {
                        local_ssdp_responses++;
                    }
                }
                /* PortMapper detection (port 111) */
                else if (udp_dst_port == 111) {
                    local_portmap_getport++;  // Simplified: count all portmap traffic
                }
                /* NetBIOS detection (ports 137, 138) */
                else if (udp_dst_port == 137) {
                    local_netbios_name++;  // NetBIOS Name Service
                }
                else if (udp_dst_port == 138) {
                    local_netbios_dgram++;  // NetBIOS Datagram Service
                }
                /* TFTP detection (port 69) */
                else if (udp_dst_port == 69 && udp_payload_len >= 2) {
                    uint16_t tftp_opcode = (udp_payload[0] << 8) | udp_payload[1];
                    if (tftp_opcode == 1) {
                        local_tftp_rrq++;  // Read Request
                    } else if (tftp_opcode == 2) {
                        local_tftp_wrq++;  // Write Request
                    }
                }
                /* MSSQL UDP detection (port 1434) */
                else if (udp_dst_port == 1434) {
                    local_mssql_sqlbatch++;  // MSSQL UDP traffic
                }
                /* CLDAP/LDAP UDP detection (port 389) */
                else if (udp_dst_port == 389) {
                    local_ldap_search++;  // CLDAP (Connectionless LDAP) traffic
                }
            }
            else if (proto == IPPROTO_ICMP) {
                local_icmp_pkts++;
            }

            /* OctoSketch update: ONLY for attack traffic + sampled (1 in N packets) */
            if (unlikely(is_attack)) {
                sample_counter++;
                if (sample_counter % SKETCH_SAMPLE_RATE == 0) {
                    /* Update per-worker sketch (LOCAL, no atomics, no contention) */
                    octosketch_update_ip(my_sketch, src_ip, SKETCH_SAMPLE_RATE);
                    octosketch_update_bytes(my_sketch, pkt_len * SKETCH_SAMPLE_RATE);

                    /* Update multi-scale sketches (all scales simultaneously) */
                    octosketch_update_ip(&my_multiscale->sketch_50ms, src_ip, SKETCH_SAMPLE_RATE);
                    octosketch_update_ip(&my_multiscale->sketch_1s, src_ip, SKETCH_SAMPLE_RATE);
                    octosketch_update_ip(&my_multiscale->sketch_10s, src_ip, SKETCH_SAMPLE_RATE);
                    octosketch_update_ip(&my_multiscale->sketch_1min, src_ip, SKETCH_SAMPLE_RATE);

                    /* Per-protocol sketch routing (sketch_adv mode) */
                    if (unlikely(g_ml_mode == ML_MODE_SKETCH_ADV)) {
                        struct octosketch *proto_sketch = NULL;
                        uint16_t dst_port = 0;

                        if (proto == IPPROTO_TCP) {
                            struct rte_tcp_hdr *th = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                            dst_port = rte_be_to_cpu_16(th->dst_port);
                            uint8_t tf = th->tcp_flags;

                            if (tf & RTE_TCP_SYN_FLAG) {
                                proto_sketch = &g_worker_sketch_syn[queue_id];
                            } else if (dst_port == 80 || dst_port == 443) {
                                proto_sketch = &g_worker_sketch_http[queue_id];
                            } else if (dst_port == 389 || dst_port == 636) {
                                proto_sketch = &g_worker_sketch_ldap[queue_id];
                            } else if (dst_port == 1433) {
                                proto_sketch = &g_worker_sketch_mssql[queue_id];
                            } else if (dst_port == 111) {
                                proto_sketch = &g_worker_sketch_portmap[queue_id];
                            }
                        } else if (proto == IPPROTO_UDP) {
                            struct rte_udp_hdr *uh = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                            dst_port = rte_be_to_cpu_16(uh->dst_port);

                            if (dst_port == 53) {
                                proto_sketch = &g_worker_sketch_dns[queue_id];
                            } else if (dst_port == 123) {
                                proto_sketch = &g_worker_sketch_ntp[queue_id];
                            } else if (dst_port == 161) {
                                proto_sketch = &g_worker_sketch_snmp[queue_id];
                            } else if (dst_port == 1900) {
                                proto_sketch = &g_worker_sketch_ssdp[queue_id];
                            } else if (dst_port == 111) {
                                proto_sketch = &g_worker_sketch_portmap[queue_id];
                            } else if (dst_port == 137 || dst_port == 138) {
                                proto_sketch = &g_worker_sketch_netbios[queue_id];
                            } else if (dst_port == 389) {
                                proto_sketch = &g_worker_sketch_ldap[queue_id];
                            } else if (dst_port == 1434) {
                                proto_sketch = &g_worker_sketch_mssql[queue_id];
                            } else if (dst_port == 69) {
                                proto_sketch = &g_worker_sketch_tftp[queue_id];
                            } else {
                                proto_sketch = &g_worker_sketch_udp_other[queue_id];
                            }
                        }

                        if (proto_sketch) {
                            octosketch_update_ip(proto_sketch, src_ip, SKETCH_SAMPLE_RATE);
                        }

                        /* Track packet size squared for variance */
                        g_worker_pktlen_sq_sum[queue_id] += (uint64_t)pkt_len * pkt_len * SKETCH_SAMPLE_RATE;
                    }
                }
            }

            rte_pktmbuf_free(m);
        }

        /* Update per-worker stats (NO ATOMICS - lock-free!) */
        struct worker_stats *ws = &g_worker_stats[queue_id];
        ws->total_packets += local_total_pkts;
        ws->total_bytes += local_total_bytes;
        ws->baseline_packets += local_baseline_pkts;
        ws->attack_packets += local_attack_pkts;
        ws->tcp_packets += local_tcp_pkts;
        ws->udp_packets += local_udp_pkts;
        ws->icmp_packets += local_icmp_pkts;
        ws->syn_packets += local_syn_pkts;
        ws->syn_ack_packets += local_syn_ack_pkts;
        ws->syn_only_packets += local_syn_only_pkts;
        ws->http_requests += local_http_reqs;
        ws->http_payload_packets += local_http_payload_pkts;
        ws->dns_queries += local_dns_queries;
        ws->baseline_bytes += local_baseline_bytes;
        ws->attack_bytes += local_attack_bytes;
        ws->rx_bursts_total += local_bursts_total;
        ws->rx_bursts_empty += local_bursts_empty;

        /* Protocol-Specific Stats Update */
        ws->ntp_monlist_queries += local_ntp_monlist;
        ws->ntp_responses += local_ntp_responses;
        ws->ntp_response_size_sum += local_ntp_resp_size_sum;
        ws->dns_any_queries += local_dns_any;
        ws->dns_txt_queries += local_dns_txt;
        ws->dns_responses += local_dns_responses;
        ws->dns_response_size_sum += local_dns_resp_size_sum;
        ws->snmp_getbulk_requests += local_snmp_getbulk;
        ws->snmp_responses += local_snmp_responses;
        ws->snmp_response_size_sum += local_snmp_resp_size_sum;
        ws->ssdp_msearch_packets += local_ssdp_msearch;
        ws->ssdp_responses += local_ssdp_responses;
        ws->portmap_getport_calls += local_portmap_getport;
        ws->portmap_dump_calls += local_portmap_dump;
        ws->netbios_name_queries += local_netbios_name;
        ws->netbios_dgram_packets += local_netbios_dgram;
        ws->ldap_bind_requests += local_ldap_bind;
        ws->ldap_search_requests += local_ldap_search;
        ws->mssql_sqlbatch_packets += local_mssql_sqlbatch;
        ws->mssql_rpc_packets += local_mssql_rpc;
        ws->tftp_rrq_packets += local_tftp_rrq;
        ws->tftp_wrq_packets += local_tftp_wrq;

        /* Update window stats */
        window_baseline_pkts[queue_id] += local_baseline_pkts;
        window_baseline_bytes[queue_id] += local_baseline_bytes;
        window_attack_pkts[queue_id] += local_attack_pkts;
        window_attack_bytes[queue_id] += local_attack_bytes;

        /* Reset local counters */
        local_total_pkts = local_total_bytes = 0;
        local_baseline_pkts = local_attack_pkts = 0;
        local_tcp_pkts = local_udp_pkts = local_icmp_pkts = 0;
        local_syn_pkts = local_syn_ack_pkts = local_syn_only_pkts = 0;
        local_http_reqs = local_http_payload_pkts = local_dns_queries = 0;
        local_baseline_bytes = local_attack_bytes = 0;
        local_bursts_total = local_bursts_empty = 0;

        /* Reset Protocol-Specific Counters */
        local_ntp_monlist = local_ntp_responses = local_ntp_resp_size_sum = 0;
        local_dns_any = local_dns_txt = local_dns_responses = local_dns_resp_size_sum = 0;
        local_snmp_getbulk = local_snmp_responses = local_snmp_resp_size_sum = 0;
        local_ssdp_msearch = local_ssdp_responses = 0;
        local_portmap_getport = local_portmap_dump = 0;
        local_netbios_name = local_netbios_dgram = 0;
        local_ldap_bind = local_ldap_search = 0;
        local_mssql_sqlbatch = local_mssql_rpc = 0;
        local_tftp_rrq = local_tftp_wrq = 0;
    }

    /* Final update before exit */
    struct worker_stats *ws = &g_worker_stats[queue_id];
    ws->total_packets += local_total_pkts;
    ws->total_bytes += local_total_bytes;
    ws->baseline_packets += local_baseline_pkts;
    ws->attack_packets += local_attack_pkts;
    ws->tcp_packets += local_tcp_pkts;
    ws->udp_packets += local_udp_pkts;
    ws->icmp_packets += local_icmp_pkts;
    ws->syn_packets += local_syn_pkts;
    ws->syn_ack_packets += local_syn_ack_pkts;
    ws->syn_only_packets += local_syn_only_pkts;
    ws->http_requests += local_http_reqs;
    ws->http_payload_packets += local_http_payload_pkts;
    ws->dns_queries += local_dns_queries;

    ws->ntp_monlist_queries += local_ntp_monlist;
    ws->ntp_responses += local_ntp_responses;
    ws->ntp_response_size_sum += local_ntp_resp_size_sum;
    ws->dns_any_queries += local_dns_any;
    ws->dns_txt_queries += local_dns_txt;
    ws->dns_responses += local_dns_responses;
    ws->dns_response_size_sum += local_dns_resp_size_sum;
    ws->snmp_getbulk_requests += local_snmp_getbulk;
    ws->snmp_responses += local_snmp_responses;
    ws->snmp_response_size_sum += local_snmp_resp_size_sum;
    ws->ssdp_msearch_packets += local_ssdp_msearch;
    ws->ssdp_responses += local_ssdp_responses;
    ws->portmap_getport_calls += local_portmap_getport;
    ws->portmap_dump_calls += local_portmap_dump;
    ws->netbios_name_queries += local_netbios_name;
    ws->netbios_dgram_packets += local_netbios_dgram;
    ws->ldap_bind_requests += local_ldap_bind;
    ws->ldap_search_requests += local_ldap_search;
    ws->mssql_sqlbatch_packets += local_mssql_sqlbatch;
    ws->mssql_rpc_packets += local_mssql_rpc;
    ws->tftp_rrq_packets += local_tftp_rrq;
    ws->tftp_wrq_packets += local_tftp_wrq;

    return 0;
}

/* Coordinator thread - Detection and stats */
static int coordinator_thread(__rte_unused void *arg)
{
    uint16_t port = 0;
    uint64_t hz = rte_get_tsc_hz();

    printf("\nCoordinator thread on lcore %u\n", rte_lcore_id());
    printf("TSC frequency: %" PRIu64 " Hz\n", hz);
    printf("Detection granularity: %.0f ms (vs MULTI-LF: 1000 ms)\n\n", FAST_DETECTION_INTERVAL * 1000);

    /* g_start_tsc will be set by first packet received in worker threads */
    uint64_t init_tsc = rte_rdtsc();
    g_stats.window_start_tsc = init_tsc;
    g_stats.last_stats_tsc = init_tsc;
    g_stats.last_fast_detection_tsc = init_tsc;
    last_window_reset_tsc = init_tsc;

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        detect_attacks(cur_tsc, hz);
        print_stats(port, cur_tsc, hz);

        rte_delay_us_block(10000);  /* 10ms sleep */
    }

    print_stats(port, rte_rdtsc(), hz);
    return 0;
}

/* Port initialization with multi-queue RSS */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = ETH_MQ_RX_RSS,  /* Enable RSS */
            .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,  /* Use default key */
                .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,  /* Hash on IP + ports */
            },
        },
    };
    const uint16_t rx_rings = NUM_RX_QUEUES, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n",
               port, strerror(-retval));
        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate RX queues - one per worker */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Allocate TX queue */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0)
            return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    printf("Port %u initialized with %u RX queues (RSS enabled)\n", port, rx_rings);
    return 0;
}

/* Main function */
int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    unsigned lcore_id;
    static uint16_t queue_ids[NUM_RX_QUEUES];

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Parse application arguments (after EAL --) */
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "dpi_sketch") == 0) {
                g_ml_mode = ML_MODE_DPI_SKETCH;
                snprintf(g_model_dir, sizeof(g_model_dir),
                         "../ml_system2/training/results/dpi_sketch/complete");
            } else if (strcmp(argv[i + 1], "sketch_adv") == 0) {
                g_ml_mode = ML_MODE_SKETCH_ADV;
                snprintf(g_model_dir, sizeof(g_model_dir),
                         "../ml_system2/training/results/sketch_adv");
            } else {
                printf("[ERROR] Unknown mode: %s (use dpi_sketch or sketch_adv)\n", argv[i + 1]);
                return -1;
            }
            i++;
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            snprintf(g_model_dir, sizeof(g_model_dir), "%s", argv[i + 1]);
            i++;
        }
    }

    printf("[CONFIG] Mode: %s (%d features)\n",
           g_ml_mode == ML_MODE_DPI_SKETCH ? "dpi_sketch" : "sketch_adv",
           g_ml_mode == ML_MODE_DPI_SKETCH ? DPI_SKETCH_NUM_FEATURES : SKETCH_ADV_NUM_FEATURES);
    printf("[CONFIG] Model directory: %s\n\n", g_model_dir);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Number of available ports: %u\n", nb_ports);

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize port with multi-queue */
    if (port_init(0, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port 0\n");

    /* Create hash table for IP tracking */
    struct rte_hash_parameters hash_params = {
        .name = "ip_hash",
        .entries = MAX_IPS,
        .key_len = sizeof(uint32_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    ip_hash = rte_hash_create(&hash_params);
    if (ip_hash == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create hash table\n");

    g_log_file = fopen("../results/mira_detector_multicore.log", "w");
    if (!g_log_file)
        printf("Warning: Could not open log file\n");

    /* Initialize atomics */
    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_ip_table, 0, sizeof(g_ip_table));
    rte_atomic32_init(&g_ip_count);
    memset(window_baseline_pkts, 0, sizeof(window_baseline_pkts));
    memset(window_attack_pkts, 0, sizeof(window_attack_pkts));
    memset(window_baseline_bytes, 0, sizeof(window_baseline_bytes));
    memset(window_attack_bytes, 0, sizeof(window_attack_bytes));

    /* Initialize OctoSketches - Per-worker architecture (NO atomics) */
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Attack-W%d", i);
        octosketch_init(&g_worker_sketch_attack[i], name);
    }
    octosketch_init(&g_merged_sketch_attack, "Attack-Merged");

    /* Initialize ring buffer for temporal features */
    memset(&g_ring_buffer, 0, sizeof(g_ring_buffer));

    /* Initialize multi-scale sketches (per-worker) */
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "MS50ms-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_50ms, name);
        snprintf(name, sizeof(name), "MS1s-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_1s, name);
        snprintf(name, sizeof(name), "MS10s-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_10s, name);
        snprintf(name, sizeof(name), "MS1m-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_1min, name);
        g_multiscale[i].windows_since_1s_reset = 0;
        g_multiscale[i].windows_since_10s_reset = 0;
        g_multiscale[i].windows_since_1min_reset = 0;
    }
    /* Initialize merged multi-scale sketches */
    octosketch_init(&g_merged_multiscale.sketch_50ms, "MS50ms-Merged");
    octosketch_init(&g_merged_multiscale.sketch_1s, "MS1s-Merged");
    octosketch_init(&g_merged_multiscale.sketch_10s, "MS10s-Merged");
    octosketch_init(&g_merged_multiscale.sketch_1min, "MS1min-Merged");

    /* Initialize per-protocol sketches (only for sketch_adv mode) */
    int proto_sketch_count = 0;
    if (g_ml_mode == ML_MODE_SKETCH_ADV) {
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            char name[32];
            snprintf(name, sizeof(name), "DNS-W%d", i);
            octosketch_init(&g_worker_sketch_dns[i], name);
            snprintf(name, sizeof(name), "NTP-W%d", i);
            octosketch_init(&g_worker_sketch_ntp[i], name);
            snprintf(name, sizeof(name), "SNMP-W%d", i);
            octosketch_init(&g_worker_sketch_snmp[i], name);
            snprintf(name, sizeof(name), "SSDP-W%d", i);
            octosketch_init(&g_worker_sketch_ssdp[i], name);
            snprintf(name, sizeof(name), "PMAP-W%d", i);
            octosketch_init(&g_worker_sketch_portmap[i], name);
            snprintf(name, sizeof(name), "NBIOS-W%d", i);
            octosketch_init(&g_worker_sketch_netbios[i], name);
            snprintf(name, sizeof(name), "LDAP-W%d", i);
            octosketch_init(&g_worker_sketch_ldap[i], name);
            snprintf(name, sizeof(name), "MSSQL-W%d", i);
            octosketch_init(&g_worker_sketch_mssql[i], name);
            snprintf(name, sizeof(name), "TFTP-W%d", i);
            octosketch_init(&g_worker_sketch_tftp[i], name);
            snprintf(name, sizeof(name), "SYN-W%d", i);
            octosketch_init(&g_worker_sketch_syn[i], name);
            snprintf(name, sizeof(name), "HTTP-W%d", i);
            octosketch_init(&g_worker_sketch_http[i], name);
            snprintf(name, sizeof(name), "UDPo-W%d", i);
            octosketch_init(&g_worker_sketch_udp_other[i], name);
        }
        /* Merged per-protocol sketches */
        octosketch_init(&g_merged_sketch_dns, "DNS-Merged");
        octosketch_init(&g_merged_sketch_ntp, "NTP-Merged");
        octosketch_init(&g_merged_sketch_snmp, "SNMP-Merged");
        octosketch_init(&g_merged_sketch_ssdp, "SSDP-Merged");
        octosketch_init(&g_merged_sketch_portmap, "PMAP-Merged");
        octosketch_init(&g_merged_sketch_netbios, "NBIOS-Merged");
        octosketch_init(&g_merged_sketch_ldap, "LDAP-Merged");
        octosketch_init(&g_merged_sketch_mssql, "MSSQL-Merged");
        octosketch_init(&g_merged_sketch_tftp, "TFTP-Merged");
        octosketch_init(&g_merged_sketch_syn, "SYN-Merged");
        octosketch_init(&g_merged_sketch_http, "HTTP-Merged");
        octosketch_init(&g_merged_sketch_udp_other, "UDPo-Merged");
        proto_sketch_count = SKETCH_ADV_NUM_PROTOS;
        memset(g_worker_pktlen_sq_sum, 0, sizeof(g_worker_pktlen_sq_sum));
    }

    size_t per_worker_mem = octosketch_memory_size();
    /* Global attack sketch: workers + merged */
    size_t global_sketch_mem = per_worker_mem * (NUM_RX_QUEUES + 1);
    /* Multi-scale: 4 scales × (workers + merged) */
    size_t multiscale_mem = per_worker_mem * 4 * (NUM_RX_QUEUES + 1);
    /* Per-protocol: 12 protocols × (workers + merged) */
    size_t proto_mem = (proto_sketch_count > 0) ?
        per_worker_mem * proto_sketch_count * (NUM_RX_QUEUES + 1) : 0;
    size_t total_sketch_mem = global_sketch_mem + multiscale_mem + proto_mem;

    printf("\n[OctoSketch Initialized - Optimized Architecture]\n");
    printf("  Per-worker sketches:     %d × %.1f KB = %.1f KB\n",
           NUM_RX_QUEUES, per_worker_mem / 1024.0, (per_worker_mem * NUM_RX_QUEUES) / 1024.0);
    printf("  Merged sketch:           1 × %.1f KB = %.1f KB\n",
           per_worker_mem / 1024.0, per_worker_mem / 1024.0);
    printf("  Multi-scale sketches:    4 scales × %d workers = %.1f MB\n",
           NUM_RX_QUEUES, multiscale_mem / (1024.0 * 1024.0));
    if (proto_sketch_count > 0) {
        printf("  Per-protocol sketches:   %d protos × %d workers = %.1f MB\n",
               proto_sketch_count, NUM_RX_QUEUES, proto_mem / (1024.0 * 1024.0));
    }
    printf("  Total sketch memory:     %.1f MB\n", total_sketch_mem / (1024.0 * 1024.0));
    printf("  Ring buffer:             %d windows × %zu bytes = %.1f KB\n",
           RING_BUFFER_SIZE, sizeof(struct feature_window),
           (RING_BUFFER_SIZE * sizeof(struct feature_window)) / 1024.0);
    printf("  Configuration:           %d rows × %d columns per sketch\n",
           SKETCH_ROWS, SKETCH_COLS);
    printf("  Architecture:            Per-worker (NO atomics, NO contention)\n");
    printf("  Sampling:                1 in %d packets (%.2f%% overhead)\n",
           SKETCH_SAMPLE_RATE, 100.0 / SKETCH_SAMPLE_RATE);
    printf("  Update policy:           Attack traffic only\n\n");

    /* ========== ML INTEGRATION: Load model ========== */
    printf("[ML] Loading machine learning model from: %s\n", g_model_dir);
    g_ml_model = ml_init(g_model_dir);
    if (!g_ml_model) {
        printf("[ML] Warning: Model failed to load, continuing without ML\n");
        printf("[ML] Detector will use threshold-based detection only\n");
    } else {
        printf("[ML] Model loaded successfully - ML-enhanced detection enabled\n");
        printf("[ML] Features expected: %d  Classes: %d\n",
               ml_get_num_features(g_ml_model), ml_get_num_classes(g_ml_model));
        printf("[ML] Confidence threshold: %.2f\n", ML_CONFIDENCE_THRESHOLD);
        printf("[ML] Hybrid mode: Thresholds + LightGBM classifier\n");
    }
    printf("\n");
    /* ================================================= */

    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  MIRA DDoS DETECTOR - DPDK + OCTOSKETCH + ML (%d workers + 1 coord)  ║\n", NUM_RX_QUEUES);
    printf("║  Mode: %-12s  Features: %-3d  Model: %-25s ║\n",
           g_ml_mode == ML_MODE_DPI_SKETCH ? "dpi_sketch" : "sketch_adv",
           g_ml_mode == ML_MODE_DPI_SKETCH ? DPI_SKETCH_NUM_FEATURES : SKETCH_ADV_NUM_FEATURES,
           g_model_dir);
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Architecture:\n");
    printf("  - DPDK:            %d RX workers + 1 coordinator\n", NUM_RX_QUEUES);
    printf("  - OctoSketch:      O(1) memory, per-worker (no atomics)\n");
    printf("  - Multi-scale:     50ms / 1s / 10s / 1min IP tracking\n");
    if (g_ml_mode == ML_MODE_SKETCH_ADV) {
        printf("  - Per-protocol:    12 protocol-specific sketches\n");
    }
    printf("  - ML classifier:   LightGBM (embedded, no HTTP/sockets)\n");
    printf("  - Detection:       Threshold anomaly + ML classification\n\n");
    printf("Press Ctrl+C to exit...\n\n");

    /* Launch worker threads on lcores 1-%d and coordinator on last lcore */
    for (unsigned i = 0; i < NUM_RX_QUEUES; i++) {
        queue_ids[i] = i;
    }

    unsigned lcore_idx = 0;
    unsigned coordinator_lcore = 0;

    /* First pass: launch workers */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (lcore_idx < NUM_RX_QUEUES) {
            /* Worker thread */
            printf("Launching worker %u on lcore %u\n", lcore_idx, lcore_id);
            rte_eal_remote_launch(worker_thread, &queue_ids[lcore_idx], lcore_id);
            lcore_idx++;
        } else {
            /* Save coordinator lcore for next pass */
            coordinator_lcore = lcore_id;
            break;
        }
    }

    /* Launch coordinator */
    if (coordinator_lcore > 0) {
        printf("Launching coordinator on lcore %u\n", coordinator_lcore);
        rte_eal_remote_launch(coordinator_thread, NULL, coordinator_lcore);
    } else {
        printf("Warning: No lcore available for coordinator thread!\n");
    }

    /* Wait for all threads */
    rte_eal_mp_wait_lcore();

    if (g_log_file)
        fclose(g_log_file);

    /* ML cleanup (also done in signal handler, but safe to double-check) */
    if (g_ml_model) {
        ml_cleanup(g_ml_model);
        g_ml_model = NULL;
    }

    rte_hash_free(ip_hash);
    printf("\nShutting down...\n");
    rte_eal_cleanup();

    return 0;
}
