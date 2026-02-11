/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 MIRA Project
 *
 * MIRA DDoS Detector - MULTI-CORE + OCTOSKETCH VERSION
 *
 * Multi-attack DDoS detector with multi-core processing + OctoSketch for line-rate detection
 * Detects: UDP Flood, UDP-Lag, SYN Flood, HTTP Flood, ICMP Flood,
 *          DNS/NTP/SNMP Amp, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP
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
#include <stdbool.h>
#include <signal.h>
#include <math.h>
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

#define RX_RING_SIZE 32768       /* Max for uint16_t compatibility (must be power of 2) */
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288         /* Keep at 524K to avoid soft lockup on cleanup */
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 2048          /* Larger bursts for max throughput - Phase 3 */
#define NUM_RX_QUEUES 14         /* 14 workers for 17+ Gbps - CRITICAL */

/* Anomaly detection thresholds (1.5x baseline maximum)
 * NOTE: This detector only identifies ANOMALIES, not attack types.
 *       Attack classification is done by the ML model.
 */
#define ANOMALY_UDP_THRESHOLD    7000000   /* 7M UDP pps (baseline max: 4.4M) */
#define ANOMALY_SYN_THRESHOLD    2500000   /* 2.5M SYN pps (baseline max: 1.6M) */
#define ANOMALY_HTTP_THRESHOLD   4000000   /* 4M HTTP rps (baseline max: 2.5M) */
#define ANOMALY_ICMP_THRESHOLD    700000   /* 700K ICMP pps (baseline max: 450K) */
#define ATTACK_TOTAL_PPS_THRESHOLD 7000000 /* Fallback total PPS until baseline is ready */

/* Protocol-specific anomaly thresholds (scaled proportionally) */
#define DNS_AMP_THRESHOLD   3000000   /* 3M DNS amp pps */
#define NTP_AMP_THRESHOLD   2000000   /* 2M NTP amp pps */
#define SNMP_AMP_THRESHOLD  2000000   /* 2M SNMP amp pps */
#define SSDP_THRESHOLD      2000000   /* 2M SSDP pps */
#define PORTMAP_THRESHOLD   2000000   /* 2M PortMap pps */
#define NETBIOS_THRESHOLD   2000000   /* 2M NetBIOS pps */
#define LDAP_THRESHOLD      2000000   /* 2M LDAP pps */
#define MSSQL_THRESHOLD     2000000   /* 2M MSSQL pps */
#define TFTP_THRESHOLD      1000000   /* 1M TFTP pps */
#define UDP_LAG_PPS_THRESHOLD 7000000 /* Same as UDP threshold */
#define UDP_LAG_AVG_PKT_BYTES 900
#define ACK_FLOOD_THRESHOLD 4000000   /* 4M ACK pps */
#define FRAG_THRESHOLD      1000000   /* 1M fragmented pps */

/* OctoSketch Heavy-Hitter Detection */
#define HEAVY_HITTER_PPS_THRESHOLD 5000   /* Single IP exceeding 5K pps = heavy hitter */
#define HEAVY_HITTER_TOP_K 5              /* Track top 5 attackers */

/* ========== RING BUFFER + MULTI-SCALE DETECTION ========== */
#define RING_BUFFER_SIZE 100              /* Last 100 windows (5 seconds at 50ms) */
#define ML_EXTENDED_FEATURES 56           /* 42 base + 14 temporal/multi-scale */

/* Multi-scale time windows */
#define SCALE_1S_WINDOWS 20               /* 20 × 50ms = 1 second */
#define SCALE_10S_WINDOWS 200             /* 200 × 50ms = 10 seconds */
#define SCALE_1MIN_WINDOWS 1200           /* 1200 × 50ms = 1 minute */

/* Adaptive threshold parameters */
#define ADAPTIVE_SIGMA 3.0                /* 3-sigma for anomaly detection */
#define MIN_BASELINE_SAMPLES 20           /* Minimum samples before adaptive threshold */

/* Time windows */
#define FAST_DETECTION_INTERVAL 0.05
#define STATS_INTERVAL_SEC 5.0
#define DETECTION_WINDOW_SEC 5.0

/* IP tracking - CLOUDLAB INTERNAL NETWORK (10.x.x.x) */
#define MAX_IPS 65536
#define BASELINE_NETWORK 0x0A0A0200     /* 10.10.2.x - benign traffic (CloudLab internal) */
#define ATTACK_NETWORK   0x0A0A0300     /* 10.10.3.x - attack traffic (CloudLab internal) */
#define NETWORK_MASK     0xFFFFFF00

#define SERVER_IP 0x0A0A0102            /* 10.10.1.2 - Server IP (CloudLab internal) */

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
    uint64_t http_requests;
    uint64_t dns_queries;

    /* Bytes counters */
    uint64_t total_bytes;
    uint64_t baseline_bytes;
    uint64_t attack_bytes;

    /* ========== Protocol-Specific Features for CIC-DDoS-2019 (26 features) ========== */
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
    /* ============================================================================== */

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
    uint64_t http_requests;
    uint64_t dns_queries;

    /* Aggregated bytes counters */
    uint64_t total_bytes;
    uint64_t baseline_bytes;
    uint64_t attack_bytes;

    /* ========== Protocol-Specific Features for CIC-DDoS-2019 (26 features) ========== */
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
    /* ============================================================================== */

    /* Detection metrics */
    uint64_t udp_flood_detections;
    uint64_t udp_lag_detections;
    uint64_t syn_flood_detections;
    uint64_t http_flood_detections;
    uint64_t icmp_flood_detections;
    uint64_t total_flood_detections;
    uint64_t dns_amp_detections;
    uint64_t ntp_amp_detections;
    uint64_t snmp_amp_detections;
    uint64_t ssdp_amp_detections;
    uint64_t portmap_detections;
    uint64_t netbios_detections;
    uint64_t ldap_detections;
    uint64_t mssql_detections;
    uint64_t tftp_detections;
    uint64_t ack_flood_detections;
    uint64_t frag_attack_detections;

    /* OctoSketch Heavy-Hitter Detection */
    uint64_t heavy_hitter_detections;     /* Times a single IP exceeded threshold */
    uint32_t top_attacker_ips[HEAVY_HITTER_TOP_K];    /* Current top attacker IPs */
    uint32_t top_attacker_counts[HEAVY_HITTER_TOP_K]; /* Their packet counts */
    uint32_t num_heavy_hitters;           /* IPs exceeding threshold this window */

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
    uint64_t timestamp_tsc;               /* CPU cycles timestamp */
    uint64_t window_id;                   /* Sequential window number */

    /* Base features (42) - same as ML */
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
    float udp_tcp_ratio;
    float syn_total_ratio;
    float baseline_attack_ratio;
    float bytes_per_packet;
    float ntp_monlist_queries;
    float ntp_responses;
    float avg_ntp_response_size;
    float dns_any_queries;
    float dns_txt_queries;
    float dns_responses;
    float avg_dns_response_size;
    float snmp_getbulk_requests;
    float snmp_responses;
    float avg_snmp_response_size;
    float ssdp_msearch_packets;
    float ssdp_responses;
    float portmap_getport_calls;
    float portmap_dump_calls;
    float netbios_name_queries;
    float netbios_dgram_packets;
    float ldap_bind_requests;
    float ldap_search_requests;
    float mssql_sqlbatch_packets;
    float mssql_rpc_packets;
    float tftp_rrq_packets;
    float tftp_wrq_packets;
    float ntp_amplification_factor;
    float dns_amplification_factor;
    float snmp_amplification_factor;
    float query_response_ratio;
    float fragmentation_ratio;
    float syn_ack_ratio;

    /* Extended features (14) - temporal + multi-scale */
    float delta_pps_5w;                   /* PPS change over 5 windows (250ms) */
    float delta_pps_10w;                  /* PPS change over 10 windows (500ms) */
    float pps_variance;                   /* Variance over last 20 windows */
    float pps_baseline;                   /* Running average (adaptive baseline) */
    float ratio_vs_baseline;              /* Current / baseline ratio */
    float top_ip_pps_50ms;                /* Top attacker PPS (50ms scale) */
    float top_ip_pps_1s;                  /* Top attacker PPS (1s scale) */
    float top_ip_pps_1min;                /* Top attacker PPS (1min scale) */
    float ratio_50ms_1min;                /* Burst ratio: 50ms / 1min */
    float num_heavy_hitters;              /* IPs exceeding threshold */
    float ip_concentration;               /* Top1 count / total count */
    float new_ips_ratio;                  /* New IPs vs known IPs */
    float attack_entropy;                 /* Distribution entropy */
    float adaptive_threshold;             /* Current adaptive threshold */

    /* Detection results */
    uint8_t threshold_detected;           /* Detected by thresholds */
    uint8_t ml_predicted_class;           /* ML prediction (0-13) */
    float ml_confidence;                  /* ML confidence */
} __attribute__((packed));

/* Ring buffer for temporal analysis */
struct ring_buffer {
    struct feature_window windows[RING_BUFFER_SIZE];
    uint32_t write_idx;                   /* Next write position */
    uint32_t count;                       /* Valid entries (up to RING_BUFFER_SIZE) */
    uint64_t total_windows;               /* Total windows processed */

    /* Running statistics for adaptive thresholds */
    double sum_pps;                       /* Sum of attack PPS */
    double sum_pps_sq;                    /* Sum of squared PPS (for variance) */

    /* Multi-scale aggregates */
    float baseline_1s;                    /* 1-second baseline */
    float baseline_10s;                   /* 10-second baseline */
    float baseline_1min;                  /* 1-minute baseline */
} __rte_cache_aligned;

/* Multi-scale sketch structure */
struct multiscale_sketches {
    struct octosketch sketch_50ms;        /* Current window (reset every 50ms) */
    struct octosketch sketch_1s;          /* 1-second accumulator */
    struct octosketch sketch_10s;         /* 10-second accumulator */
    struct octosketch sketch_1min;        /* 1-minute accumulator */

    /* Reset counters */
    uint32_t windows_since_1s_reset;
    uint32_t windows_since_10s_reset;
    uint32_t windows_since_1min_reset;
} __rte_cache_aligned;

/* Global ring buffer and multi-scale sketches */
static struct ring_buffer g_ring_buffer __rte_cache_aligned;
static struct multiscale_sketches g_multiscale[NUM_RX_QUEUES] __rte_cache_aligned;
static struct multiscale_sketches g_merged_multiscale __rte_cache_aligned;

/* Instantaneous metrics - per-worker (lock-free) */
static uint64_t window_baseline_pkts[NUM_RX_QUEUES];
static uint64_t window_attack_pkts[NUM_RX_QUEUES];
static uint64_t window_baseline_bytes[NUM_RX_QUEUES];
static uint64_t window_attack_bytes[NUM_RX_QUEUES];
static uint64_t last_window_reset_tsc = 0;
static uint64_t g_start_tsc = 0;  /* Global start timestamp for cumulative throughput */

/* Binary log record structure for ML training (compact format) */
#define BINARY_LOG_MAGIC 0x4D495241  /* "MIRA" */
#define BINARY_LOG_VERSION 1

struct __attribute__((packed)) binary_log_record {
    uint32_t magic;              /* 0x4D495241 = "MIRA" */
    uint32_t version;            /* Format version */
    uint64_t timestamp_ns;       /* Nanoseconds since start */

    /* Core counters (10 fields) */
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t syn_packets;
    uint64_t syn_ack_packets;
    uint64_t http_requests;
    uint64_t dns_queries;
    uint64_t baseline_packets;
    uint64_t attack_packets;

    /* Protocol-specific counters (22 fields) */
    uint64_t ntp_monlist_queries;
    uint64_t ntp_responses;
    uint64_t ntp_response_size_sum;
    uint64_t dns_any_queries;
    uint64_t dns_txt_queries;
    uint64_t dns_responses;
    uint64_t dns_response_size_sum;
    uint64_t snmp_getbulk_requests;
    uint64_t snmp_responses;
    uint64_t snmp_response_size_sum;
    uint64_t ssdp_msearch_packets;
    uint64_t ssdp_responses;
    uint64_t portmap_getport_calls;
    uint64_t portmap_dump_calls;
    uint64_t netbios_name_queries;
    uint64_t netbios_dgram_packets;
    uint64_t ldap_bind_requests;
    uint64_t ldap_search_requests;
    uint64_t mssql_sqlbatch_packets;
    uint64_t mssql_rpc_packets;
    uint64_t tftp_rrq_packets;
    uint64_t tftp_wrq_packets;
};
/* Total size: 4 + 4 + 8 + (11*8) + (22*8) = 280 bytes per record */

/* Sketch-ADV binary record: 64 features written directly from sketches */
#define SKETCH_ADV_MAGIC   0x534B4156  /* "SKAV" */
#define SKETCH_ADV_VERSION 1
#define SKETCH_ADV_NUM_PROTOS 12
#define SKETCH_ADV_FEATURES_TOTAL 64   /* 14 global + 48 per-proto + 2 pkt size */

struct __attribute__((packed)) sketch_adv_record {
    uint32_t magic;
    uint32_t version;
    uint64_t timestamp_ns;

    /* Block 1: 14 global sketch features (from ring buffer + multi-scale) */
    double delta_pps_5w;
    double delta_pps_10w;
    double pps_variance;
    double pps_baseline;
    double ratio_vs_baseline;
    double top_ip_pps_50ms;
    double top_ip_pps_1s;
    double top_ip_pps_1min;
    double ratio_50ms_1min;
    double num_heavy_hitters;
    double ip_concentration;
    double new_ips_ratio;
    double attack_entropy;
    double adaptive_threshold;

    /* Block 2: 48 per-protocol features (4 per protocol × 12 protocols) */
    /* Order: dns, ntp, snmp, ssdp, portmap, netbios, ldap, mssql, tftp, syn, http, udp_other */
    double pps_proto[SKETCH_ADV_NUM_PROTOS];
    double heavy_hitters_proto[SKETCH_ADV_NUM_PROTOS];
    double ip_concentration_proto[SKETCH_ADV_NUM_PROTOS];
    double ratio_vs_total_proto[SKETCH_ADV_NUM_PROTOS];

    /* Block 3: 2 packet size features */
    double avg_packet_size;
    double packet_size_variance;
};
/* Total size: 4 + 4 + 8 + 14*8 + 48*8 + 2*8 = 528 bytes per record */

/* Global variables */
static volatile bool force_quit = false;
static struct ip_stats g_ip_table[MAX_IPS];
static rte_atomic32_t g_ip_count;
static struct detection_stats g_stats;
static struct worker_stats g_worker_stats[NUM_RX_QUEUES] __rte_cache_aligned;
static FILE *g_log_file = NULL;
static const char *g_log_output_path = "../results/mira_detector_multicore.log";  /* Default log path */
static FILE *g_binary_log_file = NULL;  /* Binary log for ML training */
static bool g_binary_log_enabled = false;
static bool g_sketch_adv_enabled = false;
static FILE *g_sketch_adv_file = NULL;     /* Binary output for sketch-adv ML training */
static const char *g_sketch_adv_path = NULL;
static struct rte_hash *ip_hash = NULL;

/* OctoSketch - Per-worker sketches (NO atomics, NO contention) */
static struct octosketch g_worker_sketch_attack[NUM_RX_QUEUES] __rte_cache_aligned; /* Attack traffic per worker */

/* OctoSketch - Coordinator merged sketches (for analysis) */
static struct octosketch g_merged_sketch_attack __rte_cache_aligned;  /* Merged attack sketch */

/* ========== SKETCH-ADV: Per-protocol sketches (12 protocols) ========== */
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

/* Per-worker packet size sum-of-squares for variance calculation */
static uint64_t g_worker_pktlen_sq_sum[NUM_RX_QUEUES] __rte_cache_aligned;
/* ========== END SKETCH-ADV ========== */

/* Sampling configuration */
#define SKETCH_SAMPLE_RATE 32  /* Update sketch every N packets (1 in 32) */

/* Function declarations */
static int worker_thread(void *arg);

static inline bool ber_read_len(const uint8_t *buf, uint16_t len, uint16_t *idx, uint32_t *out_len)
{
    if (*idx >= len) {
        return false;
    }
    uint8_t l = buf[*idx];
    (*idx)++;
    if ((l & 0x80) == 0) {
        *out_len = l;
        return true;
    }
    uint8_t n = l & 0x7F;
    if (n == 0 || n > 2 || (uint32_t)(*idx + n) > len) {
        return false;
    }
    uint32_t val = 0;
    for (uint8_t i = 0; i < n; i++) {
        val = (val << 8) | buf[*idx + i];
    }
    *idx += n;
    *out_len = val;
    return true;
}

static inline bool ber_skip_tlv(const uint8_t *buf, uint16_t len, uint16_t *idx)
{
    if (*idx >= len) {
        return false;
    }
    (*idx)++;
    uint32_t l = 0;
    if (!ber_read_len(buf, len, idx, &l)) {
        return false;
    }
    if ((uint32_t)(*idx) + l > len) {
        return false;
    }
    *idx += (uint16_t)l;
    return true;
}

static inline int snmp_get_pdu_tag(const uint8_t *buf, uint16_t len)
{
    uint16_t idx = 0;
    uint32_t seq_len = 0;
    if (len < 2 || buf[idx] != 0x30) {
        return -1;
    }
    idx++;
    if (!ber_read_len(buf, len, &idx, &seq_len)) {
        return -1;
    }
    if (idx >= len || buf[idx] != 0x02) {
        return -1;
    }
    if (!ber_skip_tlv(buf, len, &idx)) {
        return -1;
    }
    if (idx >= len || buf[idx] != 0x04) {
        return -1;
    }
    if (!ber_skip_tlv(buf, len, &idx)) {
        return -1;
    }
    if (idx >= len) {
        return -1;
    }
    return buf[idx];
}
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
        return ATTACK_TOTAL_PPS_THRESHOLD;  /* Use fixed threshold until enough samples */
    }

    double mean = g_ring_buffer.sum_pps / g_ring_buffer.count;
    double variance = (g_ring_buffer.sum_pps_sq / g_ring_buffer.count) - (mean * mean);
    double stddev = sqrt(variance > 0 ? variance : 0);

    return (float)(mean + ADAPTIVE_SIGMA * stddev);
}

/* Calculate temporal features from ring buffer */
static void calculate_temporal_features(struct feature_window *current)
{
    /* Delta PPS over 5 windows (250ms) */
    struct feature_window *prev_5 = ring_buffer_get(-5);
    if (prev_5) {
        current->delta_pps_5w = current->attack_packets - prev_5->attack_packets;
    } else {
        current->delta_pps_5w = 0;
    }

    /* Delta PPS over 10 windows (500ms) */
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
    /* Get top attacker from each scale */
    struct heavy_hitter top_50ms[1], top_1s[1], top_1min[1];

    octosketch_top_k(&g_merged_multiscale.sketch_50ms, 1, top_50ms);
    octosketch_top_k(&g_merged_multiscale.sketch_1s, 1, top_1s);
    octosketch_top_k(&g_merged_multiscale.sketch_1min, 1, top_1min);

    /* Top IP PPS at each scale */
    current->top_ip_pps_50ms = (window_sec > 0 && top_50ms[0].count > 0) ?
        (float)top_50ms[0].count / window_sec : 0;
    current->top_ip_pps_1s = (top_1s[0].count > 0) ?
        (float)top_1s[0].count / 1.0f : 0;  /* 1 second scale */
    current->top_ip_pps_1min = (top_1min[0].count > 0) ?
        (float)top_1min[0].count / 60.0f : 0;  /* 1 minute scale */

    /* Burst ratio: 50ms activity vs 1min baseline */
    current->ratio_50ms_1min = (current->top_ip_pps_1min > 0) ?
        current->top_ip_pps_50ms / current->top_ip_pps_1min : 1.0f;

    /* Count heavy hitters (IPs exceeding threshold) */
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

    /* IP concentration: top1 / total */
    uint64_t total = octosketch_get_total(&g_merged_multiscale.sketch_50ms);
    current->ip_concentration = (total > 0) ?
        (float)top_50ms[0].count / total : 0;

    /* Simplified new IPs ratio and entropy (would need more tracking for accuracy) */
    current->new_ips_ratio = 0;  /* TODO: Track unique IPs */
    current->attack_entropy = 1.0f - current->ip_concentration;  /* Simplified entropy */
}

/* Push current features to ring buffer */
static void ring_buffer_push(struct feature_window *window)
{
    uint32_t idx = g_ring_buffer.write_idx;

    /* Copy to buffer */
    memcpy(&g_ring_buffer.windows[idx], window, sizeof(struct feature_window));

    /* Update running statistics for adaptive threshold */
    if (g_ring_buffer.count >= RING_BUFFER_SIZE) {
        /* Remove oldest from running stats */
        struct feature_window *oldest = &g_ring_buffer.windows[(idx + 1) % RING_BUFFER_SIZE];
        g_ring_buffer.sum_pps -= oldest->attack_packets;
        g_ring_buffer.sum_pps_sq -= oldest->attack_packets * oldest->attack_packets;
    }
    g_ring_buffer.sum_pps += window->attack_packets;
    g_ring_buffer.sum_pps_sq += window->attack_packets * window->attack_packets;

    /* Advance index */
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

/* Merge per-protocol sketches from all workers (SKETCH-ADV) */
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

        /* Reset 50ms sketch every window */
        octosketch_reset(&g_multiscale[i].sketch_50ms);

        /* Reset 1s sketch every 20 windows */
        if (g_multiscale[i].windows_since_1s_reset >= SCALE_1S_WINDOWS) {
            octosketch_reset(&g_multiscale[i].sketch_1s);
            g_multiscale[i].windows_since_1s_reset = 0;
        }

        /* Reset 10s sketch every 200 windows */
        if (g_multiscale[i].windows_since_10s_reset >= SCALE_10S_WINDOWS) {
            octosketch_reset(&g_multiscale[i].sketch_10s);
            g_multiscale[i].windows_since_10s_reset = 0;
        }

        /* Reset 1min sketch every 1200 windows */
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
    static bool window_totals_init = false;
    static uint64_t window_ntp_monlist_start = 0;
    static uint64_t window_dns_any_start = 0;
    static uint64_t window_dns_txt_start = 0;
    static uint64_t window_snmp_getbulk_start = 0;
    static uint64_t window_ssdp_msearch_start = 0;
    static uint64_t window_portmap_calls_start = 0;
    static uint64_t window_netbios_name_start = 0;
    static uint64_t window_netbios_dgram_start = 0;
    static uint64_t window_ldap_bind_start = 0;
    static uint64_t window_ldap_search_start = 0;
    static uint64_t window_mssql_sqlbatch_start = 0;
    static uint64_t window_mssql_rpc_start = 0;
    static uint64_t window_tftp_rrq_start = 0;
    static uint64_t window_tftp_wrq_start = 0;
    /* Basic protocol counters - window start values */
    static uint64_t window_syn_start = 0;
    static uint64_t window_udp_start = 0;
    static uint64_t window_icmp_start = 0;
    static uint64_t window_http_start = 0;
    static uint64_t window_dns_start = 0;

    double elapsed = (double)(cur_tsc - g_stats.last_fast_detection_tsc) / hz;

    if (elapsed >= FAST_DETECTION_INTERVAL) {
        g_stats.last_fast_detection_tsc = cur_tsc;
        uint64_t window_duration = cur_tsc - g_stats.window_start_tsc;
        double window_sec = (double)window_duration / hz;

        if (window_sec < 0.1) return;

        /* AGGREGATE DETECTION - Use worker stats (exact counters) */
        uint64_t window_base_pkts = 0, window_att_pkts = 0;
        /* Total accumulators for basic protocols (will calculate window delta) */
        uint64_t total_syn_pkts = 0, total_udp_pkts = 0, total_icmp_pkts = 0;
        uint64_t total_http_reqs = 0, total_dns_queries = 0;
        uint64_t total_ntp_monlist = 0;
        uint64_t total_dns_any = 0;
        uint64_t total_dns_txt = 0;
        uint64_t total_snmp_getbulk = 0;
        uint64_t total_ssdp_msearch = 0;
        uint64_t total_portmap_calls = 0;
        uint64_t total_netbios_name = 0;
        uint64_t total_netbios_dgram = 0;
        uint64_t total_ldap_bind = 0;
        uint64_t total_ldap_search = 0;
        uint64_t total_mssql_sqlbatch = 0;
        uint64_t total_mssql_rpc = 0;
        uint64_t total_tftp_rrq = 0;
        uint64_t total_tftp_wrq = 0;

        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            window_base_pkts += window_baseline_pkts[i];
            window_att_pkts += window_attack_pkts[i];
        }

        /* Aggregate protocol stats from workers */
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            total_syn_pkts += g_worker_stats[i].syn_packets;
            total_udp_pkts += g_worker_stats[i].udp_packets;
            total_icmp_pkts += g_worker_stats[i].icmp_packets;
            total_http_reqs += g_worker_stats[i].http_requests;
            total_dns_queries += g_worker_stats[i].dns_queries;
            total_ntp_monlist += g_worker_stats[i].ntp_monlist_queries;
            total_dns_any += g_worker_stats[i].dns_any_queries;
            total_dns_txt += g_worker_stats[i].dns_txt_queries;
            total_snmp_getbulk += g_worker_stats[i].snmp_getbulk_requests;
            total_ssdp_msearch += g_worker_stats[i].ssdp_msearch_packets;
            total_portmap_calls += g_worker_stats[i].portmap_getport_calls;
            total_netbios_name += g_worker_stats[i].netbios_name_queries;
            total_netbios_dgram += g_worker_stats[i].netbios_dgram_packets;
            total_ldap_bind += g_worker_stats[i].ldap_bind_requests;
            total_ldap_search += g_worker_stats[i].ldap_search_requests;
            total_mssql_sqlbatch += g_worker_stats[i].mssql_sqlbatch_packets;
            total_mssql_rpc += g_worker_stats[i].mssql_rpc_packets;
            total_tftp_rrq += g_worker_stats[i].tftp_rrq_packets;
            total_tftp_wrq += g_worker_stats[i].tftp_wrq_packets;
        }

        if (!window_totals_init) {
            window_ntp_monlist_start = total_ntp_monlist;
            window_dns_any_start = total_dns_any;
            window_dns_txt_start = total_dns_txt;
            window_snmp_getbulk_start = total_snmp_getbulk;
            window_ssdp_msearch_start = total_ssdp_msearch;
            window_portmap_calls_start = total_portmap_calls;
            window_netbios_name_start = total_netbios_name;
            window_netbios_dgram_start = total_netbios_dgram;
            window_ldap_bind_start = total_ldap_bind;
            window_ldap_search_start = total_ldap_search;
            window_mssql_sqlbatch_start = total_mssql_sqlbatch;
            window_mssql_rpc_start = total_mssql_rpc;
            window_tftp_rrq_start = total_tftp_rrq;
            window_tftp_wrq_start = total_tftp_wrq;
            /* Basic protocol counters */
            window_syn_start = total_syn_pkts;
            window_udp_start = total_udp_pkts;
            window_icmp_start = total_icmp_pkts;
            window_http_start = total_http_reqs;
            window_dns_start = total_dns_queries;
            window_totals_init = true;
        }

        uint64_t window_ntp_monlist = total_ntp_monlist - window_ntp_monlist_start;
        uint64_t window_dns_any = total_dns_any - window_dns_any_start;
        uint64_t window_dns_txt = total_dns_txt - window_dns_txt_start;
        uint64_t window_snmp_getbulk = total_snmp_getbulk - window_snmp_getbulk_start;
        uint64_t window_ssdp_msearch = total_ssdp_msearch - window_ssdp_msearch_start;
        uint64_t window_portmap_calls = total_portmap_calls - window_portmap_calls_start;
        uint64_t window_netbios_name = total_netbios_name - window_netbios_name_start;
        uint64_t window_netbios_dgram = total_netbios_dgram - window_netbios_dgram_start;
        uint64_t window_ldap_bind = total_ldap_bind - window_ldap_bind_start;
        uint64_t window_ldap_search = total_ldap_search - window_ldap_search_start;
        uint64_t window_mssql_sqlbatch = total_mssql_sqlbatch - window_mssql_sqlbatch_start;
        uint64_t window_mssql_rpc = total_mssql_rpc - window_mssql_rpc_start;
        uint64_t window_tftp_rrq = total_tftp_rrq - window_tftp_rrq_start;
        uint64_t window_tftp_wrq = total_tftp_wrq - window_tftp_wrq_start;

        /* Calculate window deltas for basic protocol counters */
        uint64_t window_syn_pkts = total_syn_pkts - window_syn_start;
        uint64_t window_udp_pkts = total_udp_pkts - window_udp_start;
        uint64_t window_icmp_pkts = total_icmp_pkts - window_icmp_start;
        uint64_t window_http_reqs = total_http_reqs - window_http_start;
        uint64_t window_dns_queries = total_dns_queries - window_dns_start;

        /* Calculate PPS rates */
        double attack_pps = (double)window_att_pkts / window_sec;
        double baseline_pps = (double)window_base_pkts / window_sec;
        double syn_pps = (double)window_syn_pkts / window_sec;
        double udp_pps = (double)window_udp_pkts / window_sec;
        double icmp_pps = (double)window_icmp_pkts / window_sec;
        double http_pps = (double)window_http_reqs / window_sec;
        double dns_amp_pps = (double)(window_dns_any + window_dns_txt) / window_sec;
        double ntp_amp_pps = (double)window_ntp_monlist / window_sec;
        double snmp_amp_pps = (double)window_snmp_getbulk / window_sec;
        double ssdp_pps = (double)window_ssdp_msearch / window_sec;
        double portmap_pps = (double)window_portmap_calls / window_sec;
        double netbios_pps = (double)(window_netbios_name + window_netbios_dgram) / window_sec;
        double ldap_pps = (double)(window_ldap_bind + window_ldap_search) / window_sec;
        double mssql_pps = (double)(window_mssql_sqlbatch + window_mssql_rpc) / window_sec;
        double tftp_pps = (double)(window_tftp_rrq + window_tftp_wrq) / window_sec;

        /* MEASURE-ONLY MODE: No threshold-based alerts.
         * All statistics (counters, sketches, ring buffer, multi-scale) are
         * collected. Attack classification is deferred to the ML model.
         * PPS rates above are kept for logging/stats only. */
        (void)attack_pps; (void)baseline_pps;
        (void)syn_pps; (void)udp_pps; (void)icmp_pps; (void)http_pps;
        (void)dns_amp_pps; (void)ntp_amp_pps; (void)snmp_amp_pps;
        (void)ssdp_pps; (void)portmap_pps; (void)netbios_pps;
        (void)ldap_pps; (void)mssql_pps; (void)tftp_pps;

        /* OctoSketch: Merge per-worker sketches for analysis (slow path) */
        if (window_att_pkts > 0) {
            /* Merge all worker sketches into global merged sketch */
            struct octosketch *worker_sketches[NUM_RX_QUEUES];
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                worker_sketches[i] = &g_worker_sketch_attack[i];
            }
            octosketch_merge(&g_merged_sketch_attack, worker_sketches, NUM_RX_QUEUES);

            /* Heavy-Hitter Detection using OctoSketch */
            struct heavy_hitter top_attackers[HEAVY_HITTER_TOP_K];
            octosketch_top_k(&g_merged_sketch_attack, HEAVY_HITTER_TOP_K, top_attackers);

            /* Store top attackers in stats and detect heavy-hitters */
            g_stats.num_heavy_hitters = 0;
            for (int i = 0; i < HEAVY_HITTER_TOP_K; i++) {
                g_stats.top_attacker_ips[i] = top_attackers[i].ip;
                g_stats.top_attacker_counts[i] = top_attackers[i].count;

                /* Check if this IP exceeds heavy-hitter threshold */
                if (top_attackers[i].count > 0) {
                    double ip_pps = (double)top_attackers[i].count / window_sec;
                    if (ip_pps > HEAVY_HITTER_PPS_THRESHOLD) {
                        g_stats.num_heavy_hitters++;
                    }
                }
            }
        }

        /* ========== RING BUFFER + MULTI-SCALE INTEGRATION ========== */

        /* Merge multi-scale sketches from all workers */
        merge_multiscale_sketches();

        /* Merge per-protocol sketches (SKETCH-ADV) */
        if (g_sketch_adv_enabled) {
            merge_protocol_sketches();
        }

        /* Build feature window for ring buffer */
        struct feature_window current_window;
        memset(&current_window, 0, sizeof(current_window));

        current_window.timestamp_tsc = cur_tsc;
        current_window.window_id = g_ring_buffer.total_windows;

        /* Base features (42) */
        current_window.total_packets = (float)(window_base_pkts + window_att_pkts);
        current_window.total_bytes = 0;
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            current_window.total_bytes += window_baseline_bytes[i] + window_attack_bytes[i];
        }
        current_window.udp_packets = (float)window_udp_pkts;
        current_window.tcp_packets = (float)(window_syn_pkts);  /* Approximate */
        current_window.icmp_packets = (float)window_icmp_pkts;
        current_window.syn_packets = (float)window_syn_pkts;
        current_window.http_requests = (float)window_http_reqs;
        current_window.dns_queries = (float)window_dns_queries;
        current_window.baseline_packets = (float)window_base_pkts;
        current_window.attack_packets = (float)window_att_pkts;

        /* Ratios */
        current_window.udp_tcp_ratio = (window_syn_pkts > 0) ?
            (float)window_udp_pkts / window_syn_pkts : 0;
        current_window.syn_total_ratio = (current_window.total_packets > 0) ?
            (float)window_syn_pkts / current_window.total_packets : 0;
        current_window.baseline_attack_ratio = (window_att_pkts > 0) ?
            (float)window_base_pkts / window_att_pkts : 0;
        current_window.bytes_per_packet = (current_window.total_packets > 0) ?
            current_window.total_bytes / current_window.total_packets : 0;

        /* Protocol-specific features */
        current_window.ntp_monlist_queries = (float)window_ntp_monlist;
        current_window.dns_any_queries = (float)window_dns_any;
        current_window.dns_txt_queries = (float)window_dns_txt;
        current_window.snmp_getbulk_requests = (float)window_snmp_getbulk;
        current_window.ssdp_msearch_packets = (float)window_ssdp_msearch;
        current_window.portmap_getport_calls = (float)window_portmap_calls;
        current_window.netbios_name_queries = (float)window_netbios_name;
        current_window.netbios_dgram_packets = (float)window_netbios_dgram;
        current_window.ldap_bind_requests = (float)window_ldap_bind;
        current_window.ldap_search_requests = (float)window_ldap_search;
        current_window.mssql_sqlbatch_packets = (float)window_mssql_sqlbatch;
        current_window.mssql_rpc_packets = (float)window_mssql_rpc;
        current_window.tftp_rrq_packets = (float)window_tftp_rrq;
        current_window.tftp_wrq_packets = (float)window_tftp_wrq;

        /* Calculate temporal features from ring buffer history */
        calculate_temporal_features(&current_window);

        /* Calculate multi-scale features from merged sketches */
        calculate_multiscale_features(&current_window, window_sec);

        /* MEASURE-ONLY: no threshold-based detection, always 0 */
        current_window.threshold_detected = 0;

        /* Push to ring buffer */
        ring_buffer_push(&current_window);

        /* Reset multi-scale sketches based on their time windows */
        reset_multiscale_sketches_if_needed();

        /* ========== END RING BUFFER INTEGRATION ========== */

        /* Reset detection window */
        if (window_sec >= DETECTION_WINDOW_SEC) {
            g_stats.window_start_tsc = cur_tsc;

            /* Reset per-worker sketches (will be done by workers on next batch) */
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                octosketch_reset(&g_worker_sketch_attack[i]);
            }

            /* Reset per-protocol sketches (SKETCH-ADV) */
            if (g_sketch_adv_enabled) {
                for (int i = 0; i < NUM_RX_QUEUES; i++) {
                    octosketch_reset(&g_worker_sketch_dns[i]);
                    octosketch_reset(&g_worker_sketch_ntp[i]);
                    octosketch_reset(&g_worker_sketch_snmp[i]);
                    octosketch_reset(&g_worker_sketch_ssdp[i]);
                    octosketch_reset(&g_worker_sketch_portmap[i]);
                    octosketch_reset(&g_worker_sketch_netbios[i]);
                    octosketch_reset(&g_worker_sketch_ldap[i]);
                    octosketch_reset(&g_worker_sketch_mssql[i]);
                    octosketch_reset(&g_worker_sketch_tftp[i]);
                    octosketch_reset(&g_worker_sketch_syn[i]);
                    octosketch_reset(&g_worker_sketch_http[i]);
                    octosketch_reset(&g_worker_sketch_udp_other[i]);
                    g_worker_pktlen_sq_sum[i] = 0;
                }
            }

            window_ntp_monlist_start = total_ntp_monlist;
            window_dns_any_start = total_dns_any;
            window_dns_txt_start = total_dns_txt;
            window_snmp_getbulk_start = total_snmp_getbulk;
            window_ssdp_msearch_start = total_ssdp_msearch;
            window_portmap_calls_start = total_portmap_calls;
            window_netbios_name_start = total_netbios_name;
            window_netbios_dgram_start = total_netbios_dgram;
            window_ldap_bind_start = total_ldap_bind;
            window_ldap_search_start = total_ldap_search;
            window_mssql_sqlbatch_start = total_mssql_sqlbatch;
            window_mssql_rpc_start = total_mssql_rpc;
            window_tftp_rrq_start = total_tftp_rrq;
            window_tftp_wrq_start = total_tftp_wrq;
            /* Basic protocol counters */
            window_syn_start = total_syn_pkts;
            window_udp_start = total_udp_pkts;
            window_icmp_start = total_icmp_pkts;
            window_http_start = total_http_reqs;
            window_dns_start = total_dns_queries;
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

        /* ========== Protocol-Specific Stats Aggregation ========== */
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
        /* ======================================================== */
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

    char buffer[16384];
    size_t len = 0;

    #define APPEND(fmt, ...) do { \
        if (len < sizeof(buffer)) { \
            int n = snprintf(buffer + len, sizeof(buffer) - len, fmt, ##__VA_ARGS__); \
            if (n > 0) { \
                len += (size_t)n; \
                if (len > sizeof(buffer)) { \
                    len = sizeof(buffer); \
                } \
            } \
        } \
    } while (0)

    APPEND(
        "\n╔═══════════════════════════════════════════════════════════════════════╗\n"
        "║      MIRA DDoS DETECTOR - MEASURE-ONLY MODE (MULTI-CORE)             ║\n"
        "╚═══════════════════════════════════════════════════════════════════════╝\n\n");

    double inst_baseline_pct = window_total_pkts > 0 ? (double)window_base_pkts * 100.0 / window_total_pkts : 0.0;
    double inst_attack_pct = window_total_pkts > 0 ? (double)window_att_pkts * 100.0 / window_total_pkts : 0.0;

    APPEND(
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

    APPEND(
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

    APPEND(
        "[CUMULATIVE TRAFFIC - Since first packet (%.1fs)]\n"
        "  Total received:     %" PRIu64 " pkts (%.2f Mpps) | %.2f Gbps | %" PRIu64 " bytes\n\n",
        cumulative_duration,
        g_stats.total_packets, cumulative_mpps, cumulative_gbps, g_stats.total_bytes);

    uint64_t syn_pkts = g_stats.syn_packets;
    uint64_t syn_ack_pkts = g_stats.syn_ack_packets;
    uint64_t http_reqs = g_stats.http_requests;
    uint64_t dns_qs = g_stats.dns_queries;

    APPEND(
        "[ATTACK-SPECIFIC COUNTERS]\n"
        "  SYN packets:        %" PRIu64 "\n"
        "  SYN-ACK packets:    %" PRIu64 "\n"
        "  SYN/ACK ratio:      %.2f\n"
        "  HTTP requests:      %" PRIu64 "\n"
        "  DNS queries:        %" PRIu64 "\n\n",
        syn_pkts, syn_ack_pkts,
        syn_ack_pkts > 0 ? (double)syn_pkts / syn_ack_pkts : 0.0,
        http_reqs, dns_qs);

    /* Calculate average response sizes */
    uint32_t avg_ntp_resp_size = g_stats.ntp_responses > 0 ?
        (uint32_t)(g_stats.ntp_response_size_sum / g_stats.ntp_responses) : 0;
    uint32_t avg_dns_resp_size = g_stats.dns_responses > 0 ?
        (uint32_t)(g_stats.dns_response_size_sum / g_stats.dns_responses) : 0;
    uint32_t avg_snmp_resp_size = g_stats.snmp_responses > 0 ?
        (uint32_t)(g_stats.snmp_response_size_sum / g_stats.snmp_responses) : 0;

    APPEND(
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

    /* MEASURE-ONLY: No alert detection or threshold statistics.
     * Classification is deferred to the ML model. */

    /* OctoSketch Metrics - Per-worker + Sampling */
    {
        size_t sketch_total_memory = octosketch_memory_size() * NUM_RX_QUEUES;
        uint64_t total_sketch_updates = octosketch_get_total(&g_merged_sketch_attack);

        APPEND(
            "[OCTOSKETCH METRICS]\n"
            "=== Per-Worker Sketches + Sampling (1/%d packets) ===\n\n"
            "  Architecture:              Per-worker (NO atomics, NO contention)\n"
            "  Total sketch memory:       %zu KB (%d workers × %.1f KB)\n"
            "  Sampling rate:             1 in %d packets\n"
            "  Traffic sampled:           %" PRIu64 " updates\n"
            "  Memory efficiency:         O(1) constant, %.1f KB per worker\n\n",
            SKETCH_SAMPLE_RATE,
            sketch_total_memory / 1024,
            NUM_RX_QUEUES,
            octosketch_memory_size() / 1024.0,
            SKETCH_SAMPLE_RATE,
            total_sketch_updates,
            octosketch_memory_size() / 1024.0);

        /* Heavy-Hitter Stats (informational only, no alerts) */
        APPEND(
            "[OCTOSKETCH TOP IPs]\n"
            "  Heavy-hitters detected:    %u IPs exceeding %d pps\n"
            "  Top %d IPs (estimated counts, x%d sampling):\n",
            g_stats.num_heavy_hitters,
            HEAVY_HITTER_PPS_THRESHOLD,
            HEAVY_HITTER_TOP_K,
            SKETCH_SAMPLE_RATE);

        for (int i = 0; i < HEAVY_HITTER_TOP_K; i++) {
            if (g_stats.top_attacker_counts[i] > 0) {
                uint32_t ip = g_stats.top_attacker_ips[i];
                double est_pps = (double)g_stats.top_attacker_counts[i] / window_duration;
                APPEND(
                    "    #%d: %u.%u.%u.%u - %u pkts (%.0f pps)\n",
                    i + 1,
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                    (ip >> 8) & 0xFF, ip & 0xFF,
                    g_stats.top_attacker_counts[i],
                    est_pps);
            }
        }
        APPEND("\n");
    }

    /* Ring Buffer and Multi-Scale Statistics */
    {
        struct feature_window *latest = ring_buffer_get(-1);
        APPEND(
            "[RING BUFFER + MULTI-SCALE FEATURES]\n"
            "=== Temporal Analysis (last %d windows = %.1f sec) ===\n\n"
            "  Windows processed:         %" PRIu64 "\n"
            "  Buffer utilization:        %u/%d (%.1f%%)\n"
            "  Running baseline:          %.0f pps\n"
            "  Mode:                      MEASURE-ONLY (no thresholds)\n\n",
            RING_BUFFER_SIZE, RING_BUFFER_SIZE * 0.05,
            g_ring_buffer.total_windows,
            g_ring_buffer.count, RING_BUFFER_SIZE,
            (float)g_ring_buffer.count * 100.0f / RING_BUFFER_SIZE,
            latest ? latest->pps_baseline : 0);

        if (latest) {
            APPEND(
                "  [Temporal Features - Last Window]\n"
                "    Delta PPS (250ms):       %+.0f\n"
                "    Delta PPS (500ms):       %+.0f\n"
                "    PPS Variance:            %.0f\n"
                "    Ratio vs Baseline:       %.2fx\n\n"
                "  [Multi-Scale Features]\n"
                "    Top IP (50ms):           %.0f pps\n"
                "    Top IP (1s):             %.0f pps\n"
                "    Top IP (1min):           %.0f pps\n"
                "    Burst Ratio (50ms/1min): %.2fx\n"
                "    IP Concentration:        %.1f%%\n\n",
                latest->delta_pps_5w,
                latest->delta_pps_10w,
                latest->pps_variance,
                latest->ratio_vs_baseline,
                latest->top_ip_pps_50ms,
                latest->top_ip_pps_1s,
                latest->top_ip_pps_1min,
                latest->ratio_50ms_1min,
                latest->ip_concentration * 100.0f);
        }
    }

    double pps_current = (window_total_pkts > 0 && window_duration > 0.001) ?
                         (double)window_total_pkts / window_duration : 0.0;

    APPEND(
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

    APPEND(
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

    /* SKETCH-ADV: Per-protocol features log section */
    if (g_sketch_adv_enabled) {
        double win_sec = (window_duration > 0.001) ? window_duration : 1.0;
        uint64_t global_total = octosketch_get_total(&g_merged_sketch_attack);
        double global_pps = (win_sec > 0.001) ? (double)global_total / win_sec : 0.0;

        APPEND("[SKETCH-ADV PER-PROTOCOL FEATURES]\n"
               "=== Per-Protocol Sketch Analysis (12 sketches) ===\n\n");

        struct {
            const char *name;
            const char *port_info;
            struct octosketch *sketch;
        } proto_list[12] = {
            { "DNS",       "port 53",     &g_merged_sketch_dns },
            { "NTP",       "port 123",    &g_merged_sketch_ntp },
            { "SNMP",      "port 161",    &g_merged_sketch_snmp },
            { "SSDP",      "port 1900",   &g_merged_sketch_ssdp },
            { "PortMap",   "port 111",    &g_merged_sketch_portmap },
            { "NetBIOS",   "port 137/138",&g_merged_sketch_netbios },
            { "LDAP",      "port 389",    &g_merged_sketch_ldap },
            { "MSSQL",     "port 1433/4", &g_merged_sketch_mssql },
            { "TFTP",      "port 69",     &g_merged_sketch_tftp },
            { "SYN",       "TCP SYN",     &g_merged_sketch_syn },
            { "HTTP",      "port 80/443", &g_merged_sketch_http },
            { "UDP-Other", "other UDP",   &g_merged_sketch_udp_other },
        };

        for (int p = 0; p < 12; p++) {
            uint64_t total = octosketch_get_total(proto_list[p].sketch);
            double pps = (double)total / win_sec;

            /* Count heavy hitters for this protocol sketch */
            int hh_count = 0;
            double hh_threshold = HEAVY_HITTER_PPS_THRESHOLD * win_sec;
            for (uint32_t idx = 0; idx < 65536; idx++) {
                if (proto_list[p].sketch->ip_counts[idx] >= (uint32_t)hh_threshold &&
                    proto_list[p].sketch->ip_addrs[idx] != 0) {
                    hh_count++;
                }
            }

            /* IP concentration: top1 / total */
            struct heavy_hitter top1[1];
            octosketch_top_k(proto_list[p].sketch, 1, top1);
            double concentration = (total > 0) ? (double)top1[0].count * 100.0 / total : 0.0;

            /* Ratio vs global */
            double ratio = (global_pps > 0.0) ? pps / global_pps : 0.0;

            APPEND("  [%s (%s)]\n"
                   "    PPS:              %.1f\n"
                   "    Heavy-hitters:    %d\n"
                   "    IP Concentration: %.1f%%\n"
                   "    Ratio vs Total:   %.2f\n\n",
                   proto_list[p].name, proto_list[p].port_info,
                   pps, hh_count, concentration, ratio);
        }

        /* Packet size features from global sketch */
        uint64_t global_bytes = octosketch_get_bytes(&g_merged_sketch_attack);
        double avg_pkt_size = (global_total > 0) ? (double)global_bytes / global_total : 0.0;

        /* Compute variance from per-worker sum-of-squares */
        uint64_t total_sq_sum = 0;
        for (int i = 0; i < NUM_RX_QUEUES; i++) {
            total_sq_sum += g_worker_pktlen_sq_sum[i];
        }
        double pkt_size_var = 0.0;
        if (global_total > 0) {
            double mean_sq = (double)total_sq_sum / global_total;
            pkt_size_var = mean_sq - (avg_pkt_size * avg_pkt_size);
            if (pkt_size_var < 0.0) pkt_size_var = 0.0;
        }

        APPEND("  [Packet Size]\n"
               "    Avg Packet Size:      %.1f\n"
               "    Packet Size Variance: %.1f\n\n",
               avg_pkt_size, pkt_size_var);

        /* Write binary record with all 64 features */
        if (g_sketch_adv_file) {
            struct sketch_adv_record rec;
            memset(&rec, 0, sizeof(rec));

            rec.magic = SKETCH_ADV_MAGIC;
            rec.version = SKETCH_ADV_VERSION;

            uint64_t elapsed_cycles = cur_tsc - g_start_tsc;
            rec.timestamp_ns = (uint64_t)((double)elapsed_cycles * 1e9 / (double)rte_get_tsc_hz());

            /* Block 1: 14 global sketch features from ring buffer */
            struct feature_window *latest_rb = ring_buffer_get(-1);
            if (latest_rb) {
                rec.delta_pps_5w = latest_rb->delta_pps_5w;
                rec.delta_pps_10w = latest_rb->delta_pps_10w;
                rec.pps_variance = latest_rb->pps_variance;
                rec.pps_baseline = latest_rb->pps_baseline;
                rec.ratio_vs_baseline = latest_rb->ratio_vs_baseline;
                rec.top_ip_pps_50ms = latest_rb->top_ip_pps_50ms;
                rec.top_ip_pps_1s = latest_rb->top_ip_pps_1s;
                rec.top_ip_pps_1min = latest_rb->top_ip_pps_1min;
                rec.ratio_50ms_1min = latest_rb->ratio_50ms_1min;
                rec.num_heavy_hitters = latest_rb->num_heavy_hitters;
                rec.ip_concentration = latest_rb->ip_concentration;
                rec.new_ips_ratio = latest_rb->new_ips_ratio;
                rec.attack_entropy = latest_rb->attack_entropy;
                rec.adaptive_threshold = latest_rb->adaptive_threshold;
            }

            /* Block 2: 48 per-protocol features (recompute from merged sketches) */
            struct octosketch *proto_sketches[12] = {
                &g_merged_sketch_dns, &g_merged_sketch_ntp, &g_merged_sketch_snmp,
                &g_merged_sketch_ssdp, &g_merged_sketch_portmap, &g_merged_sketch_netbios,
                &g_merged_sketch_ldap, &g_merged_sketch_mssql, &g_merged_sketch_tftp,
                &g_merged_sketch_syn, &g_merged_sketch_http, &g_merged_sketch_udp_other,
            };

            for (int p = 0; p < 12; p++) {
                uint64_t ptotal = octosketch_get_total(proto_sketches[p]);
                double ppps = (double)ptotal / win_sec;

                int phh = 0;
                double phh_thr = HEAVY_HITTER_PPS_THRESHOLD * win_sec;
                for (uint32_t idx = 0; idx < 65536; idx++) {
                    if (proto_sketches[p]->ip_counts[idx] >= (uint32_t)phh_thr &&
                        proto_sketches[p]->ip_addrs[idx] != 0) {
                        phh++;
                    }
                }

                struct heavy_hitter ptop[1];
                octosketch_top_k(proto_sketches[p], 1, ptop);
                double pconc = (ptotal > 0) ? (double)ptop[0].count / ptotal : 0.0;
                double pratio = (global_pps > 0.0) ? ppps / global_pps : 0.0;

                rec.pps_proto[p] = ppps;
                rec.heavy_hitters_proto[p] = (double)phh;
                rec.ip_concentration_proto[p] = pconc;
                rec.ratio_vs_total_proto[p] = pratio;
            }

            /* Block 3: packet size features */
            rec.avg_packet_size = avg_pkt_size;
            rec.packet_size_variance = pkt_size_var;

            fwrite(&rec, sizeof(rec), 1, g_sketch_adv_file);
            fflush(g_sketch_adv_file);
        }
    }

    #undef APPEND

    printf("%s", buffer);
    fflush(stdout);  /* Force immediate write to stdout (no buffering) */

    if (g_log_file) {
        fprintf(g_log_file, "%s", buffer);
        fflush(g_log_file);
    }

    /* Write binary log record for ML training */
    if (g_binary_log_enabled && g_binary_log_file) {
        struct binary_log_record record;
        memset(&record, 0, sizeof(record));

        record.magic = BINARY_LOG_MAGIC;
        record.version = BINARY_LOG_VERSION;

        /* Timestamp in nanoseconds since start */
        uint64_t elapsed_cycles = cur_tsc - g_start_tsc;
        double elapsed_ns = (double)elapsed_cycles * 1e9 / (double)rte_get_tsc_hz();
        record.timestamp_ns = (uint64_t)elapsed_ns;

        /* Core counters */
        record.total_packets = g_stats.total_packets;
        record.total_bytes = g_stats.total_bytes;
        record.tcp_packets = g_stats.tcp_packets;
        record.udp_packets = g_stats.udp_packets;
        record.icmp_packets = g_stats.icmp_packets;
        record.syn_packets = g_stats.syn_packets;
        record.syn_ack_packets = g_stats.syn_ack_packets;
        record.http_requests = g_stats.http_requests;
        record.dns_queries = g_stats.dns_queries;
        record.baseline_packets = g_stats.baseline_packets;
        record.attack_packets = g_stats.attack_packets;

        /* Protocol-specific counters */
        record.ntp_monlist_queries = g_stats.ntp_monlist_queries;
        record.ntp_responses = g_stats.ntp_responses;
        record.ntp_response_size_sum = g_stats.ntp_response_size_sum;
        record.dns_any_queries = g_stats.dns_any_queries;
        record.dns_txt_queries = g_stats.dns_txt_queries;
        record.dns_responses = g_stats.dns_responses;
        record.dns_response_size_sum = g_stats.dns_response_size_sum;
        record.snmp_getbulk_requests = g_stats.snmp_getbulk_requests;
        record.snmp_responses = g_stats.snmp_responses;
        record.snmp_response_size_sum = g_stats.snmp_response_size_sum;
        record.ssdp_msearch_packets = g_stats.ssdp_msearch_packets;
        record.ssdp_responses = g_stats.ssdp_responses;
        record.portmap_getport_calls = g_stats.portmap_getport_calls;
        record.portmap_dump_calls = g_stats.portmap_dump_calls;
        record.netbios_name_queries = g_stats.netbios_name_queries;
        record.netbios_dgram_packets = g_stats.netbios_dgram_packets;
        record.ldap_bind_requests = g_stats.ldap_bind_requests;
        record.ldap_search_requests = g_stats.ldap_search_requests;
        record.mssql_sqlbatch_packets = g_stats.mssql_sqlbatch_packets;
        record.mssql_rpc_packets = g_stats.mssql_rpc_packets;
        record.tftp_rrq_packets = g_stats.tftp_rrq_packets;
        record.tftp_wrq_packets = g_stats.tftp_wrq_packets;

        fwrite(&record, sizeof(record), 1, g_binary_log_file);
        fflush(g_binary_log_file);
    }

    /* Reset instantaneous counters */
    memset(window_baseline_pkts, 0, sizeof(window_baseline_pkts));
    memset(window_attack_pkts, 0, sizeof(window_attack_pkts));
    memset(window_baseline_bytes, 0, sizeof(window_baseline_bytes));
    memset(window_attack_bytes, 0, sizeof(window_attack_bytes));
    last_window_reset_tsc = cur_tsc;
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
    uint64_t local_syn_pkts = 0, local_syn_ack_pkts = 0;
    uint64_t local_http_reqs = 0, local_dns_queries = 0;
    uint64_t local_baseline_bytes = 0, local_attack_bytes = 0;
    uint64_t local_bursts_total = 0, local_bursts_empty = 0;
    uint64_t local_cycles = 0;

    /* ========== Protocol-Specific Local Counters for CIC-DDoS-2019 ========== */
    uint64_t local_ntp_monlist = 0, local_ntp_responses = 0, local_ntp_resp_size_sum = 0;
    uint64_t local_dns_any = 0, local_dns_txt = 0, local_dns_responses = 0, local_dns_resp_size_sum = 0;
    uint64_t local_snmp_getbulk = 0, local_snmp_responses = 0, local_snmp_resp_size_sum = 0;
    uint64_t local_ssdp_msearch = 0, local_ssdp_responses = 0;
    uint64_t local_portmap_getport = 0, local_portmap_dump = 0;
    uint64_t local_netbios_name = 0, local_netbios_dgram = 0;
    uint64_t local_ldap_bind = 0, local_ldap_search = 0;
    uint64_t local_mssql_sqlbatch = 0, local_mssql_rpc = 0;
    uint64_t local_tftp_rrq = 0, local_tftp_wrq = 0;
    /* ======================================================================= */

    /* Per-worker sketch (local, no atomics) */
    struct octosketch *my_sketch = &g_worker_sketch_attack[queue_id];

    /* Multi-scale sketches (local, no atomics) */
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
                uint16_t tcp_dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);

                /* SYN Flood detection */
                if (unlikely(tcp_flags & RTE_TCP_SYN_FLAG)) {
                    local_syn_pkts++;
                    local_syn_ack_pkts += (tcp_flags & RTE_TCP_ACK_FLAG) ? 1 : 0;
                }

                /* WebDDoS / HTTP detection (ports 80, 443) */
                if (tcp_dst_port == 80 || tcp_dst_port == 443) {
                    local_http_reqs++;
                }
                /* LDAP TCP detection (ports 389, 636) */
                else if (tcp_dst_port == 389 || tcp_dst_port == 636) {
                    local_ldap_bind++;
                }
                /* MSSQL TCP detection (port 1433) */
                else if (tcp_dst_port == 1433) {
                    local_mssql_sqlbatch++;
                }
                /* PortMapper TCP detection (port 111) */
                else if (tcp_dst_port == 111) {
                    local_portmap_getport++;
                }
            }
            else if (proto == IPPROTO_UDP) {
                local_udp_pkts++;
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                uint16_t udp_src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                uint16_t udp_payload_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
                uint8_t *udp_payload = (uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr);

                /* DNS detection (port 53) */
                if (udp_dst_port == 53 || udp_src_port == 53) {
                    if (udp_payload_len >= 12) {
                        uint16_t dns_flags = (uint16_t)(udp_payload[2] << 8) | udp_payload[3];
                        uint16_t dns_qdcount = (uint16_t)(udp_payload[4] << 8) | udp_payload[5];
                        bool dns_is_response = (dns_flags & 0x8000) != 0;

                        if (dns_is_response) {
                            local_dns_responses++;
                            local_dns_resp_size_sum += pkt_len;
                        } else {
                            local_dns_queries++;
                        }

                        if (!dns_is_response && dns_qdcount > 0) {
                            /* Parse QNAME (variable length), then read QTYPE */
                            uint16_t idx = 12;
                            while (idx < udp_payload_len) {
                                uint8_t len = udp_payload[idx];
                                if (len == 0) {
                                    idx += 1;
                                    break;
                                }
                                if ((len & 0xC0) == 0xC0) {
                                    /* Name compression pointer */
                                    idx += 2;
                                    break;
                                }
                                idx += 1 + len;
                            }
                            if (idx + 3 < udp_payload_len) {
                                uint16_t qtype = (uint16_t)(udp_payload[idx] << 8) | udp_payload[idx + 1];
                                if (qtype == 255) {
                                    local_dns_any++;
                                } else if (qtype == 16) {
                                    local_dns_txt++;
                                }
                            }
                        }
                    }
                }
                /* NTP detection (port 123) */
                else if (udp_dst_port == 123 || udp_src_port == 123) {
                    if (udp_payload_len >= 8) {
                        uint8_t ntp_mode = (udp_payload[0] >> 0) & 0x07;
                        if (ntp_mode == 7 && udp_dst_port == 123) {
                            local_ntp_monlist++;  // Mode 7 = Private/Monlist
                        }
                    }
                    if (udp_src_port == 123) {
                        local_ntp_responses++;
                        local_ntp_resp_size_sum += pkt_len;
                    }
                }
                /* SNMP detection (port 161) */
                else if (udp_dst_port == 161 || udp_src_port == 161) {
                    if (udp_src_port == 161) {
                        local_snmp_responses++;
                        local_snmp_resp_size_sum += pkt_len;
                    } else if (udp_dst_port == 161 && udp_payload_len >= 16) {
                        int pdu_tag = snmp_get_pdu_tag(udp_payload, udp_payload_len);
                        if (pdu_tag == 0xA5) {
                            local_snmp_getbulk++;
                        }
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
                /* PortMapper UDP detection (port 111) */
                else if (udp_dst_port == 111) {
                    local_portmap_getport++;
                }
                /* NetBIOS detection (ports 137, 138) */
                else if (udp_dst_port == 137) {
                    local_netbios_name++;
                }
                else if (udp_dst_port == 138) {
                    local_netbios_dgram++;
                }
                /* TFTP detection (port 69) */
                else if (udp_dst_port == 69 && udp_payload_len >= 2) {
                    uint16_t tftp_opcode = (udp_payload[0] << 8) | udp_payload[1];
                    if (tftp_opcode == 1) {
                        local_tftp_rrq++;
                    } else if (tftp_opcode == 2) {
                        local_tftp_wrq++;
                    }
                }
                /* MSSQL UDP detection (port 1434) */
                else if (udp_dst_port == 1434) {
                    local_mssql_sqlbatch++;
                }
                /* CLDAP/LDAP UDP detection (port 389) */
                else if (udp_dst_port == 389) {
                    local_ldap_search++;
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

                    /* SKETCH-ADV: Update per-protocol sketch */
                    if (unlikely(g_sketch_adv_enabled)) {
                        struct octosketch *proto_sketch = NULL;
                        uint16_t dst_port = 0;
                        uint8_t tcp_flags_local = 0;

                        if (proto == IPPROTO_TCP) {
                            struct rte_tcp_hdr *th = (struct rte_tcp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
                            dst_port = rte_be_to_cpu_16(th->dst_port);
                            tcp_flags_local = th->tcp_flags;

                            if (tcp_flags_local & RTE_TCP_SYN_FLAG) {
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
        ws->http_requests += local_http_reqs;
        ws->dns_queries += local_dns_queries;
        ws->baseline_bytes += local_baseline_bytes;
        ws->attack_bytes += local_attack_bytes;
        ws->rx_bursts_total += local_bursts_total;
        ws->rx_bursts_empty += local_bursts_empty;

        /* ========== Protocol-Specific Stats Update ========== */
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
        /* ==================================================== */

        /* Update window stats */
        window_baseline_pkts[queue_id] += local_baseline_pkts;
        window_baseline_bytes[queue_id] += local_baseline_bytes;
        window_attack_pkts[queue_id] += local_attack_pkts;
        window_attack_bytes[queue_id] += local_attack_bytes;

        /* Reset local counters */
        local_total_pkts = local_total_bytes = 0;
        local_baseline_pkts = local_attack_pkts = 0;
        local_tcp_pkts = local_udp_pkts = local_icmp_pkts = 0;
        local_syn_pkts = local_syn_ack_pkts = 0;
        local_http_reqs = local_dns_queries = 0;
        local_baseline_bytes = local_attack_bytes = 0;
        local_bursts_total = local_bursts_empty = 0;

        /* ========== Reset Protocol-Specific Counters ========== */
        local_ntp_monlist = local_ntp_responses = local_ntp_resp_size_sum = 0;
        local_dns_any = local_dns_txt = local_dns_responses = local_dns_resp_size_sum = 0;
        local_snmp_getbulk = local_snmp_responses = local_snmp_resp_size_sum = 0;
        local_ssdp_msearch = local_ssdp_responses = 0;
        local_portmap_getport = local_portmap_dump = 0;
        local_netbios_name = local_netbios_dgram = 0;
        local_ldap_bind = local_ldap_search = 0;
        local_mssql_sqlbatch = local_mssql_rpc = 0;
        local_tftp_rrq = local_tftp_wrq = 0;
        /* ====================================================== */
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
    ws->http_requests += local_http_reqs;
    ws->dns_queries += local_dns_queries;

    /* ========== Final Protocol-Specific Stats Update ========== */
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
    /* ========================================================= */

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

    /* Parse application arguments (after EAL args) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--binary-log") == 0) {
            g_binary_log_enabled = true;
            printf("Binary logging enabled (compact ML training format)\n");
        } else if (strcmp(argv[i], "--sketch-adv") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_sketch_adv_path = argv[i + 1];
                i++;  /* Skip path argument */
            } else {
                printf("Error: --sketch-adv requires output file path\n");
                printf("  Example: --sketch-adv ../results/dns_attack_run1.bin\n");
                return 1;
            }
            g_sketch_adv_enabled = true;
            printf("Sketch-ADV enabled → %s\n", g_sketch_adv_path);
        } else if (strcmp(argv[i], "--log-output") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                g_log_output_path = argv[i + 1];
                i++;  /* Skip path argument */
            } else {
                printf("Error: --log-output requires output file path\n");
                printf("  Example: --log-output /path/to/attack_dns_run1.log\n");
                return 1;
            }
            printf("Log output → %s\n", g_log_output_path);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [EAL options] -- [Application options]\n", argv[0]);
            printf("\nApplication options:\n");
            printf("  --log-output <path>   Set log output file path\n");
            printf("                        (default: ../results/mira_detector_multicore.log)\n");
            printf("  --binary-log          Enable binary logging for ML training\n");
            printf("                        (writes to ../results/mira_detector_ml.bin)\n");
            printf("  --sketch-adv <path>   Enable per-protocol sketches (64-feature ML)\n");
            printf("                        Writes binary features to <path>\n");
            printf("  --help, -h            Show this help message\n");
            return 0;
        }
    }

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

    g_log_file = fopen(g_log_output_path, "w");
    if (!g_log_file)
        printf("Warning: Could not open log file: %s\n", g_log_output_path);
    else
        printf("Log file: %s\n", g_log_output_path);

    /* Open binary log file if enabled */
    if (g_binary_log_enabled) {
        g_binary_log_file = fopen("../results/mira_detector_ml.bin", "wb");
        if (!g_binary_log_file) {
            printf("Warning: Could not open binary log file\n");
            g_binary_log_enabled = false;
        } else {
            printf("Binary log file opened: ../results/mira_detector_ml.bin\n");
        }
    }

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

    size_t per_worker_mem = octosketch_memory_size();
    size_t total_sketch_mem = per_worker_mem * (NUM_RX_QUEUES + 1);  /* Workers + merged */
    printf("\n[OctoSketch Initialized - Optimized Architecture]\n");
    printf("  Per-worker sketches:     %d × %.1f KB = %.1f KB\n",
           NUM_RX_QUEUES, per_worker_mem / 1024.0, (per_worker_mem * NUM_RX_QUEUES) / 1024.0);
    printf("  Merged sketch:           1 × %.1f KB = %.1f KB\n",
           per_worker_mem / 1024.0, per_worker_mem / 1024.0);
    printf("  Total memory:            %.1f KB\n", total_sketch_mem / 1024.0);
    printf("  Configuration:           %d rows × %d columns per sketch\n",
           SKETCH_ROWS, SKETCH_COLS);
    printf("  Architecture:            Per-worker (NO atomics, NO contention)\n");
    printf("  Sampling:                1 in %d packets (%.2f%% overhead)\n",
           SKETCH_SAMPLE_RATE, 100.0 / SKETCH_SAMPLE_RATE);
    printf("  Update policy:           Attack traffic only\n\n");

    /* Initialize Ring Buffer for temporal analysis */
    memset(&g_ring_buffer, 0, sizeof(g_ring_buffer));
    printf("[Ring Buffer Initialized - Temporal Analysis]\n");
    printf("  Buffer size:             %d windows (%.1f seconds)\n",
           RING_BUFFER_SIZE, RING_BUFFER_SIZE * 0.05);
    printf("  Memory:                  %.1f KB\n",
           sizeof(struct ring_buffer) / 1024.0);
    printf("  Features per window:     %d (42 base + 14 temporal)\n\n",
           ML_EXTENDED_FEATURES);

    /* Initialize Multi-Scale Sketches */
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "MS-50ms-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_50ms, name);
        snprintf(name, sizeof(name), "MS-1s-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_1s, name);
        snprintf(name, sizeof(name), "MS-10s-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_10s, name);
        snprintf(name, sizeof(name), "MS-1min-W%d", i);
        octosketch_init(&g_multiscale[i].sketch_1min, name);
        g_multiscale[i].windows_since_1s_reset = 0;
        g_multiscale[i].windows_since_10s_reset = 0;
        g_multiscale[i].windows_since_1min_reset = 0;
    }
    octosketch_init(&g_merged_multiscale.sketch_50ms, "MS-50ms-Merged");
    octosketch_init(&g_merged_multiscale.sketch_1s, "MS-1s-Merged");
    octosketch_init(&g_merged_multiscale.sketch_10s, "MS-10s-Merged");
    octosketch_init(&g_merged_multiscale.sketch_1min, "MS-1min-Merged");

    printf("[Multi-Scale Sketches Initialized]\n");
    printf("  Scales:                  50ms, 1s, 10s, 1min\n");
    printf("  Per-worker memory:       %.1f KB × 4 scales = %.1f KB\n",
           octosketch_memory_size() / 1024.0,
           (octosketch_memory_size() * 4) / 1024.0);
    printf("  Total multi-scale mem:   %.1f KB\n\n",
           (octosketch_memory_size() * 4 * (NUM_RX_QUEUES + 1)) / 1024.0);

    /* Initialize Sketch-ADV per-protocol sketches */
    if (g_sketch_adv_enabled) {
        const char *proto_names[12] = {
            "DNS", "NTP", "SNMP", "SSDP", "PortMap", "NetBIOS",
            "LDAP", "MSSQL", "TFTP", "SYN", "HTTP", "UDP-Other"
        };
        struct octosketch (*worker_arrays[12])[NUM_RX_QUEUES] = {
            &g_worker_sketch_dns, &g_worker_sketch_ntp, &g_worker_sketch_snmp,
            &g_worker_sketch_ssdp, &g_worker_sketch_portmap, &g_worker_sketch_netbios,
            &g_worker_sketch_ldap, &g_worker_sketch_mssql, &g_worker_sketch_tftp,
            &g_worker_sketch_syn, &g_worker_sketch_http, &g_worker_sketch_udp_other
        };
        struct octosketch *merged_array[12] = {
            &g_merged_sketch_dns, &g_merged_sketch_ntp, &g_merged_sketch_snmp,
            &g_merged_sketch_ssdp, &g_merged_sketch_portmap, &g_merged_sketch_netbios,
            &g_merged_sketch_ldap, &g_merged_sketch_mssql, &g_merged_sketch_tftp,
            &g_merged_sketch_syn, &g_merged_sketch_http, &g_merged_sketch_udp_other
        };

        for (int p = 0; p < 12; p++) {
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                char name[32];
                snprintf(name, sizeof(name), "%s-W%d", proto_names[p], i);
                octosketch_init(&(*worker_arrays[p])[i], name);
            }
            char mname[32];
            snprintf(mname, sizeof(mname), "%s-Merged", proto_names[p]);
            octosketch_init(merged_array[p], mname);
        }
        memset(g_worker_pktlen_sq_sum, 0, sizeof(g_worker_pktlen_sq_sum));

        size_t adv_per_worker = octosketch_memory_size() * 12;
        size_t adv_total = adv_per_worker * (NUM_RX_QUEUES + 1);
        printf("[Sketch-ADV Per-Protocol Sketches Initialized]\n");
        printf("  Protocols:               12 (DNS,NTP,SNMP,SSDP,PortMap,NetBIOS,LDAP,MSSQL,TFTP,SYN,HTTP,UDP-Other)\n");
        printf("  Per-worker memory:       %.1f KB × 12 protocols = %.1f KB\n",
               octosketch_memory_size() / 1024.0, adv_per_worker / 1024.0);
        printf("  Total sketch-adv mem:    %.1f MB (%.1f KB)\n",
               adv_total / (1024.0 * 1024.0), adv_total / 1024.0);
        printf("  Binary record size:      %zu bytes (%d features)\n",
               sizeof(struct sketch_adv_record), SKETCH_ADV_FEATURES_TOTAL);

        /* Open binary output file for sketch-adv features */
        g_sketch_adv_file = fopen(g_sketch_adv_path, "wb");
        if (!g_sketch_adv_file) {
            printf("  [ERROR] Could not open sketch-adv output: %s\n", g_sketch_adv_path);
            g_sketch_adv_enabled = false;
        } else {
            printf("  Binary output:           %s\n", g_sketch_adv_path);
        }
        printf("\n");
    }

    printf("╔═══════════════════════════════════════════════════════════════════════╗\n");
    printf("║  MIRA DDoS DETECTOR - DPDK + OCTOSKETCH (%d workers + 1 coord)       ║\n", NUM_RX_QUEUES);
    printf("║  Optimized: Per-worker sketches + Sampling + Attack-only             ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Comparing against MULTI-LF (2025):\n");
    printf("  - MULTI-LF detection latency: 866 ms\n");
    printf("  - MIRA detection latency:     <50 ms (17-170× faster)\n");
    printf("  - DPDK architecture:          %d RX workers + 1 coordinator\n", NUM_RX_QUEUES);
    printf("  - OctoSketch advantage:       O(1) memory, per-worker (no atomics)\n");
    printf("  - Sketch overhead:            <3%% (sampled updates)\n\n");
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

    if (g_sketch_adv_file) {
        fclose(g_sketch_adv_file);
        printf("Sketch-ADV binary saved: %s\n", g_sketch_adv_path);
    }

    rte_hash_free(ip_hash);
    printf("\nShutting down...\n");
    rte_eal_cleanup();

    return 0;
}
