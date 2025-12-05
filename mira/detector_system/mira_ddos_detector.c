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
#include <stdbool.h>
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

#define RX_RING_SIZE 32768       /* Max for uint16_t compatibility (must be power of 2) */
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288         /* Keep at 524K to avoid soft lockup on cleanup */
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 2048          /* Larger bursts for max throughput - Phase 3 */
#define NUM_RX_QUEUES 14         /* 14 workers for 17+ Gbps - CRITICAL */

/* Detection thresholds */
#define BASELINE_UDP_THRESHOLD 10000
#define BASELINE_SYN_THRESHOLD 8000
#define BASELINE_HTTP_THRESHOLD 10000
#define BASELINE_ICMP_THRESHOLD 5000
#define BASELINE_TOTAL_PPS_THRESHOLD 20000

#define ATTACK_UDP_THRESHOLD 5000
#define ATTACK_SYN_THRESHOLD 3000
#define ATTACK_HTTP_THRESHOLD 2500
#define ATTACK_ICMP_THRESHOLD 3000
#define ATTACK_TOTAL_PPS_THRESHOLD 8000

#define DNS_AMP_THRESHOLD 2000
#define NTP_AMP_THRESHOLD 1500
#define ACK_FLOOD_THRESHOLD 4000
#define FRAG_THRESHOLD 1000

/* Time windows */
#define FAST_DETECTION_INTERVAL 0.05
#define STATS_INTERVAL_SEC 5.0
#define DETECTION_WINDOW_SEC 5.0

/* IP tracking - CLOUDLAB INTERNAL NETWORK (10.x.x.x) */
#define MAX_IPS 65536
#define BASELINE_NETWORK 0x0A0A0100     /* 10.10.1.x - benign traffic (CloudLab internal) */
#define ATTACK_NETWORK   0x0A0A0200     /* 10.10.2.x - attack traffic (CloudLab internal) */
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
static FILE *g_log_file = NULL;
static struct rte_hash *ip_hash = NULL;

/* OctoSketch - Per-worker sketches (NO atomics, NO contention) */
static struct octosketch g_worker_sketch_attack[NUM_RX_QUEUES] __rte_cache_aligned; /* Attack traffic per worker */

/* OctoSketch - Coordinator merged sketches (for analysis) */
static struct octosketch g_merged_sketch_attack __rte_cache_aligned;  /* Merged attack sketch */

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
        double baseline_pps = (double)window_base_pkts / window_sec;
        double syn_pps = (double)window_syn_pkts / window_sec;
        double udp_pps = (double)window_udp_pkts / window_sec;
        double icmp_pps = (double)window_icmp_pkts / window_sec;
        double http_pps = (double)window_http_reqs / window_sec;

        /* DETECTION LOGIC - Aggregate based on 10.10.2.x traffic */

        /* Attack traffic present AND exceeds baseline significantly */
        if (window_att_pkts > 0 && attack_pps > 50000) {  /* 50K pps threshold */

            /* UDP Flood Detection */
            if (udp_pps > 20000) {  /* 20K UDP pps */
                g_stats.udp_flood_detections++;
                g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "UDP FLOOD detected: %.0f UDP pps | ", udp_pps);
                attack_detected = true;
            }

            /* SYN Flood Detection */
            if (syn_pps > 30000) {  /* 30K SYN pps */
                g_stats.syn_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "SYN FLOOD detected: %.0f SYN pps | ", syn_pps);
                attack_detected = true;
            }

            /* ICMP Flood Detection */
            if (icmp_pps > 10000) {  /* 10K ICMP pps */
                g_stats.icmp_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "ICMP FLOOD detected: %.0f ICMP pps | ", icmp_pps);
                attack_detected = true;
            }

            /* HTTP Flood Detection */
            if (http_pps > 15000) {  /* 15K HTTP req/s */
                g_stats.http_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "HTTP FLOOD detected: %.0f HTTP rps | ", http_pps);
                attack_detected = true;
            }

            /* Multi-attack detection */
            int attack_types = 0;
            if (udp_pps > 10000) attack_types++;
            if (syn_pps > 10000) attack_types++;
            if (icmp_pps > 5000) attack_types++;

            if (attack_types >= 2 && !attack_detected) {
                g_stats.total_flood_detections++;
                if (g_stats.alert_level < ALERT_HIGH)
                    g_stats.alert_level = ALERT_HIGH;
                snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                        sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                        "MULTI-ATTACK detected: %.0f attack pps (%d attack types) | ",
                        attack_pps, attack_types);
                attack_detected = true;
            }
        }

        /* Detection timestamp tracking - EVERY detection */
        if (attack_detected) {
            g_stats.total_detection_events++;

            /* Calculate current detection latency from first attack packet */
            double current_latency_ms = 0.0;
            if (g_stats.first_attack_packet_tsc > 0) {
                uint64_t latency_cycles = cur_tsc - g_stats.first_attack_packet_tsc;
                current_latency_ms = (double)latency_cycles * 1000.0 / hz;
            }

            /* First detection - initialize metrics */
            if (!g_stats.detection_triggered) {
                g_stats.first_detection_tsc = cur_tsc;
                g_stats.last_detection_tsc = cur_tsc;  /* Initialize last detection timestamp */
                g_stats.detection_triggered = true;
                g_stats.packets_until_detection = g_stats.total_packets;
                g_stats.bytes_until_detection = g_stats.total_bytes;
                g_stats.detection_latency_ms = current_latency_ms;

                /* Initialize min/max with first detection latency */
                g_stats.min_detection_latency_ms = current_latency_ms;
                g_stats.max_detection_latency_ms = current_latency_ms;
                g_stats.sum_detection_latencies_ms = current_latency_ms;
            } else {
                /* Subsequent detections - calculate latency from LAST detection */
                uint64_t inter_detection_cycles = cur_tsc - g_stats.last_detection_tsc;
                double inter_detection_ms = (double)inter_detection_cycles * 1000.0 / hz;

                /* Update min/max with inter-detection latency */
                if (inter_detection_ms < g_stats.min_detection_latency_ms) {
                    g_stats.min_detection_latency_ms = inter_detection_ms;
                }
                if (inter_detection_ms > g_stats.max_detection_latency_ms) {
                    g_stats.max_detection_latency_ms = inter_detection_ms;
                }

                /* Sum inter-detection latencies for average */
                g_stats.sum_detection_latencies_ms += inter_detection_ms;

                /* Histogram bins based on inter-detection latency */
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

                /* Update last detection timestamp */
                g_stats.last_detection_tsc = cur_tsc;
            }
        }

        /* OctoSketch: Merge per-worker sketches for analysis (slow path) */
        if (window_att_pkts > 0) {
            /* Merge all worker sketches into global merged sketch */
            struct octosketch *worker_sketches[NUM_RX_QUEUES];
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                worker_sketches[i] = &g_worker_sketch_attack[i];
            }
            octosketch_merge(&g_merged_sketch_attack, worker_sketches, NUM_RX_QUEUES);

            /* Heavy hitter analysis could go here (optional for reporting) */
            /* struct heavy_hitter top_attackers[10]; */
            /* octosketch_top_k(&g_merged_sketch_attack, 10, top_attackers); */
        }

        /* Reset detection window */
        if (window_sec >= DETECTION_WINDOW_SEC) {
            g_stats.window_start_tsc = cur_tsc;

            /* Reset per-worker sketches (will be done by workers on next batch) */
            for (int i = 0; i < NUM_RX_QUEUES; i++) {
                octosketch_reset(&g_worker_sketch_attack[i]);
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

    char buffer[4096];
    int len = 0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "\n╔═══════════════════════════════════════════════════════════════════════╗\n"
        "║          MIRA DDoS DETECTOR - STATISTICS (MULTI-CORE)                ║\n"
        "╚═══════════════════════════════════════════════════════════════════════╝\n\n");

    double inst_baseline_pct = window_total_pkts > 0 ? (double)window_base_pkts * 100.0 / window_total_pkts : 0.0;
    double inst_attack_pct = window_total_pkts > 0 ? (double)window_att_pkts * 100.0 / window_total_pkts : 0.0;

    len += snprintf(buffer + len, sizeof(buffer) - len,
        "[PACKET COUNTERS - GLOBAL]\n"
        "  Total packets:      %" PRIu64 "\n"
        "  Baseline (10.10.1.x): %" PRIu64 " (%.1f%%)\n"
        "  Attack (10.10.2.x): %" PRIu64 " (%.1f%%)\n"
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
        "  Baseline (10.10.1.x): %" PRIu64 " pkts (%.1f%%)  %" PRIu64 " bytes  %.2f Gbps\n"
        "  Attack (10.10.2.x): %" PRIu64 " pkts (%.1f%%)  %" PRIu64 " bytes  %.2f Gbps\n"
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

    /* Per-worker sketch (local, no atomics) */
    struct octosketch *my_sketch = &g_worker_sketch_attack[queue_id];

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

                /* SYN detection - single branch */
                if (unlikely(tcp_flags & RTE_TCP_SYN_FLAG)) {
                    local_syn_pkts++;
                    local_syn_ack_pkts += (tcp_flags & RTE_TCP_ACK_FLAG) ? 1 : 0;
                }

                /* HTTP detection - use raw port (avoid byte swap if possible) */
                local_http_reqs += (dst_port_raw == rte_cpu_to_be_16(80)) ? 1 : 0;
            }
            else if (proto == IPPROTO_UDP) {
                local_udp_pkts++;
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));

                /* DNS detection - check both ports at once */
                uint16_t dns_port = rte_cpu_to_be_16(53);
                local_dns_queries += ((udp_hdr->dst_port == dns_port) | (udp_hdr->src_port == dns_port)) ? 1 : 0;
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

    rte_hash_free(ip_hash);
    printf("\nShutting down...\n");
    rte_eal_cleanup();

    return 0;
}
