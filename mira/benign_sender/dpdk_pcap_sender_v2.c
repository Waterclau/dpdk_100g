/* SPDX-License-Identifier: BSD-3-Clause
 * DPDK PCAP sender v2.0 - WITH TEMPORAL REPLAY SUPPORT + ADAPTIVE MODE
 *
 * NEW FEATURES:
 * - --pcap-timed: Respect PCAP timestamps (temporal phases)
 * - --jitter X: Add timing jitter (±X%)
 * - --adaptive: High-speed continuous replay with phase-based protocol distribution
 * - --rate-gbps X: Target rate in Gbps (default 12)
 * - --phases <file.json>: Phase definition file
 * - --loop: Loop indefinitely
 * - --duration X: Run for X seconds
 *
 * BACKWARD COMPATIBLE: Without new flags, behaves exactly like v1 (max speed)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <sys/stat.h>
#include <ctype.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_memory.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 8192
#define NUM_MBUFS 262144
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 256
#define MAX_PCAP_PACKETS 10000000

/* Target transmission rate for non-timed mode */
#define TARGET_GBPS 12.0

static volatile uint8_t force_quit = 0;
static uint16_t port_id = 0;
static struct rte_mempool *mbuf_pool = NULL;

/* Statistics */
static uint64_t total_packets_sent = 0;
static uint64_t total_bytes_sent = 0;
static uint64_t start_tsc = 0;

/* Instantaneous statistics */
static uint64_t last_window_packets = 0;
static uint64_t last_window_bytes = 0;
static uint64_t last_window_tsc = 0;

/* NEW: Traffic phase definition for adaptive mode */
#define MAX_PHASES 16

struct traffic_phase {
    uint32_t duration_sec;   // Phase duration in seconds
    float http_pct;          // HTTP percentage (0.0-1.0)
    float dns_pct;           // DNS percentage
    float ssh_pct;           // SSH percentage
    float udp_pct;           // UDP/other percentage
};

/* NEW: Adaptive mode configuration */
struct adaptive_config {
    uint8_t enabled;
    uint8_t loop_mode;                     // Loop indefinitely
    uint32_t duration_sec;                 // Total duration (0 = infinite)
    float target_gbps;                     // Target rate
    float jitter_pct;                      // PPS jitter
    struct traffic_phase phases[MAX_PHASES];
    uint32_t num_phases;
};

static struct adaptive_config adaptive_cfg = {
    .enabled = 0,
    .loop_mode = 0,
    .duration_sec = 0,
    .target_gbps = 12.0f,
    .jitter_pct = 0.0f,
    .num_phases = 0
};

/* NEW: Temporal replay configuration */
struct replay_config {
    uint8_t pcap_timed;       // Enable timestamp-based replay
    uint8_t phase_mode;       // Adaptive phase-based pacing (deprecated, use adaptive_cfg)
    float jitter_pct;         // Jitter percentage (0-100)
    uint64_t speedup_factor;  // Speedup factor (1 = realtime, 10 = 10x faster)
};

static struct replay_config replay_cfg = {
    .pcap_timed = 0,
    .phase_mode = 0,
    .jitter_pct = 0.0f,
    .speedup_factor = 1
};

/* PCAP packets storage - NOW WITH TIMESTAMPS AND PROTOCOL TYPE */
enum packet_protocol {
    PROTO_HTTP = 0,
    PROTO_DNS,
    PROTO_SSH,
    PROTO_UDP_OTHER,
    PROTO_UNKNOWN,
    PROTO_MAX
};

struct packet_data {
    uint8_t data[2048];
    uint16_t len;
    struct timeval timestamp;      /* NEW: Store original PCAP timestamp */
    enum packet_protocol protocol; /* NEW: Protocol classification */
};

static struct packet_data *pcap_packets = NULL;
static uint32_t num_pcap_packets = 0;
static uint32_t current_packet_idx = 0;

/* NEW: Protocol-classified packet pools for adaptive mode */
static uint32_t *http_packets = NULL;   // Indices of HTTP packets
static uint32_t *dns_packets = NULL;    // Indices of DNS packets
static uint32_t *ssh_packets = NULL;    // Indices of SSH packets
static uint32_t *udp_packets = NULL;    // Indices of UDP/other packets
static uint32_t num_http = 0, num_dns = 0, num_ssh = 0, num_udp = 0;

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\n[SIGNAL] Received signal %d (Ctrl+C), initiating graceful shutdown...\n", signum);
        force_quit = 1;
        fflush(stdout);
    }
}

/* NEW: Random jitter generator */
static inline double get_jitter_multiplier(float jitter_pct)
{
    if (jitter_pct <= 0.0f)
        return 1.0;

    // Random value between (1 - jitter) and (1 + jitter)
    double jitter_factor = jitter_pct / 100.0;
    double random_val = (double)rand() / RAND_MAX;  // 0.0 to 1.0
    double jitter = (random_val * 2.0 - 1.0) * jitter_factor;  // -jitter to +jitter

    return 1.0 + jitter;
}

/* NEW: Calculate time difference in microseconds */
static inline uint64_t timeval_diff_us(struct timeval *t1, struct timeval *t2)
{
    int64_t diff_sec = (int64_t)t2->tv_sec - (int64_t)t1->tv_sec;
    int64_t diff_usec = (int64_t)t2->tv_usec - (int64_t)t1->tv_usec;

    int64_t total_us = diff_sec * 1000000LL + diff_usec;

    // Clamp to reasonable values (avoid negative or huge delays)
    if (total_us < 0)
        return 0;
    if (total_us > 10000000)  // Cap at 10 seconds
        return 10000000;

    return (uint64_t)total_us;
}

/* NEW: Classify packet by protocol (simple heuristic) */
static enum packet_protocol classify_packet(const uint8_t *data, uint16_t len)
{
    // Minimum Ethernet header size
    if (len < 14)
        return PROTO_UNKNOWN;

    // Skip Ethernet header (14 bytes)
    const uint8_t *ip_hdr = data + 14;

    // Check if it's IPv4 (EtherType 0x0800)
    uint16_t ethertype = (data[12] << 8) | data[13];
    if (ethertype != 0x0800 || len < 34)
        return PROTO_UNKNOWN;

    // Get IP protocol field (byte 9 of IP header)
    uint8_t ip_proto = ip_hdr[9];

    // Get IP header length
    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    if (len < 14 + ihl + 4)
        return PROTO_UNKNOWN;

    const uint8_t *transport_hdr = ip_hdr + ihl;

    // TCP (protocol 6)
    if (ip_proto == 6) {
        uint16_t src_port = (transport_hdr[0] << 8) | transport_hdr[1];
        uint16_t dst_port = (transport_hdr[2] << 8) | transport_hdr[3];

        if (src_port == 80 || dst_port == 80)
            return PROTO_HTTP;
        if (src_port == 22 || dst_port == 22)
            return PROTO_SSH;

        return PROTO_UNKNOWN;  // Other TCP
    }

    // UDP (protocol 17)
    if (ip_proto == 17) {
        uint16_t src_port = (transport_hdr[0] << 8) | transport_hdr[1];
        uint16_t dst_port = (transport_hdr[2] << 8) | transport_hdr[3];

        if (src_port == 53 || dst_port == 53)
            return PROTO_DNS;

        return PROTO_UDP_OTHER;
    }

    return PROTO_UNKNOWN;
}

/* NEW: Simple JSON parser for phases file (no external deps) */
static int parse_phases_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open phases file: %s\n", filename);
        return -1;
    }

    // Read entire file
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = malloc(fsize + 1);
    if (!content) {
        fclose(f);
        return -1;
    }

    size_t bytes_read = fread(content, 1, fsize, f);
    fclose(f);
    content[fsize] = 0;

    if (bytes_read != (size_t)fsize) {
        printf("Warning: Read %zu bytes, expected %ld\n", bytes_read, fsize);
    }

    // Simple JSON parsing (expects array format)
    // Format: [{"duration": 30, "http": 0.60, "dns": 0.20, "ssh": 0.10, "udp": 0.10}, ...]

    char *ptr = content;
    adaptive_cfg.num_phases = 0;

    // Find opening bracket
    while (*ptr && *ptr != '[') ptr++;
    if (*ptr == '[') ptr++;

    // Parse each phase object
    while (*ptr && adaptive_cfg.num_phases < MAX_PHASES) {
        // Skip whitespace
        while (*ptr && isspace(*ptr)) ptr++;

        if (*ptr == ']' || *ptr == '\0') break;
        if (*ptr == ',') ptr++;

        // Skip to opening brace
        while (*ptr && *ptr != '{') ptr++;
        if (*ptr != '{') break;
        ptr++;

        struct traffic_phase *phase = &adaptive_cfg.phases[adaptive_cfg.num_phases];
        phase->duration_sec = 30;  // Default
        phase->http_pct = 0.0f;
        phase->dns_pct = 0.0f;
        phase->ssh_pct = 0.0f;
        phase->udp_pct = 0.0f;

        // Parse key-value pairs
        while (*ptr && *ptr != '}') {
            while (*ptr && isspace(*ptr)) ptr++;
            if (*ptr == ',') ptr++;
            while (*ptr && isspace(*ptr)) ptr++;

            if (*ptr == '"') {
                ptr++;
                char key[64] = {0};
                int i = 0;
                while (*ptr && *ptr != '"' && i < 63) {
                    key[i++] = *ptr++;
                }
                if (*ptr == '"') ptr++;

                // Skip to colon
                while (*ptr && *ptr != ':') ptr++;
                if (*ptr == ':') ptr++;
                while (*ptr && isspace(*ptr)) ptr++;

                // Read value
                float value = 0.0f;
                if (isdigit(*ptr) || *ptr == '.') {
                    value = strtof(ptr, &ptr);
                }

                // Assign to phase
                if (strcmp(key, "duration") == 0) {
                    phase->duration_sec = (uint32_t)value;
                } else if (strcmp(key, "http") == 0) {
                    phase->http_pct = value;
                } else if (strcmp(key, "dns") == 0) {
                    phase->dns_pct = value;
                } else if (strcmp(key, "ssh") == 0) {
                    phase->ssh_pct = value;
                } else if (strcmp(key, "udp") == 0) {
                    phase->udp_pct = value;
                }
            } else {
                ptr++;
            }
        }

        if (*ptr == '}') ptr++;
        adaptive_cfg.num_phases++;
    }

    free(content);

    printf("\n[ADAPTIVE] Loaded %u phases from %s:\n", adaptive_cfg.num_phases, filename);
    for (uint32_t i = 0; i < adaptive_cfg.num_phases; i++) {
        struct traffic_phase *p = &adaptive_cfg.phases[i];
        printf("  Phase %u: %us - HTTP:%.0f%% DNS:%.0f%% SSH:%.0f%% UDP:%.0f%%\n",
               i+1, p->duration_sec,
               p->http_pct*100, p->dns_pct*100, p->ssh_pct*100, p->udp_pct*100);
    }
    printf("\n");

    return adaptive_cfg.num_phases > 0 ? 0 : -1;
}

/* NEW: Create default phases if no file specified */
static void create_default_phases(void)
{
    // Phase 1: HTTP Peak (33%)
    adaptive_cfg.phases[0].duration_sec = 30;
    adaptive_cfg.phases[0].http_pct = 0.60f;
    adaptive_cfg.phases[0].dns_pct = 0.20f;
    adaptive_cfg.phases[0].ssh_pct = 0.10f;
    adaptive_cfg.phases[0].udp_pct = 0.10f;

    // Phase 2: DNS Burst (20%)
    adaptive_cfg.phases[1].duration_sec = 15;
    adaptive_cfg.phases[1].http_pct = 0.30f;
    adaptive_cfg.phases[1].dns_pct = 0.50f;
    adaptive_cfg.phases[1].ssh_pct = 0.10f;
    adaptive_cfg.phases[1].udp_pct = 0.10f;

    // Phase 3: SSH Stable (27%)
    adaptive_cfg.phases[2].duration_sec = 45;
    adaptive_cfg.phases[2].http_pct = 0.50f;
    adaptive_cfg.phases[2].dns_pct = 0.15f;
    adaptive_cfg.phases[2].ssh_pct = 0.25f;
    adaptive_cfg.phases[2].udp_pct = 0.10f;

    adaptive_cfg.num_phases = 3;

    printf("\n[ADAPTIVE] Using default phases (no file specified):\n");
    for (uint32_t i = 0; i < adaptive_cfg.num_phases; i++) {
        struct traffic_phase *p = &adaptive_cfg.phases[i];
        printf("  Phase %u: %us - HTTP:%.0f%% DNS:%.0f%% SSH:%.0f%% UDP:%.0f%%\n",
               i+1, p->duration_sec,
               p->http_pct*100, p->dns_pct*100, p->ssh_pct*100, p->udp_pct*100);
    }
    printf("\n");
}

/* Port initialization */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool __rte_unused)
{
    struct rte_eth_conf port_conf = {
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    };

    const uint16_t rx_rings = 0, tx_rings = 1;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u\n", port);
        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, NULL, &nb_txd);
    if (retval != 0)
        return retval;

    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
            rte_eth_dev_socket_id(port), NULL);
    if (retval < 0)
        return retval;

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    printf("Port %u initialized successfully\n", port);
    return 0;
}

/* Load PCAP file - NOW STORES TIMESTAMPS */
static int load_pcap(const char *filename)
{
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *data;
    int ret;

    printf("Loading PCAP file: %s\n", filename);

    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        printf("Error opening PCAP: %s\n", errbuf);
        return -1;
    }

    pcap_packets = malloc(MAX_PCAP_PACKETS * sizeof(struct packet_data));
    if (pcap_packets == NULL) {
        printf("Failed to allocate memory for PCAP packets\n");
        pcap_close(pcap);
        return -1;
    }

    num_pcap_packets = 0;
    while ((ret = pcap_next_ex(pcap, &header, &data)) >= 0) {
        if (ret == 0) continue;

        if (num_pcap_packets >= MAX_PCAP_PACKETS) {
            printf("Warning: PCAP has more than %d packets, truncating\n", MAX_PCAP_PACKETS);
            break;
        }

        if (header->caplen > sizeof(pcap_packets[0].data)) {
            printf("Warning: packet %u too large (%u bytes), skipping\n",
                   num_pcap_packets, header->caplen);
            continue;
        }

        memcpy(pcap_packets[num_pcap_packets].data, data, header->caplen);
        pcap_packets[num_pcap_packets].len = header->caplen;
        pcap_packets[num_pcap_packets].timestamp = header->ts;  /* NEW: Store timestamp */

        /* NEW: Classify packet for adaptive mode */
        pcap_packets[num_pcap_packets].protocol = classify_packet(data, header->caplen);

        num_pcap_packets++;

        if (num_pcap_packets % 1000000 == 0)
            printf("Loaded %u packets...\n", num_pcap_packets);
    }

    pcap_close(pcap);
    printf("Loaded %u packets from PCAP\n", num_pcap_packets);

    /* NEW: Build protocol-classified indexes for adaptive mode */
    if (adaptive_cfg.enabled) {
        printf("Classifying packets by protocol for adaptive mode...\n");

        // Allocate index arrays
        http_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        dns_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        ssh_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        udp_packets = malloc(num_pcap_packets * sizeof(uint32_t));

        if (!http_packets || !dns_packets || !ssh_packets || !udp_packets) {
            printf("Failed to allocate protocol classification arrays\n");
            return -1;
        }

        // Classify all packets
        for (uint32_t i = 0; i < num_pcap_packets; i++) {
            switch (pcap_packets[i].protocol) {
                case PROTO_HTTP:
                    http_packets[num_http++] = i;
                    break;
                case PROTO_DNS:
                    dns_packets[num_dns++] = i;
                    break;
                case PROTO_SSH:
                    ssh_packets[num_ssh++] = i;
                    break;
                case PROTO_UDP_OTHER:
                    udp_packets[num_udp++] = i;
                    break;
                default:
                    // Add unknown packets to UDP pool
                    udp_packets[num_udp++] = i;
                    break;
            }
        }

        printf("\n[PROTOCOL CLASSIFICATION]\n");
        printf("  HTTP:  %u packets (%.1f%%)\n", num_http, num_http*100.0f/num_pcap_packets);
        printf("  DNS:   %u packets (%.1f%%)\n", num_dns, num_dns*100.0f/num_pcap_packets);
        printf("  SSH:   %u packets (%.1f%%)\n", num_ssh, num_ssh*100.0f/num_pcap_packets);
        printf("  UDP:   %u packets (%.1f%%)\n", num_udp, num_udp*100.0f/num_pcap_packets);
        printf("\n");

        // Check if we have packets for all categories
        if (num_http == 0) printf("Warning: No HTTP packets found!\n");
        if (num_dns == 0) printf("Warning: No DNS packets found!\n");
        if (num_ssh == 0) printf("Warning: No SSH packets found!\n");
        if (num_udp == 0) printf("Warning: No UDP packets found!\n");
    }

    /* NEW: Analyze timestamp distribution if timed mode */
    if (replay_cfg.pcap_timed && num_pcap_packets > 1) {
        uint64_t total_duration_us = timeval_diff_us(
            &pcap_packets[0].timestamp,
            &pcap_packets[num_pcap_packets - 1].timestamp
        );

        printf("\n[TIMED MODE] PCAP temporal analysis:\n");
        printf("  First timestamp: %ld.%06ld\n",
               pcap_packets[0].timestamp.tv_sec,
               pcap_packets[0].timestamp.tv_usec);
        printf("  Last timestamp:  %ld.%06ld\n",
               pcap_packets[num_pcap_packets - 1].timestamp.tv_sec,
               pcap_packets[num_pcap_packets - 1].timestamp.tv_usec);
        printf("  Total duration:  %.2f seconds\n", total_duration_us / 1e6);
        printf("  Average PPS:     %.0f packets/sec\n",
               num_pcap_packets / (total_duration_us / 1e6));

        if (replay_cfg.speedup_factor > 1) {
            printf("  Speedup factor:  %lux\n", replay_cfg.speedup_factor);
            printf("  Replay duration: %.2f seconds (estimated)\n",
                   (total_duration_us / 1e6) / replay_cfg.speedup_factor);
        }

        if (replay_cfg.jitter_pct > 0) {
            printf("  Jitter:          ±%.1f%%\n", replay_cfg.jitter_pct);
        }
        printf("\n");
    }

    return 0;
}

/* NEW: Timed sending loop (respects timestamps) */
static void send_loop_timed(void)
{
    uint16_t nb_tx;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    struct timeval prev_timestamp = {0, 0};
    uint8_t first_packet = 1;

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         DPDK PCAP SENDER v2.0 - TIMED REPLAY MODE        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");
    printf("Replaying PCAP with timestamp-based pacing...\n");
    printf("Jitter: ±%.1f%%  |  Speedup: %lux\n",
           replay_cfg.jitter_pct, replay_cfg.speedup_factor);
    printf("Press Ctrl+C to stop\n\n");

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;

    srand(time(NULL));  // Initialize random for jitter

    while (!force_quit && current_packet_idx < num_pcap_packets) {
        struct packet_data *pkt_data = &pcap_packets[current_packet_idx];

        /* Calculate delay based on timestamp difference */
        if (!first_packet) {
            uint64_t delta_us = timeval_diff_us(&prev_timestamp, &pkt_data->timestamp);

            /* Apply speedup factor */
            delta_us = delta_us / replay_cfg.speedup_factor;

            /* Apply jitter if configured */
            if (replay_cfg.jitter_pct > 0) {
                double jitter_mult = get_jitter_multiplier(replay_cfg.jitter_pct);
                delta_us = (uint64_t)(delta_us * jitter_mult);
            }

            /* Wait for the calculated time */
            if (delta_us > 0 && delta_us < 10000000) {  // Sanity check: < 10s
                rte_delay_us_block(delta_us);
            }
        }

        prev_timestamp = pkt_data->timestamp;
        first_packet = 0;

        /* Allocate mbuf */
        struct rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
        if (pkt == NULL) {
            rte_delay_us_block(100);
            continue;
        }

        /* Copy packet data */
        char *pkt_buf = rte_pktmbuf_mtod(pkt, char *);
        rte_memcpy(pkt_buf, pkt_data->data, pkt_data->len);
        pkt->data_len = pkt_data->len;
        pkt->pkt_len = pkt_data->len;

        /* Send single packet */
        nb_tx = rte_eth_tx_burst(port_id, 0, &pkt, 1);

        if (nb_tx == 1) {
            total_packets_sent++;
            total_bytes_sent += pkt->pkt_len;
        } else {
            rte_pktmbuf_free(pkt);
        }

        current_packet_idx++;

        /* Print statistics every 5 seconds */
        uint64_t cur_tsc = rte_rdtsc();
        if (cur_tsc - last_stats_tsc >= hz * 5) {
            double elapsed = (double)(cur_tsc - start_tsc) / hz;
            double gbps_cumulative = (total_bytes_sent * 8.0) / (elapsed * 1e9);
            double mpps_cumulative = (total_packets_sent / elapsed) / 1e6;

            double progress = (double)current_packet_idx / num_pcap_packets * 100.0;

            printf("[%.1fs] Sent: %lu/%u pkts (%.1f%%) | %.2f Mpps | %.2f Gbps\n",
                   elapsed, total_packets_sent, num_pcap_packets, progress,
                   mpps_cumulative, gbps_cumulative);

            last_stats_tsc = cur_tsc;
        }
    }

    printf("\n=== TIMED REPLAY COMPLETE ===\n");
    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total packets sent:  %lu\n", total_packets_sent);
    printf("Total bytes sent:    %lu\n", total_bytes_sent);
    printf("Duration:            %.2f seconds\n", elapsed);
    printf("Average throughput:  %.2f Gbps\n", gbps);
    printf("Average pps:         %.2f Mpps\n", mpps);
}

/* ORIGINAL: Fast sending loop with rate limiting (UNCHANGED) */
static void send_loop_fast(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    /* Rate limiting variables */
    const uint64_t target_bytes_per_sec = (uint64_t)(TARGET_GBPS * 1e9 / 8.0);
    uint64_t bytes_sent_in_window = 0;
    uint64_t window_start_tsc = 0;

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      DPDK PCAP SENDER - %.1f Gbps baseline transmission     ║\n", TARGET_GBPS);
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");
    printf("Starting packet transmission at %.1f Gbps...\n", TARGET_GBPS);
    printf("Press Ctrl+C to stop\n\n");

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    window_start_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;

    while (!force_quit) {
        /* Allocate fresh mbufs */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE) != 0) {
            rte_delay_us_block(100);
            continue;
        }

        /* Fill mbufs with PCAP data */
        for (i = 0; i < BURST_SIZE; i++) {
            struct packet_data *pkt_data = &pcap_packets[current_packet_idx];

            char *pkt_buf = rte_pktmbuf_mtod(pkts[i], char *);
            rte_memcpy(pkt_buf, pkt_data->data, pkt_data->len);
            pkts[i]->data_len = pkt_data->len;
            pkts[i]->pkt_len = pkt_data->len;

            current_packet_idx++;
            if (current_packet_idx >= num_pcap_packets)
                current_packet_idx = 0;
        }

        /* Send burst */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts, BURST_SIZE);
        total_packets_sent += nb_tx;

        /* Track bytes for rate limiting */
        for (i = 0; i < nb_tx; i++) {
            bytes_sent_in_window += pkts[i]->pkt_len;
            total_bytes_sent += pkts[i]->pkt_len;
        }

        /* Free unsent packets */
        if (unlikely(nb_tx < BURST_SIZE)) {
            for (i = nb_tx; i < BURST_SIZE; i++)
                rte_pktmbuf_free(pkts[i]);
        }

        /* Rate limiting */
        uint64_t cur_tsc = rte_rdtsc();
        double elapsed_sec = (double)(cur_tsc - window_start_tsc) / hz;

        if (elapsed_sec >= 1.0) {
            /* Reset window every second */
            bytes_sent_in_window = 0;
            window_start_tsc = cur_tsc;
        } else if (bytes_sent_in_window > (uint64_t)(target_bytes_per_sec * elapsed_sec)) {
            /* Too fast, calculate sleep time */
            double bytes_expected = target_bytes_per_sec * elapsed_sec;
            double bytes_over = bytes_sent_in_window - bytes_expected;
            uint64_t sleep_ns = (uint64_t)((bytes_over * 8.0 * 1e9) / (TARGET_GBPS * 1e9));

            if (sleep_ns > 0 && sleep_ns < 100000) {
                rte_delay_us_block(sleep_ns / 1000);
            }
        }

        /* Print statistics every 5 seconds */
        if (cur_tsc - last_stats_tsc >= hz * 5) {
            /* Cumulative statistics (from start) */
            double elapsed = (double)(cur_tsc - start_tsc) / hz;
            double gbps_cumulative = (total_bytes_sent * 8.0) / (elapsed * 1e9);
            double mpps_cumulative = (total_packets_sent / elapsed) / 1e6;

            /* Instantaneous statistics (last 5 seconds) */
            double window_duration = (double)(cur_tsc - last_window_tsc) / hz;
            uint64_t window_packets = total_packets_sent - last_window_packets;
            uint64_t window_bytes = total_bytes_sent - last_window_bytes;
            double gbps_instant = (window_bytes * 8.0) / (window_duration * 1e9);

            printf("[%.1fs] Sent: %lu pkts (%.2f Mpps) | Cumulative: %.2f Gbps | Instant: %.2f Gbps | %lu bytes\n",
                   elapsed, total_packets_sent, mpps_cumulative, gbps_cumulative, gbps_instant, total_bytes_sent);

            /* Update window markers */
            last_window_packets = total_packets_sent;
            last_window_bytes = total_bytes_sent;
            last_window_tsc = cur_tsc;
            last_stats_tsc = cur_tsc;
        }
    }

    printf("\n=== FINAL STATISTICS ===\n");
    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total packets sent:  %lu\n", total_packets_sent);
    printf("Total bytes sent:    %lu\n", total_bytes_sent);
    printf("Duration:            %.2f seconds\n", elapsed);
    printf("Average throughput:  %.2f Gbps\n", gbps);
    printf("Average pps:         %.2f Mpps\n", mpps);
}

/* NEW: Adaptive high-speed replay with phase-based protocol distribution */
static void send_loop_adaptive(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         DPDK PCAP SENDER v2.0 - ADAPTIVE REPLAY MODE            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target rate: %.1f Gbps  |  Jitter: ±%.1f%%  |  Loop: %s\n",
           adaptive_cfg.target_gbps, adaptive_cfg.jitter_pct,
           adaptive_cfg.loop_mode ? "YES" : "NO");
    printf("Duration: %s\n", adaptive_cfg.duration_sec ?
           "unlimited" : "limited");
    printf("Phases: %u loaded\n", adaptive_cfg.num_phases);
    printf("Press Ctrl+C to stop\n\n");

    if (num_http == 0 && num_dns == 0 && num_ssh == 0 && num_udp == 0) {
        printf("ERROR: No classified packets available!\n");
        return;
    }

    /* Rate limiting variables */
    const uint64_t target_bytes_per_sec = (uint64_t)(adaptive_cfg.target_gbps * 1e9 / 8.0);
    uint64_t bytes_sent_in_window = 0;
    uint64_t window_start_tsc = 0;

    /* Phase tracking */
    uint32_t current_phase = 0;
    uint64_t phase_start_tsc = 0;
    uint64_t phase_duration_tsc = 0;

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    window_start_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;
    phase_start_tsc = start_tsc;

    srand(time(NULL));

    // Initialize first phase
    if (adaptive_cfg.num_phases > 0) {
        phase_duration_tsc = adaptive_cfg.phases[0].duration_sec * hz;
        printf("[PHASE 1/%u] Starting - %us - HTTP:%.0f%% DNS:%.0f%% SSH:%.0f%% UDP:%.0f%%\n",
               adaptive_cfg.num_phases,
               adaptive_cfg.phases[0].duration_sec,
               adaptive_cfg.phases[0].http_pct*100,
               adaptive_cfg.phases[0].dns_pct*100,
               adaptive_cfg.phases[0].ssh_pct*100,
               adaptive_cfg.phases[0].udp_pct*100);
    }

    uint64_t total_start_tsc = start_tsc;
    uint64_t total_duration_tsc = adaptive_cfg.duration_sec * hz;

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        // Check total duration limit
        if (adaptive_cfg.duration_sec > 0 &&
            (cur_tsc - total_start_tsc) >= total_duration_tsc) {
            printf("\n[DURATION LIMIT] Reached %u seconds, stopping.\n",
                   adaptive_cfg.duration_sec);
            break;
        }

        // Check if we need to advance to next phase
        if (adaptive_cfg.num_phases > 0 &&
            (cur_tsc - phase_start_tsc) >= phase_duration_tsc) {
            current_phase = (current_phase + 1) % adaptive_cfg.num_phases;
            phase_start_tsc = cur_tsc;
            phase_duration_tsc = adaptive_cfg.phases[current_phase].duration_sec * hz;

            printf("\n[PHASE %u/%u] Switching - %us - HTTP:%.0f%% DNS:%.0f%% SSH:%.0f%% UDP:%.0f%%\n",
                   current_phase + 1, adaptive_cfg.num_phases,
                   adaptive_cfg.phases[current_phase].duration_sec,
                   adaptive_cfg.phases[current_phase].http_pct*100,
                   adaptive_cfg.phases[current_phase].dns_pct*100,
                   adaptive_cfg.phases[current_phase].ssh_pct*100,
                   adaptive_cfg.phases[current_phase].udp_pct*100);
        }

        /* Allocate fresh mbufs */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE) != 0) {
            rte_delay_us_block(100);
            continue;
        }

        /* Fill mbufs based on current phase distribution */
        struct traffic_phase *phase = &adaptive_cfg.phases[current_phase];

        for (i = 0; i < BURST_SIZE; i++) {
            uint32_t pkt_idx = 0;
            float r = (float)rand() / RAND_MAX;

            // Select protocol based on phase percentages
            if (r < phase->http_pct && num_http > 0) {
                // HTTP packet
                uint32_t idx = rand() % num_http;
                pkt_idx = http_packets[idx];
            } else if (r < (phase->http_pct + phase->dns_pct) && num_dns > 0) {
                // DNS packet
                uint32_t idx = rand() % num_dns;
                pkt_idx = dns_packets[idx];
            } else if (r < (phase->http_pct + phase->dns_pct + phase->ssh_pct) && num_ssh > 0) {
                // SSH packet
                uint32_t idx = rand() % num_ssh;
                pkt_idx = ssh_packets[idx];
            } else if (num_udp > 0) {
                // UDP packet
                uint32_t idx = rand() % num_udp;
                pkt_idx = udp_packets[idx];
            } else {
                // Fallback to any random packet
                pkt_idx = rand() % num_pcap_packets;
            }

            struct packet_data *pkt_data = &pcap_packets[pkt_idx];

            char *pkt_buf = rte_pktmbuf_mtod(pkts[i], char *);
            rte_memcpy(pkt_buf, pkt_data->data, pkt_data->len);
            pkts[i]->data_len = pkt_data->len;
            pkts[i]->pkt_len = pkt_data->len;
        }

        /* Send burst */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts, BURST_SIZE);
        total_packets_sent += nb_tx;

        /* Track bytes for rate limiting */
        for (i = 0; i < nb_tx; i++) {
            bytes_sent_in_window += pkts[i]->pkt_len;
            total_bytes_sent += pkts[i]->pkt_len;
        }

        /* Free unsent packets */
        if (unlikely(nb_tx < BURST_SIZE)) {
            for (i = nb_tx; i < BURST_SIZE; i++)
                rte_pktmbuf_free(pkts[i]);
        }

        /* Rate limiting with jitter */
        cur_tsc = rte_rdtsc();
        double elapsed_sec = (double)(cur_tsc - window_start_tsc) / hz;

        if (elapsed_sec >= 1.0) {
            /* Reset window every second */
            bytes_sent_in_window = 0;
            window_start_tsc = cur_tsc;
        } else if (bytes_sent_in_window > (uint64_t)(target_bytes_per_sec * elapsed_sec)) {
            /* Too fast, calculate sleep time with jitter */
            double bytes_expected = target_bytes_per_sec * elapsed_sec;
            double bytes_over = bytes_sent_in_window - bytes_expected;
            uint64_t sleep_ns = (uint64_t)((bytes_over * 8.0 * 1e9) / (adaptive_cfg.target_gbps * 1e9));

            // Apply jitter to sleep time
            if (adaptive_cfg.jitter_pct > 0) {
                double jitter_mult = get_jitter_multiplier(adaptive_cfg.jitter_pct);
                sleep_ns = (uint64_t)(sleep_ns * jitter_mult);
            }

            if (sleep_ns > 0 && sleep_ns < 100000) {
                rte_delay_us_block(sleep_ns / 1000);
            }
        }

        /* Print statistics every 5 seconds */
        if (cur_tsc - last_stats_tsc >= hz * 5) {
            double elapsed = (double)(cur_tsc - start_tsc) / hz;
            double gbps_cumulative = (total_bytes_sent * 8.0) / (elapsed * 1e9);
            double mpps_cumulative = (total_packets_sent / elapsed) / 1e6;

            double window_duration = (double)(cur_tsc - last_window_tsc) / hz;
            uint64_t window_packets = total_packets_sent - last_window_packets;
            uint64_t window_bytes = total_bytes_sent - last_window_bytes;
            double gbps_instant = (window_bytes * 8.0) / (window_duration * 1e9);

            printf("[%.1fs] Phase %u/%u | %lu pkts (%.2f Mpps) | Avg: %.2f Gbps | Inst: %.2f Gbps\n",
                   elapsed, current_phase + 1, adaptive_cfg.num_phases,
                   total_packets_sent, mpps_cumulative, gbps_cumulative, gbps_instant);

            last_window_packets = total_packets_sent;
            last_window_bytes = total_bytes_sent;
            last_window_tsc = cur_tsc;
            last_stats_tsc = cur_tsc;
        }
    }

    printf("\n=== ADAPTIVE REPLAY COMPLETE ===\n");
    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total packets sent:  %lu\n", total_packets_sent);
    printf("Total bytes sent:    %lu\n", total_bytes_sent);
    printf("Duration:            %.2f seconds\n", elapsed);
    printf("Average throughput:  %.2f Gbps\n", gbps);
    printf("Average pps:         %.2f Mpps\n", mpps);
    printf("Phases completed:    %u cycles\n", current_phase / adaptive_cfg.num_phases);
}

/* NEW: Print usage with new options */
static void print_usage(const char *prgname)
{
    printf("\nUsage: %s [EAL options] -- <pcap_file> [OPTIONS]\n\n", prgname);
    printf("MODES:\n");
    printf("  --pcap-timed              Replay PCAP respecting timestamps (temporal phases)\n");
    printf("  --adaptive                Adaptive high-speed replay with phase-based protocol mix\n");
    printf("\n");
    printf("TIMED MODE OPTIONS:\n");
    printf("  --jitter <percent>        Add timing jitter (±X%%, e.g., 10 for ±10%%)\n");
    printf("  --speedup <factor>        Speedup factor (1=realtime, 10=10x faster, default: 1)\n");
    printf("\n");
    printf("ADAPTIVE MODE OPTIONS:\n");
    printf("  --rate-gbps <rate>        Target rate in Gbps (default: 12)\n");
    printf("  --jitter <percent>        PPS variation (±X%%)\n");
    printf("  --phases <file.json>      Phase definition file (optional, uses defaults if not provided)\n");
    printf("  --loop                    Loop indefinitely through phases\n");
    printf("  --duration <seconds>      Run for specified duration (0=infinite, default: 0)\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  # Original mode (max speed, ~12 Gbps):\n");
    printf("  %s -l 0-7 -- traffic.pcap\n\n", prgname);
    printf("  # Timed replay with jitter (realistic):\n");
    printf("  %s -l 0-7 -- benign_10M_v2.pcap --pcap-timed --jitter 15\n\n", prgname);
    printf("  # Adaptive mode with default phases (continuous 12Gbps with phase rotation):\n");
    printf("  %s -l 0-7 -- benign_10M_v2.pcap --adaptive --loop\n\n", prgname);
    printf("  # Adaptive mode with custom phases and 10Gbps:\n");
    printf("  %s -l 0-7 -- benign.pcap --adaptive --rate-gbps 10 --phases custom.json --duration 300\n\n", prgname);
    printf("\nPHASE FILE FORMAT (JSON):\n");
    printf("  [{\"duration\": 30, \"http\": 0.60, \"dns\": 0.20, \"ssh\": 0.10, \"udp\": 0.10},\n");
    printf("   {\"duration\": 15, \"http\": 0.30, \"dns\": 0.50, \"ssh\": 0.10, \"udp\": 0.10}]\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int ret;
    char *pcap_file = NULL;
    int opt;
    int option_index;
    char *phases_file = NULL;
    float jitter;  // Declare here to avoid error in switch

    /* NEW: Long options for temporal replay and adaptive mode */
    static struct option long_options[] = {
        {"pcap-timed", no_argument, NULL, 't'},
        {"adaptive", no_argument, NULL, 'a'},
        {"jitter", required_argument, NULL, 'j'},
        {"phase-mode", no_argument, NULL, 'p'},
        {"speedup", required_argument, NULL, 's'},
        {"rate-gbps", required_argument, NULL, 'r'},
        {"phases", required_argument, NULL, 'f'},
        {"loop", no_argument, NULL, 'l'},
        {"duration", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }

    pcap_file = argv[1];

    /* Parse application arguments (after --) */
    optind = 2;  // Start after pcap_file
    while ((opt = getopt_long(argc, argv, "taj:ps:r:f:ld:h", long_options, &option_index)) != -1) {
        switch (opt) {
        case 't':
            replay_cfg.pcap_timed = 1;
            printf("[CONFIG] Timed replay enabled\n");
            break;
        case 'a':
            adaptive_cfg.enabled = 1;
            printf("[CONFIG] Adaptive mode enabled\n");
            break;
        case 'j':
            jitter = atof(optarg);
            if (jitter < 0 || jitter > 100) {
                printf("Error: Jitter must be between 0 and 100\n");
                return -1;
            }
            // Apply to both configs (whichever mode is active will use it)
            replay_cfg.jitter_pct = jitter;
            adaptive_cfg.jitter_pct = jitter;
            printf("[CONFIG] Jitter: ±%.1f%%\n", jitter);
            break;
        case 'p':
            replay_cfg.phase_mode = 1;
            printf("[CONFIG] Phase mode enabled (deprecated, use --adaptive)\n");
            break;
        case 's':
            replay_cfg.speedup_factor = atol(optarg);
            if (replay_cfg.speedup_factor < 1 || replay_cfg.speedup_factor > 1000) {
                printf("Error: Speedup factor must be between 1 and 1000\n");
                return -1;
            }
            printf("[CONFIG] Speedup factor: %lux\n", replay_cfg.speedup_factor);
            break;
        case 'r':
            adaptive_cfg.target_gbps = atof(optarg);
            if (adaptive_cfg.target_gbps <= 0 || adaptive_cfg.target_gbps > 100) {
                printf("Error: Rate must be between 0 and 100 Gbps\n");
                return -1;
            }
            printf("[CONFIG] Target rate: %.1f Gbps\n", adaptive_cfg.target_gbps);
            break;
        case 'f':
            phases_file = optarg;
            printf("[CONFIG] Phases file: %s\n", phases_file);
            break;
        case 'l':
            adaptive_cfg.loop_mode = 1;
            printf("[CONFIG] Loop mode enabled\n");
            break;
        case 'd':
            adaptive_cfg.duration_sec = atoi(optarg);
            printf("[CONFIG] Duration: %u seconds\n", adaptive_cfg.duration_sec);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    /* Load or create phases for adaptive mode */
    if (adaptive_cfg.enabled) {
        if (phases_file) {
            if (parse_phases_file(phases_file) != 0) {
                printf("Error: Failed to parse phases file, using defaults\n");
                create_default_phases();
            }
        } else {
            create_default_phases();
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", port_id);

    if (load_pcap(pcap_file) != 0)
        rte_exit(EXIT_FAILURE, "Failed to load PCAP file\n");

    /* NEW: Choose sending loop based on configuration */
    if (adaptive_cfg.enabled) {
        /* NEW: Adaptive mode with phase-based protocol distribution */
        send_loop_adaptive();
    } else if (replay_cfg.pcap_timed || replay_cfg.phase_mode) {
        /* Timed mode with timestamp-based pacing */
        send_loop_timed();
    } else {
        /* ORIGINAL BEHAVIOR: Fast mode (~12 Gbps) */
        send_loop_fast();
    }

    /* Cleanup */
    printf("Stopping port %u...\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (pcap_packets) {
        printf("Freeing PCAP data...\n");
        free(pcap_packets);
    }

    /* NEW: Cleanup protocol classification arrays */
    if (http_packets) free(http_packets);
    if (dns_packets) free(dns_packets);
    if (ssh_packets) free(ssh_packets);
    if (udp_packets) free(udp_packets);

    printf("Cleanup complete.\n");
    printf("Sender stopped.\n");
    return 0;
}
