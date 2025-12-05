/* SPDX-License-Identifier: BSD-3-Clause
 * DPDK PCAP sender v2.0 - WITH TEMPORAL REPLAY SUPPORT
 *
 * NEW FEATURES:
 * - --pcap-timed: Respect PCAP timestamps (temporal phases)
 * - --jitter X: Add timing jitter (±X%)
 * - --phase-mode: Adaptive pacing for phase-based traffic
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

/* NEW: Temporal replay configuration */
struct replay_config {
    uint8_t pcap_timed;       // Enable timestamp-based replay
    uint8_t phase_mode;       // Adaptive phase-based pacing
    float jitter_pct;         // Jitter percentage (0-100)
    uint64_t speedup_factor;  // Speedup factor (1 = realtime, 10 = 10x faster)
};

static struct replay_config replay_cfg = {
    .pcap_timed = 0,
    .phase_mode = 0,
    .jitter_pct = 0.0f,
    .speedup_factor = 1
};

/* PCAP packets storage - NOW WITH TIMESTAMPS */
struct packet_data {
    uint8_t data[2048];
    uint16_t len;
    struct timeval timestamp;  /* NEW: Store original PCAP timestamp */
};

static struct packet_data *pcap_packets = NULL;
static uint32_t num_pcap_packets = 0;
static uint32_t current_packet_idx = 0;

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

/* Port initialization */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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
        num_pcap_packets++;

        if (num_pcap_packets % 1000000 == 0)
            printf("Loaded %u packets...\n", num_pcap_packets);
    }

    pcap_close(pcap);
    printf("Loaded %u packets from PCAP\n", num_pcap_packets);

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
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
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
            double mpps_instant = (window_packets / window_duration) / 1e6;

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

/* NEW: Print usage with new options */
static void print_usage(const char *prgname)
{
    printf("\nUsage: %s [EAL options] -- <pcap_file> [OPTIONS]\n\n", prgname);
    printf("OPTIONS:\n");
    printf("  --pcap-timed              Replay PCAP respecting timestamps (temporal phases)\n");
    printf("  --jitter <percent>        Add timing jitter (±X%%, e.g., 10 for ±10%%)\n");
    printf("  --phase-mode              Enable adaptive phase-based pacing\n");
    printf("  --speedup <factor>        Speedup factor (1=realtime, 10=10x faster, default: 1)\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  # Original mode (max speed):\n");
    printf("  %s -l 0-7 -- traffic.pcap\n\n", prgname);
    printf("  # Timed replay with jitter (realistic):\n");
    printf("  %s -l 0-7 -- benign_10M_v2.pcap --pcap-timed --jitter 15\n\n", prgname);
    printf("  # Timed replay 10x faster:\n");
    printf("  %s -l 0-7 -- benign_10M_v2.pcap --pcap-timed --speedup 10\n\n", prgname);
}

int main(int argc, char *argv[])
{
    int ret;
    char *pcap_file = NULL;
    int opt;
    int option_index;

    /* NEW: Long options for temporal replay */
    static struct option long_options[] = {
        {"pcap-timed", no_argument, NULL, 't'},
        {"jitter", required_argument, NULL, 'j'},
        {"phase-mode", no_argument, NULL, 'p'},
        {"speedup", required_argument, NULL, 's'},
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
    while ((opt = getopt_long(argc, argv, "tj:ps:h", long_options, &option_index)) != -1) {
        switch (opt) {
        case 't':
            replay_cfg.pcap_timed = 1;
            printf("[CONFIG] Timed replay enabled\n");
            break;
        case 'j':
            replay_cfg.jitter_pct = atof(optarg);
            if (replay_cfg.jitter_pct < 0 || replay_cfg.jitter_pct > 100) {
                printf("Error: Jitter must be between 0 and 100\n");
                return -1;
            }
            printf("[CONFIG] Jitter: ±%.1f%%\n", replay_cfg.jitter_pct);
            break;
        case 'p':
            replay_cfg.phase_mode = 1;
            printf("[CONFIG] Phase mode enabled\n");
            break;
        case 's':
            replay_cfg.speedup_factor = atol(optarg);
            if (replay_cfg.speedup_factor < 1 || replay_cfg.speedup_factor > 1000) {
                printf("Error: Speedup factor must be between 1 and 1000\n");
                return -1;
            }
            printf("[CONFIG] Speedup factor: %lux\n", replay_cfg.speedup_factor);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return -1;
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
    if (replay_cfg.pcap_timed || replay_cfg.phase_mode) {
        send_loop_timed();
    } else {
        /* ORIGINAL BEHAVIOR: Fast mode */
        send_loop_fast();
    }

    /* Cleanup */
    printf("Stopping port %u...\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (pcap_packets) {
        printf("Freeing PCAP data...\n");
        free(pcap_packets);
        printf("Cleanup complete.\n");
    }

    printf("Sender stopped.\n");
    return 0;
}
