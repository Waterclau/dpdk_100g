/* SPDX-License-Identifier: BSD-3-Clause
 * DPDK PCAP sender - SIMPLE VERSION (no pre-load mbufs)
 * Based on working old/dpdk_pcap_sender.c
 * Optimized for 7 Gbps with rate limiting
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_memory.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 8192
#define NUM_MBUFS 262144
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 256//512
#define MAX_PCAP_PACKETS 10000000

/* Target transmission rate: 17 Gbps (to achieve ~7 Gbps real at detector) */
#define TARGET_GBPS 12.0//17

static volatile uint8_t force_quit = 0;
static uint16_t port_id = 0;
static struct rte_mempool *mbuf_pool = NULL;

/* Statistics */
static uint64_t total_packets_sent = 0;
static uint64_t total_bytes_sent = 0;
static uint64_t start_tsc = 0;

/* Instantaneous statistics (for 5-second window) */
static uint64_t last_window_packets = 0;
static uint64_t last_window_bytes = 0;
static uint64_t last_window_tsc = 0;

/* PCAP packets storage - SIMPLE STRUCT (not mbufs) */
struct packet_data {
    uint8_t data[2048];
    uint16_t len;
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

/* Load PCAP file into simple struct array */
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
        num_pcap_packets++;

        if (num_pcap_packets % 1000000 == 0)
            printf("Loaded %u packets...\n", num_pcap_packets);
    }

    pcap_close(pcap);
    printf("Loaded %u packets from PCAP\n", num_pcap_packets);
    return 0;
}

/* Main sending loop with rate limiting */
static void send_loop(void)
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

int main(int argc, char *argv[])
{
    int ret;
    char *pcap_file = NULL;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    if (argc < 2) {
        printf("Usage: %s [EAL options] -- <pcap_file>\n", argv[0]);
        return -1;
    }

    pcap_file = argv[1];

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

    send_loop();

    /* Cleanup - INSTANTANEOUS */
    printf("Stopping port %u...\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (pcap_packets) {
        printf("Freeing PCAP data...\n");
        free(pcap_packets);  /* Single free - instant! */
        printf("Cleanup complete.\n");
    }

    printf("Sender stopped.\n");
    return 0;
}
