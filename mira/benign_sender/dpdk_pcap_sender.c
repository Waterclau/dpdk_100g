/* SPDX-License-Identifier: BSD-3-Clause
 * Simple DPDK PCAP replayer for line-rate transmission
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
#define TX_RING_SIZE 4096
#define NUM_MBUFS 262144
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 512
#define MAX_PCAP_PACKETS 10000000

static volatile uint8_t force_quit = 0;
static uint16_t port_id = 0;
static struct rte_mempool *mbuf_pool = NULL;

/* Statistics */
static uint64_t total_packets_sent = 0;
static uint64_t total_bytes_sent = 0;
static uint64_t start_tsc = 0;

/* PCAP packets storage */
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
        printf("\n\nSignal %d received, stopping...\n", signum);
        force_quit = 1;
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

    /* Adjust TX descriptor count - use newer API */
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, NULL, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate TX queue */
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
            rte_eth_dev_socket_id(port), NULL);
    if (retval < 0)
        return retval;

    /* Start the Ethernet port */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    printf("Port %u initialized successfully\n", port);
    return 0;
}

/* Load PCAP file */
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

    /* Allocate memory for packets */
    pcap_packets = malloc(MAX_PCAP_PACKETS * sizeof(struct packet_data));
    if (pcap_packets == NULL) {
        printf("Failed to allocate memory for PCAP packets\n");
        pcap_close(pcap);
        return -1;
    }

    /* Read all packets */
    num_pcap_packets = 0;
    while ((ret = pcap_next_ex(pcap, &header, &data)) >= 0) {
        if (ret == 0) continue; /* Timeout */

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

/* Main sending loop */
static void send_loop(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║      DPDK PCAP SENDER - Line-rate transmission           ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");
    printf("Starting packet transmission...\n");
    printf("Press Ctrl+C to stop\n\n");

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;

    while (!force_quit) {
        /* Allocate mbufs */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE) != 0) {
            printf("Failed to allocate mbufs\n");
            rte_delay_us_block(100);
            continue;
        }

        /* Fill mbufs with PCAP data */
        for (i = 0; i < BURST_SIZE; i++) {
            struct packet_data *pkt_data = &pcap_packets[current_packet_idx];

            /* Copy packet data to mbuf */
            char *pkt_buf = rte_pktmbuf_mtod(pkts[i], char *);
            rte_memcpy(pkt_buf, pkt_data->data, pkt_data->len);
            pkts[i]->data_len = pkt_data->len;
            pkts[i]->pkt_len = pkt_data->len;

            total_bytes_sent += pkt_data->len;

            /* Move to next packet (loop) */
            current_packet_idx++;
            if (current_packet_idx >= num_pcap_packets)
                current_packet_idx = 0;
        }

        /* Send burst */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts, BURST_SIZE);
        total_packets_sent += nb_tx;

        /* Free unsent packets */
        if (unlikely(nb_tx < BURST_SIZE)) {
            for (i = nb_tx; i < BURST_SIZE; i++)
                rte_pktmbuf_free(pkts[i]);
        }

        /* Print statistics every 5 seconds */
        uint64_t cur_tsc = rte_rdtsc();
        if (cur_tsc - last_stats_tsc >= hz * 5) {
            double elapsed = (double)(cur_tsc - start_tsc) / hz;
            double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
            double mpps = (total_packets_sent / elapsed) / 1e6;

            printf("[%.1fs] Sent: %lu pkts (%.2f Mpps) | %.2f Gbps | %lu bytes\n",
                   elapsed, total_packets_sent, mpps, gbps, total_bytes_sent);

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

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check for PCAP file argument */
    if (argc < 2) {
        printf("Usage: %s [EAL options] -- <pcap_file>\n", argv[0]);
        return -1;
    }

    pcap_file = argv[1];

    /* Install signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check for available ports */
    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize port */
    if (port_init(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", port_id);

    /* Load PCAP file */
    if (load_pcap(pcap_file) != 0)
        rte_exit(EXIT_FAILURE, "Failed to load PCAP file\n");

    /* Start sending */
    send_loop();

    /* Cleanup */
    printf("Stopping port %u...\n", port_id);
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (pcap_packets)
        free(pcap_packets);

    printf("Sender stopped.\n");
    return 0;
}
