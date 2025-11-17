/*
 * DPDK-based Benign HTTP Traffic Generator
 * Target: 80 Gbps (~80% of 100G link capacity)
 * Designed for c6525-100g nodes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_cycles.h>

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288  // Increased for high-speed traffic
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 128    // Increased burst size for better throughput

// Target: 80 Gbps = 10 GB/s
// With average HTTP packet size ~800 bytes: ~12.5M pps
#define TARGET_RATE_GBPS 80
#define TARGET_PPS 12500000  // 12.5M packets per second

// Packet templates for realistic HTTP traffic
#define NUM_HTTP_TEMPLATES 10
#define MAX_PACKET_SIZE 1518
#define MIN_PACKET_SIZE 64

// Statistics structure
struct traffic_stats {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_dropped;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    double tx_rate_gbps;
    double tx_rate_mpps;
} __rte_cache_aligned;

static volatile bool force_quit = false;
static struct traffic_stats stats[RTE_MAX_LCORE];

// HTTP request templates (realistic benign traffic patterns)
static const char *http_templates[] = {
    "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/users HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
    "POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"username\":\"user\",\"password\":\"pass\"}",
    "GET /images/logo.png HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: image/png\r\nConnection: keep-alive\r\n\r\n",
    "GET /css/style.css HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/css\r\nConnection: keep-alive\r\n\r\n",
    "GET /js/app.js HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/javascript\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/products?page=1 HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
    "POST /api/checkout HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 78\r\n\r\n{\"cart_id\":123,\"payment\":\"credit_card\"}",
    "GET /search?q=dpdk+networking HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/stats HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\nAuthorization: Bearer token123\r\nConnection: keep-alive\r\n\r\n"
};

// Configuration structure
struct generator_config {
    uint16_t port_id;
    uint16_t nb_ports;
    struct rte_mempool *mbuf_pool;
    uint32_t target_rate_pps;
    uint16_t pkt_size_min;
    uint16_t pkt_size_max;
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    uint32_t src_ip_base;
    uint32_t dst_ip_base;
    uint16_t src_port_base;
    uint16_t dst_port;
};

static struct generator_config gen_config;

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Initialize port configuration */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM |
                    DEV_TX_OFFLOAD_TCP_CKSUM |
                    DEV_TX_OFFLOAD_MULTI_SEGS,
    },
};

/* Calculate checksums */
static uint16_t calc_ip_checksum(struct rte_ipv4_hdr *ipv4_hdr)
{
    uint32_t sum = 0;
    uint16_t val;
    int i;

    ipv4_hdr->hdr_checksum = 0;

    // Access via memcpy to avoid alignment warnings
    uint8_t *bytes = (uint8_t *)ipv4_hdr;
    for (i = 0; i < 20; i += 2) {
        val = (bytes[i] << 8) | bytes[i + 1];
        sum += val;
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return rte_cpu_to_be_16((uint16_t)~sum);
}

/* Generate realistic benign HTTP packet */
static struct rte_mbuf *generate_benign_packet(struct rte_mempool *mbuf_pool,
                                                uint32_t template_idx,
                                                uint32_t seq_num)
{
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint8_t *payload;

    const char *http_template = http_templates[template_idx % NUM_HTTP_TEMPLATES];
    uint16_t http_len = strlen(http_template);

    // Allocate mbuf
    mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (mbuf == NULL)
        return NULL;

    // Ethernet header
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    rte_ether_addr_copy(&gen_config.dst_mac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&gen_config.src_mac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    // IPv4 header
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                               sizeof(struct rte_tcp_hdr) + http_len);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(seq_num & 0xFFFF);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_TCP;

    // Vary source IPs for realistic traffic
    ipv4_hdr->src_addr = rte_cpu_to_be_32(gen_config.src_ip_base + (seq_num % 65536));
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(gen_config.dst_ip_base);

    ipv4_hdr->hdr_checksum = calc_ip_checksum(ipv4_hdr);

    // TCP header
    tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
    tcp_hdr->src_port = rte_cpu_to_be_16(gen_config.src_port_base + (seq_num % 10000));
    tcp_hdr->dst_port = rte_cpu_to_be_16(gen_config.dst_port);
    tcp_hdr->sent_seq = rte_cpu_to_be_32(seq_num);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(0);
    tcp_hdr->data_off = 0x50;  // 20 bytes
    tcp_hdr->tcp_flags = RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG;
    tcp_hdr->rx_win = rte_cpu_to_be_16(65535);
    tcp_hdr->cksum = 0;  // Offload to NIC
    tcp_hdr->tcp_urp = 0;

    // HTTP payload
    payload = (uint8_t *)(tcp_hdr + 1);
    memcpy(payload, http_template, http_len);

    // Set packet length
    mbuf->data_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr) + http_len;
    mbuf->pkt_len = mbuf->data_len;

    // Enable checksum offload
    mbuf->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_TCP_CKSUM;
    mbuf->l2_len = sizeof(struct rte_ether_hdr);
    mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
    mbuf->l4_len = sizeof(struct rte_tcp_hdr);

    return mbuf;
}

/* Main packet generation loop per core */
static int lcore_benign_traffic(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t hz = rte_get_tsc_hz();
    uint32_t seq_num = lcore_id * 1000000;
    uint32_t template_idx = 0;

    // Calculate packets per core per second
    uint32_t nb_lcores = rte_lcore_count() - 1;  // Exclude main lcore
    uint32_t pps_per_core = gen_config.target_rate_pps / nb_lcores;
    uint64_t tsc_per_packet = hz / pps_per_core;

    printf("Core %u: Generating %u pps (TSC per packet: %lu)\n",
           lcore_id, pps_per_core, tsc_per_packet);

    prev_tsc = rte_rdtsc();

    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;

        // Rate limiting: only send if enough time has passed
        if (diff_tsc >= tsc_per_packet) {
            // Generate burst of packets
            uint16_t nb_bufs = 0;
            for (int i = 0; i < BURST_SIZE; i++) {
                bufs[i] = generate_benign_packet(gen_config.mbuf_pool,
                                                  template_idx,
                                                  seq_num++);
                if (bufs[i] == NULL) {
                    // Failed to allocate, send what we have
                    nb_bufs = i;
                    break;
                }
                nb_bufs++;
                template_idx = (template_idx + 1) % NUM_HTTP_TEMPLATES;
            }

            // Send burst
            uint16_t nb_tx = rte_eth_tx_burst(gen_config.port_id, 0, bufs, nb_bufs);

            // Update statistics
            stats[lcore_id].tx_packets += nb_tx;
            for (int i = 0; i < nb_tx; i++) {
                stats[lcore_id].tx_bytes += bufs[i]->pkt_len;
            }

            // Free unsent packets
            if (unlikely(nb_tx < nb_bufs)) {
                stats[lcore_id].tx_dropped += (nb_bufs - nb_tx);
                for (int i = nb_tx; i < nb_bufs; i++) {
                    rte_pktmbuf_free(bufs[i]);
                }
            }

            prev_tsc = cur_tsc;
        }
    }

    printf("Core %u: Stopping. Sent %lu packets (%lu bytes)\n",
           lcore_id, stats[lcore_id].tx_packets, stats[lcore_id].tx_bytes);

    return 0;
}

/* Print statistics */
static void print_stats(void)
{
    uint64_t total_tx_packets = 0;
    uint64_t total_tx_bytes = 0;
    uint64_t total_dropped = 0;
    static uint64_t prev_packets = 0;
    static uint64_t prev_bytes = 0;
    static uint64_t prev_tsc = 0;

    // Sum statistics from all cores
    for (int i = 0; i < RTE_MAX_LCORE; i++) {
        total_tx_packets += stats[i].tx_packets;
        total_tx_bytes += stats[i].tx_bytes;
        total_dropped += stats[i].tx_dropped;
    }

    // Calculate rates
    uint64_t cur_tsc = rte_rdtsc();
    if (prev_tsc > 0) {
        double time_diff = (double)(cur_tsc - prev_tsc) / rte_get_tsc_hz();
        uint64_t pkt_diff = total_tx_packets - prev_packets;
        uint64_t byte_diff = total_tx_bytes - prev_bytes;

        double pps = pkt_diff / time_diff;
        double bps = (byte_diff * 8) / time_diff;
        double gbps = bps / 1e9;

        printf("\n=== Benign Traffic Generator Statistics ===\n");
        printf("Total Packets:  %20lu\n", total_tx_packets);
        printf("Total Bytes:    %20lu\n", total_tx_bytes);
        printf("Dropped:        %20lu\n", total_dropped);
        printf("Rate:           %20.2f Mpps\n", pps / 1e6);
        printf("Throughput:     %20.2f Gbps\n", gbps);
        printf("Target:         %20.2f Gbps (%d%%)\n",
               (double)TARGET_RATE_GBPS,
               (int)((gbps / TARGET_RATE_GBPS) * 100));
        printf("==========================================\n");
    }

    prev_packets = total_tx_packets;
    prev_bytes = total_tx_bytes;
    prev_tsc = cur_tsc;
}

/* Initialize port */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info: %s\n", strerror(-retval));
        return retval;
    }

    // Configure the Ethernet device
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    // Allocate and set up RX queue
    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mbuf_pool);
    if (retval < 0)
        return retval;

    // Allocate and set up TX queue
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
                                     rte_eth_dev_socket_id(port),
                                     &txconf);
    if (retval < 0)
        return retval;

    // Start the Ethernet port
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    // Enable promiscuous mode
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           port,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    return 0;
}

/* Main function */
int main(int argc, char *argv[])
{
    unsigned lcore_id;
    int ret;
    uint16_t portid = 0;

    // Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    // Check number of ports
    gen_config.nb_ports = rte_eth_dev_count_avail();
    if (gen_config.nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Found %u Ethernet ports\n", gen_config.nb_ports);

    // Create mbuf pool
    gen_config.mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                                    MBUF_CACHE_SIZE, 0,
                                                    RTE_MBUF_DEFAULT_BUF_SIZE,
                                                    rte_socket_id());
    if (gen_config.mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize configuration with default values
    gen_config.port_id = 0;
    gen_config.target_rate_pps = TARGET_PPS;
    gen_config.dst_port = 80;
    gen_config.src_port_base = 20000;

    // Default MAC addresses (should be configured via command line)
    memset(&gen_config.src_mac, 0xAA, sizeof(struct rte_ether_addr));
    memset(&gen_config.dst_mac, 0xBB, sizeof(struct rte_ether_addr));

    // Default IPs: 192.168.1.0/24 -> 10.0.0.1
    gen_config.src_ip_base = (192 << 24) | (168 << 16) | (1 << 8);
    gen_config.dst_ip_base = (10 << 24) | (0 << 16) | (0 << 8) | 1;

    // Initialize port
    if (port_init(portid, gen_config.mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", portid);

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n=== Starting Benign Traffic Generator ===\n");
    printf("Target Rate: %u Gbps (%u Mpps)\n", TARGET_RATE_GBPS, TARGET_PPS / 1000000);
    printf("Number of worker cores: %u\n", rte_lcore_count() - 1);
    printf("Press Ctrl+C to stop...\n\n");

    // Launch traffic generation on all worker cores
    rte_eal_mp_remote_launch(lcore_benign_traffic, NULL, SKIP_MASTER);

    // Main core: print statistics every second
    while (!force_quit) {
        sleep(1);
        print_stats();
    }

    // Wait for all cores to finish
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            break;
    }

    // Stop port (void return in DPDK 19.11)
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);

    printf("\n=== Generator stopped ===\n");
    print_stats();

    // Cleanup EAL
    rte_eal_cleanup();

    return 0;
}
