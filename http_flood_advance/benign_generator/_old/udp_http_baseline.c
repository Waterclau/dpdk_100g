/*
 * High-Performance UDP-based HTTP Traffic Generator with DPDK
 * Simulates realistic HTTP traffic using UDP packets with HTTP payloads
 * Optimized for 40-100 Gbps line rate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288          // 512K mbufs for high throughput
#define MBUF_CACHE_SIZE 512
#define MAX_PKT_BURST 512         // Large burst for line rate
#define PREFETCH_OFFSET 3

/* HTTP payload templates with realistic distribution */
#define NUM_HTTP_TEMPLATES 15

static const char *http_templates[] = {
    /* Homepage requests - 25% */
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Chrome/120.0\r\nAccept: text/html\r\n\r\n",
    "GET /home HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Firefox/121.0\r\nAccept: */*\r\n\r\n",

    /* API endpoints - 35% */
    "GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\nAuthorization: Bearer xyz\r\n\r\n",
    "POST /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 45\r\n\r\n{\"user\":\"test\",\"pass\":\"secret\"}",
    "GET /api/v1/products?limit=10 HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n",
    "POST /api/v1/orders HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 60\r\n\r\n{\"product_id\":123,\"qty\":2}",
    "GET /api/v1/status HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n",

    /* Static resources - 30% */
    "GET /static/css/main.css HTTP/1.1\r\nHost: cdn.example.com\r\nAccept: text/css\r\n\r\n",
    "GET /static/js/app.js HTTP/1.1\r\nHost: cdn.example.com\r\nAccept: application/javascript\r\n\r\n",
    "GET /static/images/logo.png HTTP/1.1\r\nHost: cdn.example.com\r\nAccept: image/png\r\n\r\n",
    "GET /favicon.ico HTTP/1.1\r\nHost: www.example.com\r\nAccept: image/x-icon\r\n\r\n",

    /* Dynamic content - 10% */
    "GET /search?q=dpdk HTTP/1.1\r\nHost: www.example.com\r\nAccept: text/html\r\n\r\n",
    "GET /products/12345 HTTP/1.1\r\nHost: www.example.com\r\nAccept: text/html\r\n\r\n",
    "POST /api/search HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 25\r\n\r\n{\"query\":\"test\"}"
};

/* Template weights (cumulative probabilities) */
static const double template_weights[] = {
    0.08, 0.16, 0.25,           // Homepage (25%)
    0.32, 0.39, 0.46, 0.53, 0.60, // API (35%)
    0.68, 0.76, 0.84, 0.90,     // Static (30%)
    0.94, 0.97, 1.00            // Dynamic (10%)
};

/* Configuration structure */
struct gen_config {
    uint16_t port_id;
    uint16_t nb_queues;
    uint32_t rate_pps;
    uint32_t src_ip_base;       // Base IP for /16 subnet
    uint32_t dst_ip;
    struct rte_ether_addr dst_mac;
    struct rte_ether_addr src_mac;
    uint16_t burst_size;
    bool enable_udp_checksum;
} __rte_cache_aligned;

static struct gen_config g_config = {
    .port_id = 0,
    .nb_queues = 1,
    .rate_pps = 1000000,        // 1M pps default
    .src_ip_base = 0xC0A80000,  // 192.168.0.0
    .dst_ip = 0x0A000001,       // 10.0.0.1
    .burst_size = 256,
    .enable_udp_checksum = false
};

/* Per-core statistics */
struct core_stats {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_dropped;
    uint64_t tx_failed;
} __rte_cache_aligned;

static struct core_stats stats[RTE_MAX_LCORE];
static volatile bool force_quit = false;
static volatile bool start_tx = false;

/* Pre-built packet templates (one per HTTP template) */
static struct rte_mbuf *pkt_templates[NUM_HTTP_TEMPLATES];
static struct rte_mempool *pktmbuf_pool = NULL;

/* Forward declarations */
static inline struct rte_mbuf *generate_packet_fast(int template_id, uint16_t *src_port_seed, uint32_t *ip_seed);

/* Port configuration */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Calculate UDP checksum (optional) */
static uint16_t calc_udp_checksum(struct rte_ipv4_hdr *ipv4_hdr,
                                   struct rte_udp_hdr *udp_hdr,
                                   uint16_t udp_len)
{
    uint32_t sum = 0;
    uint8_t *bytes = (uint8_t *)udp_hdr;
    uint16_t val;
    int i;

    /* Pseudo header */
    sum += (ipv4_hdr->src_addr >> 16) & 0xFFFF;
    sum += ipv4_hdr->src_addr & 0xFFFF;
    sum += (ipv4_hdr->dst_addr >> 16) & 0xFFFF;
    sum += ipv4_hdr->dst_addr & 0xFFFF;
    sum += rte_cpu_to_be_16(IPPROTO_UDP);
    sum += rte_cpu_to_be_16(udp_len);

    /* UDP header and data - use byte access to avoid alignment issues */
    udp_hdr->dgram_cksum = 0;

    for (i = 0; i < udp_len - 1; i += 2) {
        val = (bytes[i] << 8) | bytes[i + 1];
        sum += val;
    }

    if (udp_len & 1) {
        sum += bytes[udp_len - 1] << 8;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

/* Select template based on probability distribution */
static inline int select_template(uint32_t *seed)
{
    /* Simple fast random using seed */
    *seed = *seed * 1103515245 + 12345;
    uint32_t rand_val = (*seed / 65536) % 32768;
    double prob = (double)rand_val / 32768.0;

    for (int i = 0; i < NUM_HTTP_TEMPLATES; i++) {
        if (prob <= template_weights[i])
            return i;
    }
    return NUM_HTTP_TEMPLATES - 1;
}

/* Create packet template */
static struct rte_mbuf *create_template_packet(struct rte_mempool *mp,
                                                const char *http_payload,
                                                int template_id)
{
    struct rte_mbuf *pkt;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint8_t *payload;
    uint16_t payload_len = strlen(http_payload);
    uint16_t udp_len = sizeof(struct rte_udp_hdr) + payload_len;
    uint16_t ip_len = sizeof(struct rte_ipv4_hdr) + udp_len;

    pkt = rte_pktmbuf_alloc(mp);
    if (pkt == NULL) {
        printf("Failed to allocate mbuf for template %d\n", template_id);
        return NULL;
    }

    /* Reserve headroom */
    pkt->data_len = sizeof(struct rte_ether_hdr) + ip_len;
    pkt->pkt_len = pkt->data_len;

    /* Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    rte_ether_addr_copy(&g_config.dst_mac, &eth_hdr->d_addr);
    rte_ether_addr_copy(&g_config.src_mac, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IPv4 header */
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    memset(ipv4_hdr, 0, sizeof(*ipv4_hdr));
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(ip_len);
    ipv4_hdr->packet_id = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(g_config.src_ip_base);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(g_config.dst_ip);
    ipv4_hdr->hdr_checksum = 0;  // Will be set per packet

    /* UDP header */
    udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
    udp_hdr->src_port = rte_cpu_to_be_16(1024);  // Will be randomized per packet
    udp_hdr->dst_port = rte_cpu_to_be_16(80);
    udp_hdr->dgram_len = rte_cpu_to_be_16(udp_len);
    udp_hdr->dgram_cksum = 0;

    /* HTTP payload */
    payload = (uint8_t *)(udp_hdr + 1);
    rte_memcpy(payload, http_payload, payload_len);

    /* Mark as template */
    pkt->refcnt = 1;

    return pkt;
}

/* Initialize all packet templates */
static int init_packet_templates(struct rte_mempool *mp)
{
    printf("Creating %d packet templates...\n", NUM_HTTP_TEMPLATES);

    for (int i = 0; i < NUM_HTTP_TEMPLATES; i++) {
        pkt_templates[i] = create_template_packet(mp, http_templates[i], i);
        if (pkt_templates[i] == NULL) {
            printf("Failed to create template %d\n", i);
            return -1;
        }
        printf("  Template %d: %u bytes, payload: %.50s...\n",
               i, pkt_templates[i]->pkt_len, http_templates[i]);
    }

    printf("All templates created successfully\n");
    return 0;
}

/* Fast packet generation by copying template data */
static inline struct rte_mbuf *generate_packet_fast(int template_id,
                                                     uint16_t *src_port_seed,
                                                     uint32_t *ip_seed)
{
    struct rte_mbuf *pkt;
    struct rte_mbuf *template;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint32_t src_ip_offset;
    uint16_t src_port;
    uint16_t pkt_len;

    template = pkt_templates[template_id];
    pkt_len = template->pkt_len;

    /* Allocate new mbuf */
    pkt = rte_pktmbuf_alloc(pktmbuf_pool);
    if (pkt == NULL)
        return NULL;

    /* Copy template data directly (fast memcpy) */
    rte_memcpy(rte_pktmbuf_mtod(pkt, void *),
               rte_pktmbuf_mtod(template, void *),
               pkt_len);

    pkt->data_len = pkt_len;
    pkt->pkt_len = pkt_len;

    /* Modify only variable fields for randomization */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);

    /* Randomize source IP within /16 subnet using simple LCG */
    *ip_seed = *ip_seed * 1103515245 + 12345;
    src_ip_offset = *ip_seed & 0xFFFF;  // 0-65535
    ipv4_hdr->src_addr = rte_cpu_to_be_32(g_config.src_ip_base + src_ip_offset);

    /* Randomize source port */
    *src_port_seed = (*src_port_seed + 1) & 0xEFFF;  // Rotate through ephemeral ports
    src_port = 1024 + *src_port_seed;
    udp_hdr->src_port = rte_cpu_to_be_16(src_port);

    /* Randomize packet ID */
    *ip_seed = *ip_seed * 1103515245 + 12345;
    ipv4_hdr->packet_id = rte_cpu_to_be_16(*ip_seed & 0xFFFF);

    /* Recalculate IP checksum (software) */
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    /* UDP checksum (optional) */
    if (g_config.enable_udp_checksum) {
        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
        udp_hdr->dgram_cksum = calc_udp_checksum(ipv4_hdr, udp_hdr, udp_len);
    }

    return pkt;
}

/* Main packet transmission loop per lcore */
static int lcore_main_loop(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    /* Each worker core gets its own TX queue to avoid multi-producer issues */
    /* lcore_id starts at 1 for first worker, so queue 0 for first worker */
    uint16_t queue_id = lcore_id - 1;
    struct rte_mbuf *tx_burst[MAX_PKT_BURST];
    uint16_t nb_tx;
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t hz = rte_get_tsc_hz();
    uint16_t src_port_seed = lcore_id * 10000;
    uint32_t ip_seed = lcore_id * 123456;
    uint32_t template_seed = lcore_id * 789;

    /* Calculate packets per core */
    unsigned nb_lcores = rte_lcore_count() - 1;
    if (nb_lcores == 0) nb_lcores = 1;
    uint32_t target_pps_per_core = g_config.rate_pps / nb_lcores;
    uint64_t tsc_per_burst = (hz * g_config.burst_size) / target_pps_per_core;

    printf("Lcore %u (Queue %u): Target rate %u pps, burst %u\n",
           lcore_id, queue_id, target_pps_per_core, g_config.burst_size);

    /* Wait for signal to start */
    printf("Lcore %u: Waiting for start signal...\n", lcore_id);
    while (!start_tx && !force_quit) {
        rte_pause();
    }

    if (force_quit) {
        printf("Lcore %u: Quit before start\n", lcore_id);
        return 0;
    }

    printf("Lcore %u: Starting transmission\n", lcore_id);
    prev_tsc = rte_rdtsc();

    /* Small stagger per core to avoid all hitting TX at once */
    usleep((lcore_id - 1) * 100000);  // 0ms, 100ms, 200ms delay
    printf("Lcore %u: Delay complete, entering main loop\n", lcore_id);

    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;

        /* Check if it's time to send next burst */
        if (diff_tsc >= tsc_per_burst) {
            uint16_t actual_burst = 0;

            /* Generate burst of packets */
            for (uint16_t i = 0; i < g_config.burst_size; i++) {
                int template_id = select_template(&template_seed);
                tx_burst[i] = generate_packet_fast(template_id, &src_port_seed, &ip_seed);

                if (unlikely(tx_burst[i] == NULL)) {
                    /* Allocation failed, send what we have */
                    break;
                }

                actual_burst++;

                /* Prefetch next packet data */
                if (i + PREFETCH_OFFSET < g_config.burst_size)
                    rte_prefetch0(rte_pktmbuf_mtod(tx_burst[i + PREFETCH_OFFSET],
                                                   void *));
            }

            /* Only transmit if we have packets */
            if (actual_burst == 0) {
                prev_tsc = cur_tsc;
                continue;
            }

            /* DEBUG: First transmission from this core */
            static __thread bool first_tx = true;
            if (first_tx) {
                printf("Lcore %u: About to call first rte_eth_tx_burst with %u packets\n",
                       lcore_id, actual_burst);
                first_tx = false;
            }

            /* Transmit burst */
            nb_tx = rte_eth_tx_burst(g_config.port_id, queue_id,
                                     tx_burst, actual_burst);

            /* DEBUG: After transmission */
            if (nb_tx > 0 && stats[lcore_id].tx_packets == 0) {
                printf("Lcore %u: First TX successful, sent %u packets\n", lcore_id, nb_tx);
            }

            /* Update stats */
            stats[lcore_id].tx_packets += nb_tx;
            for (uint16_t i = 0; i < nb_tx; i++) {
                stats[lcore_id].tx_bytes += tx_burst[i]->pkt_len;
            }

            /* Free unsent packets */
            if (unlikely(nb_tx < actual_burst)) {
                stats[lcore_id].tx_dropped += (actual_burst - nb_tx);
                for (uint16_t i = nb_tx; i < actual_burst; i++) {
                    rte_pktmbuf_free(tx_burst[i]);
                }
            }

            prev_tsc = cur_tsc;
        }
    }

    printf("Lcore %u: Stopping. Sent %lu packets, %lu bytes\n",
           lcore_id, stats[lcore_id].tx_packets, stats[lcore_id].tx_bytes);

    return 0;
}

/* Print statistics */
static void print_stats(void)
{
    static uint64_t prev_packets = 0;
    static uint64_t prev_bytes = 0;
    static uint64_t prev_tsc = 0;
    uint64_t total_tx_packets = 0;
    uint64_t total_tx_bytes = 0;
    uint64_t total_dropped = 0;

    /* Sum all cores */
    for (unsigned i = 0; i < RTE_MAX_LCORE; i++) {
        total_tx_packets += stats[i].tx_packets;
        total_tx_bytes += stats[i].tx_bytes;
        total_dropped += stats[i].tx_dropped;
    }

    uint64_t cur_tsc = rte_rdtsc();

    if (prev_tsc > 0) {
        double time_diff = (double)(cur_tsc - prev_tsc) / rte_get_tsc_hz();
        uint64_t pkt_diff = total_tx_packets - prev_packets;
        uint64_t byte_diff = total_tx_bytes - prev_bytes;

        double pps = pkt_diff / time_diff;
        double bps = (byte_diff * 8) / time_diff;
        double gbps = bps / 1e9;

        unsigned mbuf_avail = rte_mempool_avail_count(pktmbuf_pool);
        unsigned mbuf_in_use = rte_mempool_in_use_count(pktmbuf_pool);

        printf("\r[TX] Packets: %12lu | Rate: %10.0f pps (%.2f Mpps) | "
               "Throughput: %8.2f Gbps | Dropped: %8lu | Mbufs: %u/%u   ",
               total_tx_packets, pps, pps / 1e6, gbps,
               total_dropped, mbuf_avail, mbuf_avail + mbuf_in_use);
        fflush(stdout);
    }

    prev_packets = total_tx_packets;
    prev_bytes = total_tx_bytes;
    prev_tsc = cur_tsc;
}

/* Initialize port */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t nb_queues)
{
    struct rte_eth_conf port_conf = port_conf_default;
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

    if (nb_queues > dev_info.max_tx_queues) {
        printf("Requested %u TX queues, but max is %u\n",
               nb_queues, dev_info.max_tx_queues);
        nb_queues = dev_info.max_tx_queues;
    }

    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    retval = rte_eth_dev_configure(port, 1, nb_queues, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Setup RX queue 0 */
    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mbuf_pool);
    if (retval < 0)
        return retval;

    /* Setup TX queues */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;

    for (uint16_t q = 0; q < nb_queues; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                         rte_eth_dev_socket_id(port),
                                         &txconf);
        if (retval < 0) {
            printf("Failed to setup TX queue %u\n", q);
            return retval;
        }
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           port,
           addr.addr_bytes[0], addr.addr_bytes[1],
           addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Copy to config */
    rte_ether_addr_copy(&addr, &g_config.src_mac);

    return 0;
}

/* Parse MAC address */
static int parse_mac_addr(const char *str, struct rte_ether_addr *addr)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &addr->addr_bytes[0], &addr->addr_bytes[1],
                  &addr->addr_bytes[2], &addr->addr_bytes[3],
                  &addr->addr_bytes[4], &addr->addr_bytes[5]) == 6 ? 0 : -1;
}

/* Parse IP address */
static uint32_t parse_ipv4_addr(const char *str)
{
    unsigned char a, b, c, d;
    if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

/* Print usage */
static void print_usage(const char *prgname)
{
    printf("Usage: %s [EAL options] -- [APP options]\n"
           "APP options:\n"
           "  --rate-pps RATE       : Target rate in packets per second (default: 1000000)\n"
           "  --src-ip-base IP      : Source IP base for /16 subnet (default: 192.168.0.0)\n"
           "  --dst-ip IP           : Destination IP (default: 10.0.0.1)\n"
           "  --dst-mac MAC         : Destination MAC address (default: ff:ff:ff:ff:ff:ff)\n"
           "  --burst-size SIZE     : Burst size 1-512 (default: 256)\n"
           "  --udp-checksum        : Enable UDP checksum calculation\n"
           "  --help                : Show this help\n",
           prgname);
}

/* Parse application arguments */
static int parse_args(int argc, char **argv)
{
    int opt, option_index;
    char *prgname = argv[0];

    static struct option lgopts[] = {
        {"rate-pps", required_argument, 0, 'r'},
        {"src-ip-base", required_argument, 0, 's'},
        {"dst-ip", required_argument, 0, 'd'},
        {"dst-mac", required_argument, 0, 'm'},
        {"burst-size", required_argument, 0, 'b'},
        {"udp-checksum", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, 0, 0}
    };

    /* Default destination MAC (broadcast) */
    memset(&g_config.dst_mac, 0xFF, RTE_ETHER_ADDR_LEN);

    while ((opt = getopt_long(argc, argv, "r:s:d:m:b:ch",
                              lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'r':
            g_config.rate_pps = atoi(optarg);
            break;
        case 's':
            g_config.src_ip_base = parse_ipv4_addr(optarg);
            break;
        case 'd':
            g_config.dst_ip = parse_ipv4_addr(optarg);
            break;
        case 'm':
            if (parse_mac_addr(optarg, &g_config.dst_mac) < 0) {
                printf("Invalid MAC address: %s\n", optarg);
                return -1;
            }
            break;
        case 'b':
            g_config.burst_size = atoi(optarg);
            if (g_config.burst_size < 1 || g_config.burst_size > MAX_PKT_BURST) {
                printf("Burst size must be 1-%d\n", MAX_PKT_BURST);
                return -1;
            }
            break;
        case 'c':
            g_config.enable_udp_checksum = true;
            break;
        case 'h':
            print_usage(prgname);
            exit(0);
        default:
            print_usage(prgname);
            return -1;
        }
    }

    return 0;
}

/* Main function */
int main(int argc, char **argv)
{
    unsigned lcore_id;
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

    argc -= ret;
    argv += ret;

    /* Parse application arguments */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid application arguments\n");

    /* Signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check ports */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Found %u Ethernet ports\n", nb_ports);

    /* Create mbuf pool */
    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    printf("Mbuf pool created: %u mbufs\n", NUM_MBUFS);

    /* Use one TX queue per worker core to avoid multi-producer issues */
    unsigned nb_lcores = rte_lcore_count() - 1;
    if (nb_lcores == 0) nb_lcores = 1;
    g_config.nb_queues = nb_lcores;  // One queue per worker core

    printf("Using %u TX queues (one per core) for %u worker cores\n",
           g_config.nb_queues, nb_lcores);

    /* Initialize port */
    if (port_init(g_config.port_id, pktmbuf_pool, g_config.nb_queues) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", g_config.port_id);

    /* Initialize packet templates */
    if (init_packet_templates(pktmbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "Cannot create packet templates\n");

    /* Print configuration */
    printf("\n=== UDP HTTP Baseline Traffic Generator ===\n");
    printf("Port:              %u\n", g_config.port_id);
    printf("TX Queues:         %u\n", g_config.nb_queues);
    printf("Target Rate:       %u pps (%.2f Mpps)\n",
           g_config.rate_pps, g_config.rate_pps / 1e6);
    printf("Burst Size:        %u\n", g_config.burst_size);
    printf("Source IP Base:    %u.%u.%u.%u/16\n",
           (g_config.src_ip_base >> 24) & 0xFF,
           (g_config.src_ip_base >> 16) & 0xFF,
           (g_config.src_ip_base >> 8) & 0xFF,
           g_config.src_ip_base & 0xFF);
    printf("Destination IP:    %u.%u.%u.%u\n",
           (g_config.dst_ip >> 24) & 0xFF,
           (g_config.dst_ip >> 16) & 0xFF,
           (g_config.dst_ip >> 8) & 0xFF,
           g_config.dst_ip & 0xFF);
    printf("Destination MAC:   %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_config.dst_mac.addr_bytes[0], g_config.dst_mac.addr_bytes[1],
           g_config.dst_mac.addr_bytes[2], g_config.dst_mac.addr_bytes[3],
           g_config.dst_mac.addr_bytes[4], g_config.dst_mac.addr_bytes[5]);
    printf("UDP Checksum:      %s\n", g_config.enable_udp_checksum ? "Enabled" : "Disabled");
    printf("HTTP Templates:    %d\n", NUM_HTTP_TEMPLATES);
    printf("Worker Cores:      %u\n", nb_lcores);
    printf("===========================================\n\n");

    /* Test transmission from main core to verify port is ready */
    printf("Testing port transmission...\n");
    uint16_t test_port = 1000;
    uint32_t test_ip = 999;
    struct rte_mbuf *test_pkt = generate_packet_fast(0, &test_port, &test_ip);
    if (test_pkt != NULL) {
        uint16_t sent = rte_eth_tx_burst(g_config.port_id, 0, &test_pkt, 1);
        if (sent == 0) {
            printf("WARNING: Test transmission failed!\n");
            rte_pktmbuf_free(test_pkt);
        } else {
            printf("Test transmission successful\n");
        }
    }

    /* Wait for port to stabilize */
    sleep(2);

    /* Launch worker cores */
    printf("Launching worker cores...\n");
    rte_eal_mp_remote_launch(lcore_main_loop, NULL, SKIP_MASTER);

    /* Give cores time to initialize */
    printf("Waiting for worker cores to initialize...\n");
    sleep(1);

    /* Signal workers to start transmission */
    printf("Signaling workers to start...\n");
    start_tx = true;
    __sync_synchronize();  /* Memory barrier */

    sleep(1);
    printf("Traffic generation started! (Press Ctrl+C to stop)\n\n");

    /* Main core: print statistics */
    while (!force_quit) {
        sleep(1);
        print_stats();
    }

    /* Wait for all cores */
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            break;
    }

    /* Print final stats */
    printf("\n\n=== Final Statistics ===\n");
    print_stats();
    printf("\n");

    /* Cleanup */
    rte_eth_dev_stop(g_config.port_id);
    rte_eth_dev_close(g_config.port_id);

    /* Free templates */
    for (int i = 0; i < NUM_HTTP_TEMPLATES; i++) {
        if (pkt_templates[i])
            rte_pktmbuf_free(pkt_templates[i]);
    }

    rte_eal_cleanup();

    return 0;
}
