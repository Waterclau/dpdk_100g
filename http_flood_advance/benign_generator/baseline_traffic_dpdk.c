/*
 * DPDK-based Realistic Baseline HTTP Traffic Generator
 * Simulates normal web server traffic patterns with natural variations
 * Designed for establishing baseline behavior before DDoS attacks
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <time.h>
#include <signal.h>
#include <math.h>
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

#define RX_RING_SIZE 2048
#define TX_RING_SIZE 2048
#define NUM_MBUFS 65536       // Reduced for normal traffic
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32         // Smaller bursts for realistic traffic

// Realistic baseline traffic rates (much lower than DDoS)
// Typical web server: 10K - 500K requests/sec
// We'll use configurable baseline with variations
#define DEFAULT_BASE_RATE_PPS 50000      // 50K pps baseline
#define MIN_RATE_PPS 10000               // 10K pps minimum
#define MAX_RATE_PPS 200000              // 200K pps maximum

// Traffic profile types
typedef enum {
    TRAFFIC_PROFILE_LOW = 0,      // Off-peak hours
    TRAFFIC_PROFILE_MEDIUM,       // Normal business hours
    TRAFFIC_PROFILE_HIGH,         // Peak hours
    TRAFFIC_PROFILE_VARIABLE      // Realistic daily variations
} traffic_profile_t;

// Packet templates for realistic HTTP traffic
#define NUM_HTTP_TEMPLATES 20
#define MAX_PACKET_SIZE 1518
#define MIN_PACKET_SIZE 64

// Statistics structure
struct traffic_stats {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_dropped;
    uint64_t sessions_created;
    double current_rate_pps;
    double current_rate_mbps;
    double avg_think_time_ms;
} __rte_cache_aligned;

static volatile bool force_quit = false;
static struct traffic_stats stats[RTE_MAX_LCORE];

// Realistic HTTP request templates (diverse web application traffic)
static const char *http_templates[] = {
    // Homepage and main pages (40% of traffic)
    "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\nAccept: text/html,application/xhtml+xml\r\nConnection: keep-alive\r\n\r\n",
    "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /home HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /about HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_1)\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",

    // API endpoints (30% of traffic)
    "GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: axios/1.6.0\r\nAccept: application/json\r\nAuthorization: Bearer eyJhbGc...\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/v1/products?limit=10 HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: fetch/3.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/v1/orders/status HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: axios/1.6.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n",
    "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 52\r\n\r\n{\"email\":\"user@example.com\",\"password\":\"pass123\"}",
    "POST /api/v1/items HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 85\r\n\r\n{\"name\":\"Product\",\"quantity\":1,\"price\":29.99}",

    // Static resources (20% of traffic)
    "GET /static/css/main.css HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/css\r\nConnection: keep-alive\r\n\r\n",
    "GET /static/js/app.bundle.js HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/javascript\r\nConnection: keep-alive\r\n\r\n",
    "GET /static/images/logo.png HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: image/png\r\nConnection: keep-alive\r\n\r\n",
    "GET /static/fonts/roboto.woff2 HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: font/woff2\r\nConnection: keep-alive\r\n\r\n",
    "GET /favicon.ico HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: image/x-icon\r\nConnection: keep-alive\r\n\r\n",

    // Search and dynamic content (10% of traffic)
    "GET /search?q=laptop HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /category/electronics HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "GET /product/12345 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n",
    "POST /api/v1/search HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 38\r\n\r\n{\"query\":\"dpdk\",\"filters\":{}}",
    "GET /user/profile HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nCookie: session_id=abc123\r\nConnection: keep-alive\r\n\r\n",
    "GET /api/v1/notifications HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: axios/1.6.0\r\nAccept: application/json\r\nConnection: keep-alive\r\n\r\n"
};

// Request weights (probability distribution)
static const double http_template_weights[] = {
    0.15, 0.10, 0.08, 0.07,  // Homepage variants (40%)
    0.08, 0.07, 0.06, 0.05, 0.04,  // API calls (30%)
    0.05, 0.05, 0.05, 0.03, 0.02,  // Static resources (20%)
    0.03, 0.02, 0.02, 0.02, 0.01, 0.01  // Dynamic content (10%)
};

// Configuration structure
struct generator_config {
    uint16_t port_id;
    uint16_t nb_ports;
    struct rte_mempool *mbuf_pool;
    uint32_t base_rate_pps;
    traffic_profile_t profile;
    uint16_t pkt_size_min;
    uint16_t pkt_size_max;
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    uint32_t src_ip_base;
    uint32_t dst_ip_base;
    uint16_t src_port_base;
    uint16_t dst_port;
    bool enable_variations;
    uint32_t variation_period_sec;
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
                    DEV_TX_OFFLOAD_TCP_CKSUM,
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

/* Select HTTP template based on probability distribution */
static int select_weighted_template(void)
{
    double rand_val = (double)rand() / RAND_MAX;
    double cumulative = 0.0;

    for (int i = 0; i < NUM_HTTP_TEMPLATES; i++) {
        cumulative += http_template_weights[i];
        if (rand_val <= cumulative) {
            return i;
        }
    }
    return NUM_HTTP_TEMPLATES - 1;
}

/* Calculate current rate based on traffic profile and time */
static uint32_t calculate_current_rate(time_t start_time, uint32_t base_rate)
{
    if (!gen_config.enable_variations) {
        return base_rate;
    }

    time_t now = time(NULL);
    uint32_t elapsed = now - start_time;

    // Simulate daily traffic pattern (24-hour cycle)
    uint32_t period = gen_config.variation_period_sec;
    if (period == 0) period = 3600; // Default 1 hour cycle

    double cycle_pos = (double)(elapsed % period) / period;

    // Sinusoidal variation: low at night, high during day
    // Base rate ± 50% variation
    double variation = 0.5 + 0.5 * sin(cycle_pos * 2 * M_PI);

    // Add some random noise (±10%)
    double noise = 0.9 + 0.2 * ((double)rand() / RAND_MAX);

    uint32_t current_rate = (uint32_t)(base_rate * variation * noise);

    // Clamp to reasonable bounds
    if (current_rate < MIN_RATE_PPS) current_rate = MIN_RATE_PPS;
    if (current_rate > MAX_RATE_PPS) current_rate = MAX_RATE_PPS;

    return current_rate;
}

/* Generate realistic baseline HTTP packet */
static struct rte_mbuf *generate_baseline_packet(struct rte_mempool *mbuf_pool,
                                                  uint32_t seq_num)
{
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint8_t *payload;

    // Select HTTP template with weighted distribution
    int template_idx = select_weighted_template();
    const char *http_template = http_templates[template_idx];
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

    // IPv4 header - varied source IPs for realistic traffic
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                               sizeof(struct rte_tcp_hdr) + http_len);
    ipv4_hdr->packet_id = rte_cpu_to_be_16(seq_num & 0xFFFF);
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_TCP;

    // Realistic source IP distribution (simulate many users)
    // Use /16 network (65K hosts)
    uint32_t ip_offset = rand() % 65536;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(gen_config.src_ip_base + ip_offset);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(gen_config.dst_ip_base);

    ipv4_hdr->hdr_checksum = calc_ip_checksum(ipv4_hdr);

    // TCP header - realistic ephemeral ports
    tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
    tcp_hdr->src_port = rte_cpu_to_be_16(32768 + (rand() % 28232)); // Ephemeral range
    tcp_hdr->dst_port = rte_cpu_to_be_16(gen_config.dst_port);
    tcp_hdr->sent_seq = rte_cpu_to_be_32(seq_num);
    tcp_hdr->recv_ack = rte_cpu_to_be_32(1);
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

/* Main packet generation loop per core with realistic timing */
static int lcore_baseline_traffic(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t prev_tsc = 0, cur_tsc, diff_tsc;
    uint64_t hz = rte_get_tsc_hz();
    uint32_t seq_num = lcore_id * 1000000;
    time_t start_time = time(NULL);
    uint32_t burst_count = 0;

    // Calculate packets per core per second
    uint32_t nb_lcores = rte_lcore_count() - 1;  // Exclude main lcore
    if (nb_lcores == 0) nb_lcores = 1;

    uint32_t base_pps_per_core = gen_config.base_rate_pps / nb_lcores;

    printf("Core %u: Starting baseline traffic generation\n", lcore_id);
    printf("  Base rate: %u pps per core\n", base_pps_per_core);
    printf("  Profile: %s\n",
           gen_config.profile == TRAFFIC_PROFILE_LOW ? "LOW" :
           gen_config.profile == TRAFFIC_PROFILE_MEDIUM ? "MEDIUM" :
           gen_config.profile == TRAFFIC_PROFILE_HIGH ? "HIGH" : "VARIABLE");

    prev_tsc = rte_rdtsc();

    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;

        // Calculate current rate with variations
        uint32_t current_pps = calculate_current_rate(start_time, base_pps_per_core);
        uint64_t tsc_per_burst = (hz * BURST_SIZE) / current_pps;

        // Rate limiting with realistic variations
        if (diff_tsc >= tsc_per_burst) {
            // Generate smaller burst for more natural traffic
            int actual_burst = BURST_SIZE;

            // Add randomness to burst size (±25%)
            if (rand() % 4 == 0) {
                actual_burst = BURST_SIZE * 3 / 4 + (rand() % (BURST_SIZE / 2));
            }

            // Generate packets
            int generated = 0;
            for (int i = 0; i < actual_burst; i++) {
                bufs[i] = generate_baseline_packet(gen_config.mbuf_pool, seq_num++);
                if (bufs[i] == NULL) {
                    actual_burst = i;
                    break;
                }
                generated++;
            }

            // Send burst
            uint16_t nb_tx = rte_eth_tx_burst(gen_config.port_id, 0, bufs, actual_burst);

            // Update statistics
            stats[lcore_id].tx_packets += nb_tx;
            for (int i = 0; i < nb_tx; i++) {
                stats[lcore_id].tx_bytes += bufs[i]->pkt_len;
            }

            // Free unsent packets
            if (unlikely(nb_tx < actual_burst)) {
                stats[lcore_id].tx_dropped += (actual_burst - nb_tx);
                for (int i = nb_tx; i < actual_burst; i++) {
                    rte_pktmbuf_free(bufs[i]);
                }
            }

            burst_count++;
            prev_tsc = cur_tsc;

            // Realistic think time - occasionally pause briefly
            if (burst_count % 100 == 0) {
                // Small delay every 100 bursts (~10-100 microseconds)
                rte_delay_us_block(10 + (rand() % 90));
            }
        }
    }

    printf("Core %u: Stopping. Sent %lu packets (%lu bytes)\n",
           lcore_id, stats[lcore_id].tx_packets, stats[lcore_id].tx_bytes);

    return 0;
}

/* Print statistics with baseline metrics */
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
        double mbps = bps / 1e6;

        printf("\n=== Baseline Traffic Generator Statistics ===\n");
        printf("Total Packets:  %20lu\n", total_tx_packets);
        printf("Total Bytes:    %20lu (%.2f MB)\n", total_tx_bytes, total_tx_bytes / 1e6);
        printf("Dropped:        %20lu\n", total_dropped);
        printf("Current Rate:   %20.2f pps (%.2f Kpps)\n", pps, pps / 1e3);
        printf("Throughput:     %20.2f Mbps (%.3f Gbps)\n", mbps, mbps / 1e3);
        printf("Avg Packet:     %20.2f bytes\n",
               pkt_diff > 0 ? (double)byte_diff / pkt_diff : 0);
        printf("Base Rate:      %20u pps\n", gen_config.base_rate_pps);
        printf("=============================================\n");
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

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mbuf_pool);
    if (retval < 0)
        return retval;

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
                                     rte_eth_dev_socket_id(port),
                                     &txconf);
    if (retval < 0)
        return retval;

    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

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

    // Seed random number generator
    srand(time(NULL));

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

    // Create mbuf pool (smaller for baseline traffic)
    gen_config.mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                                    MBUF_CACHE_SIZE, 0,
                                                    RTE_MBUF_DEFAULT_BUF_SIZE,
                                                    rte_socket_id());
    if (gen_config.mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Initialize configuration with realistic baseline values
    gen_config.port_id = 0;
    gen_config.base_rate_pps = DEFAULT_BASE_RATE_PPS;  // 50K pps default
    gen_config.profile = TRAFFIC_PROFILE_VARIABLE;
    gen_config.dst_port = 80;
    gen_config.src_port_base = 32768;
    gen_config.enable_variations = true;
    gen_config.variation_period_sec = 3600;  // 1 hour cycle

    // Default MAC addresses (configure via command line in production)
    memset(&gen_config.src_mac, 0xAA, sizeof(struct rte_ether_addr));
    memset(&gen_config.dst_mac, 0xBB, sizeof(struct rte_ether_addr));

    // Default IPs: 192.168.0.0/16 -> 10.0.0.1
    gen_config.src_ip_base = (192 << 24) | (168 << 16);
    gen_config.dst_ip_base = (10 << 24) | (0 << 16) | (0 << 8) | 1;

    // Initialize port
    if (port_init(portid, gen_config.mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", portid);

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n=== Realistic Baseline Traffic Generator ===\n");
    printf("Base Rate:         %u pps (%.2f Kpps)\n",
           gen_config.base_rate_pps, gen_config.base_rate_pps / 1e3);
    printf("Rate Range:        %u - %u pps\n", MIN_RATE_PPS, MAX_RATE_PPS);
    printf("Profile:           %s\n",
           gen_config.profile == TRAFFIC_PROFILE_VARIABLE ? "VARIABLE (realistic)" : "STATIC");
    printf("Variations:        %s\n", gen_config.enable_variations ? "ENABLED" : "DISABLED");
    printf("Worker Cores:      %u\n", rte_lcore_count() - 1);
    printf("HTTP Templates:    %d (weighted distribution)\n", NUM_HTTP_TEMPLATES);
    printf("Press Ctrl+C to stop...\n\n");

    // Launch traffic generation on all worker cores
    rte_eal_mp_remote_launch(lcore_baseline_traffic, NULL, SKIP_MASTER);

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
