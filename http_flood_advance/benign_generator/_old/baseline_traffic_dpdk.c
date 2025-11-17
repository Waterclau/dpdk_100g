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
#define NUM_MBUFS 262144      // Increased: 256K mbufs to prevent exhaustion
#define MBUF_CACHE_SIZE 512   // Increased cache per core
#define BURST_SIZE 32         // Smaller bursts for realistic traffic
#define MBUF_REFILL_THRESHOLD 1000  // Warn if free mbufs below this

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
    uint64_t alloc_failed;     // Track allocation failures
    uint64_t sessions_created;
    double current_rate_pps;
    double current_rate_mbps;
    double avg_think_time_ms;
} __rte_cache_aligned;

static volatile bool force_quit = false;
static volatile bool port_ready = false;  // Signal when port is ready
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
        // Disable offloads initially to avoid Mellanox issues
        .offloads = 0,
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

/* Calculate TCP checksum */
static uint16_t calc_tcp_checksum(struct rte_ipv4_hdr *ipv4_hdr,
                                   struct rte_tcp_hdr *tcp_hdr,
                                   uint16_t tcp_len)
{
    uint32_t sum = 0;
    uint8_t *bytes = (uint8_t *)tcp_hdr;
    uint16_t val;
    int i;

    // Pseudo header
    sum += (ipv4_hdr->src_addr >> 16) & 0xFFFF;
    sum += ipv4_hdr->src_addr & 0xFFFF;
    sum += (ipv4_hdr->dst_addr >> 16) & 0xFFFF;
    sum += ipv4_hdr->dst_addr & 0xFFFF;
    sum += rte_cpu_to_be_16(IPPROTO_TCP);
    sum += rte_cpu_to_be_16(tcp_len);

    // TCP header and data - use byte access to avoid alignment issues
    tcp_hdr->cksum = 0;
    for (i = 0; i < tcp_len - 1; i += 2) {
        val = (bytes[i] << 8) | bytes[i + 1];
        sum += val;
    }

    // Handle odd length
    if (tcp_len & 1) {
        sum += bytes[tcp_len - 1] << 8;
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
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
    tcp_hdr->cksum = 0;
    tcp_hdr->tcp_urp = 0;

    // HTTP payload
    payload = (uint8_t *)(tcp_hdr + 1);
    memcpy(payload, http_template, http_len);

    // Calculate TCP checksum manually (since offload is disabled)
    uint16_t tcp_len = sizeof(struct rte_tcp_hdr) + http_len;
    tcp_hdr->cksum = calc_tcp_checksum(ipv4_hdr, tcp_hdr, tcp_len);

    // Set packet length
    mbuf->data_len = sizeof(struct rte_ether_hdr) +
                     sizeof(struct rte_ipv4_hdr) +
                     sizeof(struct rte_tcp_hdr) + http_len;
    mbuf->pkt_len = mbuf->data_len;

    // No offload flags needed (software checksums calculated above)
    mbuf->ol_flags = 0;
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
    uint32_t consecutive_alloc_fails = 0;

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

    // Wait for port to be ready before starting traffic
    printf("Core %u: Waiting for port to be ready...\n", lcore_id);
    while (!port_ready && !force_quit) {
        usleep(100000);  // 100ms
    }

    if (force_quit) {
        printf("Core %u: Quit signaled before start\n", lcore_id);
        return 0;
    }

    printf("Core %u: Port ready, starting traffic generation\n", lcore_id);

    // Verify port is actually started
    struct rte_eth_dev_info dev_info;
    if (rte_eth_dev_info_get(gen_config.port_id, &dev_info) == 0) {
        printf("Core %u: Port device info retrieved\n", lcore_id);
    }

    // Small initial delay per core to stagger startup
    usleep(lcore_id * 100000);  // lcore_id * 100ms

    printf("Core %u: Beginning packet transmission\n", lcore_id);
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

            // Ensure at least 1 packet
            if (actual_burst < 1) actual_burst = 1;

            // Generate packets with improved error handling
            int generated = 0;
            for (int i = 0; i < actual_burst; i++) {
                bufs[i] = generate_baseline_packet(gen_config.mbuf_pool, seq_num++);
                if (bufs[i] == NULL) {
                    // Allocation failed - stop generating this burst
                    stats[lcore_id].alloc_failed++;
                    consecutive_alloc_fails++;

                    // If too many consecutive failures, pause briefly
                    if (consecutive_alloc_fails > 10) {
                        rte_delay_us_block(1000); // 1ms pause
                        if (consecutive_alloc_fails > 100) {
                            printf("Core %u: Critical - sustained mbuf allocation failures!\n", lcore_id);
                            rte_delay_us_block(10000); // 10ms pause
                        }
                    }
                    break;
                }
                generated++;
            }

            // Update actual burst size to number of successfully generated packets
            actual_burst = generated;

            // Only send if we generated packets
            if (actual_burst > 0) {
                // Reset consecutive failure counter on success
                consecutive_alloc_fails = 0;

                // Send burst - wrap in error detection
                uint16_t nb_tx = 0;

                // Try to send with error checking
                nb_tx = rte_eth_tx_burst(gen_config.port_id, 0, bufs, actual_burst);

                // Check if transmission failed completely
                if (nb_tx == 0 && actual_burst > 0) {
                    // All packets failed to send - this might indicate QP error
                    static uint64_t tx_fail_count = 0;
                    tx_fail_count++;

                    if (tx_fail_count < 10) {
                        printf("Core %u: WARNING - TX burst returned 0 (attempt %lu)\n",
                               lcore_id, tx_fail_count);
                    }

                    if (tx_fail_count >= 100) {
                        printf("Core %u: CRITICAL - Sustained TX failures, stopping\n", lcore_id);
                        // Free all packets and stop
                        for (int i = 0; i < actual_burst; i++) {
                            rte_pktmbuf_free(bufs[i]);
                        }
                        force_quit = true;
                        break;
                    }
                }

                // Update statistics
                stats[lcore_id].tx_packets += nb_tx;
                for (int i = 0; i < nb_tx; i++) {
                    stats[lcore_id].tx_bytes += bufs[i]->pkt_len;
                }

                // CRITICAL: Free unsent packets to return mbufs to pool
                if (unlikely(nb_tx < actual_burst)) {
                    stats[lcore_id].tx_dropped += (actual_burst - nb_tx);
                    for (int i = nb_tx; i < actual_burst; i++) {
                        rte_pktmbuf_free(bufs[i]);
                    }
                }
            }

            burst_count++;
            prev_tsc = cur_tsc;

            // Realistic think time - occasionally pause briefly
            if (burst_count % 100 == 0) {
                // Small delay every 100 bursts (~10-100 microseconds)
                rte_delay_us_block(10 + (rand() % 90));
            }

            // Check mempool health periodically
            if (burst_count % 1000 == 0) {
                unsigned available = rte_mempool_avail_count(gen_config.mbuf_pool);
                unsigned in_use = rte_mempool_in_use_count(gen_config.mbuf_pool);

                if (available < MBUF_REFILL_THRESHOLD) {
                    printf("Core %u WARNING: Low mbuf count! Available=%u, InUse=%u\n",
                           lcore_id, available, in_use);
                }
            }
        }
    }

    printf("Core %u: Stopping. Sent %lu packets (%lu bytes), Alloc Failures: %lu\n",
           lcore_id, stats[lcore_id].tx_packets, stats[lcore_id].tx_bytes,
           stats[lcore_id].alloc_failed);

    return 0;
}

/* Print statistics with baseline metrics */
static void print_stats(void)
{
    uint64_t total_tx_packets = 0;
    uint64_t total_tx_bytes = 0;
    uint64_t total_dropped = 0;
    uint64_t total_alloc_failed = 0;
    static uint64_t prev_packets = 0;
    static uint64_t prev_bytes = 0;
    static uint64_t prev_tsc = 0;

    // Sum statistics from all cores
    for (int i = 0; i < RTE_MAX_LCORE; i++) {
        total_tx_packets += stats[i].tx_packets;
        total_tx_bytes += stats[i].tx_bytes;
        total_dropped += stats[i].tx_dropped;
        total_alloc_failed += stats[i].alloc_failed;
    }

    // Get mempool statistics
    unsigned mbuf_available = rte_mempool_avail_count(gen_config.mbuf_pool);
    unsigned mbuf_in_use = rte_mempool_in_use_count(gen_config.mbuf_pool);

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
        printf("Alloc Failed:   %20lu\n", total_alloc_failed);
        printf("Current Rate:   %20.2f pps (%.2f Kpps)\n", pps, pps / 1e3);
        printf("Throughput:     %20.2f Mbps (%.3f Gbps)\n", mbps, mbps / 1e3);
        printf("Avg Packet:     %20.2f bytes\n",
               pkt_diff > 0 ? (double)byte_diff / pkt_diff : 0);
        printf("Base Rate:      %20u pps\n", gen_config.base_rate_pps);
        printf("Mempool:        %u available, %u in use\n", mbuf_available, mbuf_in_use);
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
    struct rte_eth_link link;

    if (!rte_eth_dev_is_valid_port(port)) {
        printf("Port %u is not valid\n", port);
        return -1;
    }

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info: %s\n", strerror(-retval));
        return retval;
    }

    printf("Configuring port %u...\n", port);
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        printf("Error configuring port %u: %s\n", port, strerror(-retval));
        return retval;
    }

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        printf("Error adjusting descriptors: %s\n", strerror(-retval));
        return retval;
    }

    printf("Setting up RX queue (descriptors: %u)...\n", nb_rxd);
    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd,
                                     rte_eth_dev_socket_id(port),
                                     NULL, mbuf_pool);
    if (retval < 0) {
        printf("Error setting up RX queue: %s\n", strerror(-retval));
        return retval;
    }

    printf("Setting up TX queue (descriptors: %u)...\n", nb_txd);

    // For Mellanox NICs: Use minimal configuration to avoid QP issues
    memset(&txconf, 0, sizeof(txconf));
    txconf.tx_thresh.pthresh = 0;
    txconf.tx_thresh.hthresh = 0;
    txconf.tx_thresh.wthresh = 0;
    txconf.tx_rs_thresh = 0;
    txconf.tx_free_thresh = 0;
    txconf.offloads = 0;  // No offloads

    retval = rte_eth_tx_queue_setup(port, 0, nb_txd,
                                     rte_eth_dev_socket_id(port),
                                     &txconf);
    if (retval < 0) {
        printf("Error setting up TX queue: %s\n", strerror(-retval));
        return retval;
    }
    printf("TX queue configured successfully\n");

    printf("Starting port %u...\n", port);
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        printf("Error starting port %u: %s\n", port, strerror(-retval));
        return retval;
    }
    printf("Port %u started successfully\n", port);

    // Give the port time to initialize (critical for Mellanox)
    printf("Waiting for port initialization...\n");
    usleep(1000000);  // 1 second using usleep instead of rte_delay_ms
    printf("Initialization delay complete\n");

    // Wait for link to come up
    printf("Checking link status...\n");
    int wait_count = 0;
    memset(&link, 0, sizeof(link));

    do {
        printf("Attempt %d to get link status...\n", wait_count + 1);
        retval = rte_eth_link_get_nowait(port, &link);
        if (retval < 0) {
            printf("Error getting link info: %s\n", strerror(-retval));
            return retval;
        }

        printf("Link status: %s\n", link.link_status == ETH_LINK_UP ? "UP" : "DOWN");

        if (link.link_status == ETH_LINK_UP) {
            printf("Link is UP - Speed: %u Mbps, Duplex: %s\n",
                   link.link_speed,
                   link.link_duplex == ETH_LINK_FULL_DUPLEX ? "Full" : "Half");
            break;
        }

        usleep(100000);  // 100ms
        wait_count++;

        if (wait_count > 50) {  // 5 seconds timeout
            printf("WARNING: Link still DOWN after 5 seconds, continuing anyway...\n");
            break;
        }
    } while (link.link_status == ETH_LINK_DOWN);

    printf("Link check complete\n");

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) {
        printf("Warning: Cannot enable promiscuous mode: %s\n", strerror(-retval));
        // Don't return error - continue anyway
    }

    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0) {
        printf("Error getting MAC address: %s\n", strerror(-retval));
        return retval;
    }

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

    // Find first usable port (skip ports that fail link check)
    uint16_t first_port = RTE_MAX_ETHPORTS;
    uint16_t port_id;

    RTE_ETH_FOREACH_DEV(port_id) {
        // Try to get link status (this will fail if port can't be used)
        struct rte_eth_dev_info dev_info;
        ret = rte_eth_dev_info_get(port_id, &dev_info);
        if (ret == 0) {
            first_port = port_id;
            printf("Using port %u\n", first_port);
            break;
        }
    }

    if (first_port == RTE_MAX_ETHPORTS) {
        // Fallback to port 0
        first_port = 0;
        printf("Warning: Using default port 0\n");
    }

    portid = first_port;
    gen_config.port_id = portid;

    // Create mbuf pool with sufficient size to prevent exhaustion
    // Calculate optimal size based on cores and burst size
    uint32_t nb_workers = rte_lcore_count() - 1;
    if (nb_workers == 0) nb_workers = 1;

    // Ensure we have enough mbufs: NUM_MBUFS should handle all cores bursting
    uint32_t optimal_mbufs = NUM_MBUFS;
    printf("Creating mbuf pool with %u mbufs for %u worker cores\n",
           optimal_mbufs, nb_workers);

    gen_config.mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", optimal_mbufs,
                                                    MBUF_CACHE_SIZE, 0,
                                                    RTE_MBUF_DEFAULT_BUF_SIZE,
                                                    rte_socket_id());
    if (gen_config.mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
                 rte_strerror(rte_errno));

    printf("Mbuf pool created successfully: %u available\n",
           rte_mempool_avail_count(gen_config.mbuf_pool));

    // Initialize configuration with realistic baseline values
    // port_id already set above
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

    // Get port MAC address
    struct rte_ether_addr port_mac;
    rte_eth_macaddr_get(portid, &port_mac);

    printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           portid,
           port_mac.addr_bytes[0], port_mac.addr_bytes[1],
           port_mac.addr_bytes[2], port_mac.addr_bytes[3],
           port_mac.addr_bytes[4], port_mac.addr_bytes[5]);

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n=== Realistic Baseline Traffic Generator ===\n");
    printf("Using Port:        %u\n", portid);
    printf("Base Rate:         %u pps (%.2f Kpps)\n",
           gen_config.base_rate_pps, gen_config.base_rate_pps / 1e3);
    printf("Rate Range:        %u - %u pps\n", MIN_RATE_PPS, MAX_RATE_PPS);
    printf("Profile:           %s\n",
           gen_config.profile == TRAFFIC_PROFILE_VARIABLE ? "VARIABLE (realistic)" : "STATIC");
    printf("Variations:        %s\n", gen_config.enable_variations ? "ENABLED" : "DISABLED");
    printf("Worker Cores:      %u\n", rte_lcore_count() - 1);
    printf("HTTP Templates:    %d (weighted distribution)\n", NUM_HTTP_TEMPLATES);
    printf("Press Ctrl+C to stop...\n\n");

    // Warm-up: Send a test packet to initialize the TX queue properly
    printf("Warming up TX queue...\n");
    struct rte_mbuf *test_pkt = generate_baseline_packet(gen_config.mbuf_pool, 0);
    if (test_pkt != NULL) {
        uint16_t sent = rte_eth_tx_burst(portid, 0, &test_pkt, 1);
        if (sent == 0) {
            printf("Warning: Warm-up packet failed to send\n");
            rte_pktmbuf_free(test_pkt);
        } else {
            printf("Warm-up successful - TX queue is operational\n");
        }
    }

    // Additional stabilization delay
    usleep(500000);  // 500ms

    // Launch traffic generation on all worker cores
    rte_eal_mp_remote_launch(lcore_baseline_traffic, NULL, SKIP_MASTER);

    // Give worker cores time to initialize and port to stabilize
    printf("Waiting for worker cores to initialize...\n");
    sleep(1);

    // Additional wait for Mellanox port to be fully ready
    printf("Waiting for port to be fully operational...\n");
    sleep(2);

    // Signal that port is ready for traffic
    printf("Signaling port ready for traffic...\n");
    port_ready = true;
    rte_mb();  // Memory barrier to ensure visibility

    // Additional delay to ensure all cores see the signal
    usleep(500000);  // 500ms

    printf("Traffic generation started!\n\n");

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
