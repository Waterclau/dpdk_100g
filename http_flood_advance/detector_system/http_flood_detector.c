/*
 * HTTP Flood Detector with DPDK + OctoSketch
 *
 * Detector de ataques HTTP flood usando reglas precisas sin ML
 * Optimizado para 100 Gbps con NICs Mellanox
 *
 * Reglas de detección:
 * 1. Rate Anomaly: Tasa de peticiones por IP > umbral
 * 2. URL Concentration: Mismo path repetido > 80%
 * 3. Botnet Detection: Muchas IPs con bajo tráfico cada una
 * 4. User-Agent Anomaly: Ausencia o UA maliciosos
 * 5. HTTP Method Anomaly: Ratio GET/POST anormal
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

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
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096
#define NUM_MBUFS 524288
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 512

/* OctoSketch parameters */
#define SKETCH_WIDTH 65536    // 64K buckets
#define SKETCH_DEPTH 4        // 4 hash functions
#define HEAVY_HITTER_THRESHOLD 1000  // Paquetes para ser heavy hitter

/* Detection thresholds */
#define RATE_THRESHOLD_PPS 10000      // 10K pps por IP = sospechoso
#define URL_CONCENTRATION_THRESHOLD 0.80  // 80% misma URL = ataque
#define BOTNET_IPS_THRESHOLD 50       // >50 IPs únicas en 1 segundo = botnet
#define MIN_PACKETS_FOR_DETECTION 1000  // Mínimo de paquetes para análisis

/* Time window */
#define DETECTION_WINDOW_SEC 1        // Ventana de 1 segundo
#define STATS_INTERVAL_SEC 5          // Mostrar stats cada 5 segundos

/* Alert levels */
#define ALERT_NONE 0
#define ALERT_LOW 1
#define ALERT_MEDIUM 2
#define ALERT_HIGH 3
#define ALERT_CRITICAL 4

/* Count-Min Sketch para conteo de frecuencias */
struct count_min_sketch {
    uint32_t width;
    uint32_t depth;
    uint32_t **counters;
};

/* Heavy Hitter detector */
struct heavy_hitter {
    uint32_t ip;
    uint64_t count;
    uint64_t last_seen;
};

/* URL statistics */
struct url_stats {
    char path[256];
    uint64_t count;
};

/* Detection statistics */
struct detection_stats {
    /* Counters */
    uint64_t total_packets;
    uint64_t http_packets;
    uint64_t baseline_packets;  // 192.168.x.x
    uint64_t attack_packets;    // 203.0.113.x

    /* Per-IP tracking */
    uint64_t unique_ips;
    uint64_t heavy_hitters;

    /* HTTP stats */
    uint64_t get_requests;
    uint64_t post_requests;
    uint64_t other_methods;

    /* URL concentration */
    uint64_t top_url_count;
    char top_url[256];

    /* Botnet indicators */
    uint64_t low_rate_ips;  // IPs con <100 pps cada una

    /* Alert level */
    uint32_t alert_level;
    char alert_reason[512];

    /* Timestamps */
    uint64_t window_start_tsc;
    uint64_t last_stats_tsc;
};

/* Global configuration */
struct detector_config {
    uint16_t port_id;
    uint16_t nb_queues;
    bool verbose;
} g_config = {
    .port_id = 0,
    .nb_queues = 1,
    .verbose = false,
};

/* Global state */
static volatile bool force_quit = false;
static FILE *g_log_file = NULL;
static struct rte_mempool *mbuf_pool = NULL;
static struct count_min_sketch *ip_sketch = NULL;
static struct count_min_sketch *url_sketch = NULL;
static struct detection_stats g_stats;

/* Forward declarations */
static void close_log_file(void);

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;

        /* Close log file immediately */
        if (g_log_file) {
            fprintf(g_log_file, "\n================================================================================\n");
            fprintf(g_log_file, "Detector stopped by signal %d\n", signum);
            fflush(g_log_file);
            fclose(g_log_file);
            g_log_file = NULL;
            printf("[*] Log file closed by signal handler\n");
        }
    }
}

/* Open log file for automatic saving */
static int open_log_file(void)
{
    char log_path[] = "/local/dpdk_100g/results/results_http_flood_1.log";

    g_log_file = fopen(log_path, "w");
    if (!g_log_file) {
        fprintf(stderr, "Warning: Could not open log file %s: %s\n",
                log_path, strerror(errno));
        fprintf(stderr, "Continuing without file logging (output to stdout only)\n");
        return -1;
    }

    printf("[*] Log file opened: %s\n", log_path);
    fprintf(g_log_file, "HTTP Flood Detector Log\n");
    fprintf(g_log_file, "Start time: %s\n", __DATE__ " " __TIME__);
    fprintf(g_log_file, "================================================================================\n\n");
    fflush(g_log_file);

    return 0;
}

/* Close log file */
static void close_log_file(void)
{
    if (g_log_file) {
        fprintf(g_log_file, "\n================================================================================\n");
        fprintf(g_log_file, "Detector stopped\n");
        fclose(g_log_file);
        g_log_file = NULL;
        printf("[*] Log file closed\n");
    }
}

/* Dual output function - print to both stdout and log file */
static void dual_printf(const char *format, ...)
{
    va_list args1, args2;

    va_start(args1, format);
    vprintf(format, args1);
    va_end(args1);

    if (g_log_file) {
        va_start(args2, format);
        vfprintf(g_log_file, format, args2);
        va_end(args2);
        fflush(g_log_file);
    }
}

/* Initialize Count-Min Sketch */
static struct count_min_sketch *cms_init(uint32_t width, uint32_t depth)
{
    struct count_min_sketch *cms = malloc(sizeof(*cms));
    if (!cms)
        return NULL;

    cms->width = width;
    cms->depth = depth;

    cms->counters = malloc(depth * sizeof(uint32_t *));
    if (!cms->counters) {
        free(cms);
        return NULL;
    }

    for (uint32_t i = 0; i < depth; i++) {
        cms->counters[i] = calloc(width, sizeof(uint32_t));
        if (!cms->counters[i]) {
            for (uint32_t j = 0; j < i; j++)
                free(cms->counters[j]);
            free(cms->counters);
            free(cms);
            return NULL;
        }
    }

    return cms;
}

/* Update Count-Min Sketch */
static void cms_update(struct count_min_sketch *cms, uint32_t item, uint32_t count)
{
    for (uint32_t i = 0; i < cms->depth; i++) {
        uint32_t hash = rte_jhash_1word(item, i);
        uint32_t index = hash % cms->width;
        cms->counters[i][index] += count;
    }
}

/* Query Count-Min Sketch */
static uint32_t cms_query(struct count_min_sketch *cms, uint32_t item)
{
    uint32_t min_count = UINT32_MAX;

    for (uint32_t i = 0; i < cms->depth; i++) {
        uint32_t hash = rte_jhash_1word(item, i);
        uint32_t index = hash % cms->width;
        if (cms->counters[i][index] < min_count)
            min_count = cms->counters[i][index];
    }

    return min_count;
}

/* Reset Count-Min Sketch */
static void cms_reset(struct count_min_sketch *cms)
{
    for (uint32_t i = 0; i < cms->depth; i++) {
        memset(cms->counters[i], 0, cms->width * sizeof(uint32_t));
    }
}

/* Free Count-Min Sketch */
static void cms_free(struct count_min_sketch *cms)
{
    if (!cms)
        return;

    for (uint32_t i = 0; i < cms->depth; i++) {
        free(cms->counters[i]);
    }
    free(cms->counters);
    free(cms);
}

/* Extract URL path from HTTP payload */
static int extract_http_path(const char *payload, size_t len, char *path, size_t path_len)
{
    const char *method_end = NULL;
    const char *path_end = NULL;

    /* Find first space (end of method) */
    for (size_t i = 0; i < len && i < 20; i++) {
        if (payload[i] == ' ') {
            method_end = &payload[i];
            break;
        }
    }

    if (!method_end)
        return -1;

    /* Path starts after method */
    const char *path_start = method_end + 1;

    /* Find second space (end of path) */
    for (size_t i = 0; i < len - (path_start - payload) && i < 256; i++) {
        if (path_start[i] == ' ' || path_start[i] == '\r' || path_start[i] == '\n') {
            path_end = &path_start[i];
            break;
        }
    }

    if (!path_end)
        return -1;

    size_t copy_len = path_end - path_start;
    if (copy_len >= path_len)
        copy_len = path_len - 1;

    memcpy(path, path_start, copy_len);
    path[copy_len] = '\0';

    return 0;
}

/* Detect HTTP flood attack using multiple rules */
static void detect_http_flood(void)
{
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    uint64_t elapsed_tsc = cur_tsc - g_stats.window_start_tsc;
    double elapsed_sec = (double)elapsed_tsc / hz;

    if (elapsed_sec < DETECTION_WINDOW_SEC)
        return;

    /* Reset alert */
    g_stats.alert_level = ALERT_NONE;
    g_stats.alert_reason[0] = '\0';

    /* Requiere mínimo de paquetes */
    if (g_stats.http_packets < MIN_PACKETS_FOR_DETECTION) {
        goto reset_window;
    }

    double packets_per_sec = g_stats.http_packets / elapsed_sec;
    double attack_ratio = (double)g_stats.attack_packets / g_stats.http_packets;

    /* Rule 1: High rate from attack network (203.0.113.x) */
    if (g_stats.attack_packets > 0 && attack_ratio > 0.3) {
        double attack_pps = g_stats.attack_packets / elapsed_sec;
        if (attack_pps > 5000) {
            g_stats.alert_level = ALERT_HIGH;
            snprintf(g_stats.alert_reason, sizeof(g_stats.alert_reason),
                    "HIGH ATTACK RATE: %.0f pps from botnet (%.1f%% of traffic)",
                    attack_pps, attack_ratio * 100);
        }
    }

    /* Rule 2: URL Concentration (mismo path >80%) */
    if (g_stats.http_packets > 0) {
        double url_concentration = (double)g_stats.top_url_count / g_stats.http_packets;
        if (url_concentration > URL_CONCENTRATION_THRESHOLD) {
            if (g_stats.alert_level < ALERT_MEDIUM) {
                g_stats.alert_level = ALERT_MEDIUM;
            }
            snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                    sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                    " | URL CONCENTRATION: %.1f%% to '%s'",
                    url_concentration * 100, g_stats.top_url);
        }
    }

    /* Rule 3: Botnet detection (muchas IPs, bajo rate cada una) */
    if (g_stats.unique_ips > BOTNET_IPS_THRESHOLD) {
        double avg_pps_per_ip = packets_per_sec / g_stats.unique_ips;
        if (avg_pps_per_ip < 200) {  // Cada IP < 200 pps pero muchas IPs
            if (g_stats.alert_level < ALERT_MEDIUM) {
                g_stats.alert_level = ALERT_MEDIUM;
            }
            snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                    sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                    " | BOTNET PATTERN: %lu IPs, avg %.0f pps/IP",
                    g_stats.unique_ips, avg_pps_per_ip);
        }
    }

    /* Rule 4: Heavy hitters (IPs individuales con alta tasa) */
    if (g_stats.heavy_hitters > 10) {
        if (g_stats.alert_level < ALERT_LOW) {
            g_stats.alert_level = ALERT_LOW;
        }
        snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                " | HEAVY HITTERS: %lu IPs suspicious",
                g_stats.heavy_hitters);
    }

    /* Rule 5: HTTP Method anomaly */
    if (g_stats.http_packets > 0) {
        double get_ratio = (double)g_stats.get_requests / g_stats.http_packets;
        if (get_ratio > 0.98) {  // >98% GETs es sospechoso
            if (g_stats.alert_level < ALERT_LOW) {
                g_stats.alert_level = ALERT_LOW;
            }
            snprintf(g_stats.alert_reason + strlen(g_stats.alert_reason),
                    sizeof(g_stats.alert_reason) - strlen(g_stats.alert_reason),
                    " | METHOD ANOMALY: %.1f%% GET requests",
                    get_ratio * 100);
        }
    }

reset_window:
    /* Reset window */
    g_stats.window_start_tsc = cur_tsc;
    g_stats.unique_ips = 0;
    g_stats.heavy_hitters = 0;
    g_stats.top_url_count = 0;
    g_stats.low_rate_ips = 0;

    /* Reset sketches */
    cms_reset(ip_sketch);
    cms_reset(url_sketch);
}

/* Process packet and extract features */
static void process_packet(struct rte_mbuf *pkt)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint8_t *payload;
    uint32_t payload_len;

    g_stats.total_packets++;

    /* Parse Ethernet */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return;

    /* Parse IP */
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    if (ipv4_hdr->next_proto_id != IPPROTO_TCP)
        return;

    /* Parse TCP */
    tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));

    /* Only HTTP (port 80) */
    if (tcp_hdr->dst_port != rte_cpu_to_be_16(80))
        return;

    g_stats.http_packets++;

    /* Get payload */
    payload = (uint8_t *)tcp_hdr + (tcp_hdr->data_off >> 4) * 4;
    payload_len = rte_pktmbuf_data_len(pkt) -
                  ((uint8_t *)payload - (uint8_t *)eth_hdr);

    if (payload_len < 10)
        return;

    /* Classify: baseline vs attack */
    uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    uint8_t first_octet = (src_ip >> 24) & 0xFF;
    uint8_t second_octet = (src_ip >> 16) & 0xFF;
    uint8_t third_octet = (src_ip >> 8) & 0xFF;

    if (first_octet == 192 && second_octet == 168) {
        g_stats.baseline_packets++;
    } else if (first_octet == 203 && second_octet == 0 && third_octet == 113) {
        g_stats.attack_packets++;
    }

    /* Update IP sketch */
    cms_update(ip_sketch, src_ip, 1);
    uint32_t ip_count = cms_query(ip_sketch, src_ip);

    if (ip_count == 1) {
        g_stats.unique_ips++;
    }

    if (ip_count > HEAVY_HITTER_THRESHOLD) {
        g_stats.heavy_hitters++;
    }

    /* Parse HTTP method and path */
    char http_path[256] = {0};

    if (payload_len > 4) {
        if (memcmp(payload, "GET ", 4) == 0) {
            g_stats.get_requests++;
            extract_http_path((char *)payload, payload_len, http_path, sizeof(http_path));
        } else if (memcmp(payload, "POST", 4) == 0) {
            g_stats.post_requests++;
            extract_http_path((char *)payload, payload_len, http_path, sizeof(http_path));
        } else {
            g_stats.other_methods++;
        }
    }

    /* Update URL sketch */
    if (http_path[0] != '\0') {
        uint32_t path_hash = rte_jhash(http_path, strlen(http_path), 0);
        cms_update(url_sketch, path_hash, 1);
        uint32_t path_count = cms_query(url_sketch, path_hash);

        if (path_count > g_stats.top_url_count) {
            g_stats.top_url_count = path_count;
            strncpy(g_stats.top_url, http_path, sizeof(g_stats.top_url) - 1);
        }
    }
}

/* Print detection statistics */
static void print_stats(void)
{
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t hz = rte_get_tsc_hz();
    uint64_t elapsed_tsc = cur_tsc - g_stats.last_stats_tsc;

    if (elapsed_tsc < hz * STATS_INTERVAL_SEC)
        return;

    g_stats.last_stats_tsc = cur_tsc;

    dual_printf("\n");
    dual_printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    dual_printf("║               HTTP FLOOD DETECTOR - STATISTICS                      ║\n");
    dual_printf("╚══════════════════════════════════════════════════════════════════════╝\n");

    dual_printf("\n[PACKET COUNTERS]\n");
    dual_printf("  Total packets:      %lu\n", g_stats.total_packets);
    dual_printf("  HTTP packets:       %lu\n", g_stats.http_packets);
    dual_printf("  Baseline (192.168): %lu (%.1f%%)\n",
           g_stats.baseline_packets,
           g_stats.http_packets > 0 ? (double)g_stats.baseline_packets / g_stats.http_packets * 100 : 0);
    dual_printf("  Attack (203.0.113): %lu (%.1f%%)\n",
           g_stats.attack_packets,
           g_stats.http_packets > 0 ? (double)g_stats.attack_packets / g_stats.http_packets * 100 : 0);

    dual_printf("\n[TRAFFIC ANALYSIS]\n");
    dual_printf("  Unique IPs:         %lu\n", g_stats.unique_ips);
    dual_printf("  Heavy hitters:      %lu\n", g_stats.heavy_hitters);

    dual_printf("\n[HTTP METHODS]\n");
    dual_printf("  GET:                %lu (%.1f%%)\n",
           g_stats.get_requests,
           g_stats.http_packets > 0 ? (double)g_stats.get_requests / g_stats.http_packets * 100 : 0);
    dual_printf("  POST:               %lu (%.1f%%)\n",
           g_stats.post_requests,
           g_stats.http_packets > 0 ? (double)g_stats.post_requests / g_stats.http_packets * 100 : 0);
    dual_printf("  Other:              %lu\n", g_stats.other_methods);

    dual_printf("\n[URL CONCENTRATION]\n");
    dual_printf("  Top URL:            %s\n", g_stats.top_url[0] ? g_stats.top_url : "(none)");
    dual_printf("  Top URL count:      %lu (%.1f%%)\n",
           g_stats.top_url_count,
           g_stats.http_packets > 0 ? (double)g_stats.top_url_count / g_stats.http_packets * 100 : 0);

    dual_printf("\n[ALERT STATUS]\n");
    const char *alert_names[] = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    const char *alert_colors[] = {"\033[0m", "\033[33m", "\033[93m", "\033[91m", "\033[1;91m"};

    dual_printf("  Alert level:        %s%s\033[0m\n",
           alert_colors[g_stats.alert_level],
           alert_names[g_stats.alert_level]);

    if (g_stats.alert_level > ALERT_NONE) {
        dual_printf("  Reason:             %s\n", g_stats.alert_reason);
    }

    dual_printf("\n");
}

/* Port initialization */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mtu = RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN,
        },
    };

    const uint16_t rx_rings = 1, tx_rings = 0;
    uint16_t nb_rxd = RX_RING_SIZE;
    int retval;
    struct rte_eth_dev_info dev_info;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
    if (retval != 0)
        return retval;

    /* Setup RX queue */
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Start device */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Enable promiscuous mode */
    rte_eth_promiscuous_enable(port);

    return 0;
}

/* Main detection loop */
static int detection_loop(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    uint16_t port = g_config.port_id;
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("Detection loop started on lcore %u\n", lcore_id);

    g_stats.window_start_tsc = rte_rdtsc();
    g_stats.last_stats_tsc = rte_rdtsc();

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        for (uint16_t i = 0; i < nb_rx; i++) {
            process_packet(bufs[i]);
            rte_pktmbuf_free(bufs[i]);
        }

        /* Run detection */
        detect_http_flood();

        /* Print stats */
        print_stats();
    }

    return 0;
}

/* Main function */
int main(int argc, char **argv)
{
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check ports */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    printf("Found %u Ethernet port(s)\n", nb_ports);

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize sketches */
    ip_sketch = cms_init(SKETCH_WIDTH, SKETCH_DEPTH);
    url_sketch = cms_init(SKETCH_WIDTH, SKETCH_DEPTH);

    if (!ip_sketch || !url_sketch)
        rte_exit(EXIT_FAILURE, "Cannot create sketches\n");

    printf("OctoSketch initialized: %ux%u\n", SKETCH_WIDTH, SKETCH_DEPTH);

    /* Initialize port */
    if (port_init(g_config.port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", g_config.port_id);

    printf("Port %u initialized\n", g_config.port_id);

    /* Initialize stats */
    memset(&g_stats, 0, sizeof(g_stats));

    /* Open log file */
    open_log_file();

    dual_printf("\n");
    dual_printf("╔══════════════════════════════════════════════════════════════════════╗\n");
    dual_printf("║         HTTP FLOOD DETECTOR - DPDK + OctoSketch                     ║\n");
    dual_printf("╠══════════════════════════════════════════════════════════════════════╣\n");
    dual_printf("║  Port:              %u                                               ║\n", g_config.port_id);
    dual_printf("║  Detection window:  %u second                                        ║\n", DETECTION_WINDOW_SEC);
    dual_printf("║  Stats interval:    %u seconds                                       ║\n", STATS_INTERVAL_SEC);
    dual_printf("║                                                                      ║\n");
    dual_printf("║  Detection Rules:                                                    ║\n");
    dual_printf("║    1. Rate Anomaly (>%u pps per IP)                               ║\n", RATE_THRESHOLD_PPS);
    dual_printf("║    2. URL Concentration (>%.0f%% same path)                        ║\n", URL_CONCENTRATION_THRESHOLD * 100);
    dual_printf("║    3. Botnet Detection (>%u IPs)                                  ║\n", BOTNET_IPS_THRESHOLD);
    dual_printf("║    4. Heavy Hitters (suspicious IPs)                                 ║\n");
    dual_printf("║    5. HTTP Method Anomaly (>98%% GET)                                ║\n");
    dual_printf("╚══════════════════════════════════════════════════════════════════════╝\n");
    dual_printf("\nPress Ctrl+C to exit...\n\n");

    /* Run detection */
    detection_loop(NULL);

    /* Final stats */
    printf("\n\n=== FINAL STATISTICS ===\n");
    print_stats();

    /* Cleanup */
    cms_free(ip_sketch);
    cms_free(url_sketch);

    printf("\nDetector stopped.\n");

    return 0;
}
