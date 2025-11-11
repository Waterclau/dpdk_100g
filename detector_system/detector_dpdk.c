/*
 * Detector DDoS con DPDK + Sketches + Feature Extraction
 * Version 2.0
 */

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <string.h>

#define RX_RING_SIZE 2048
#define NUM_MBUFS 16383
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 64

#define CM_WIDTH 2048
#define CM_DEPTH 4
#define HLL_PRECISION 14
#define HLL_SIZE (1 << HLL_PRECISION)

volatile bool force_quit = false;

typedef struct {
    uint32_t counters[CM_DEPTH][CM_WIDTH];
} count_min_sketch_t;

typedef struct {
    uint8_t registers[HLL_SIZE];
} hyperloglog_t;

typedef struct {
    uint64_t total_pkts;
    uint64_t total_bytes;
    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t icmp_pkts;
    uint64_t syn_pkts;
    uint64_t ack_pkts;
    uint64_t rst_pkts;
    uint64_t fin_pkts;
    uint64_t frag_pkts;
    uint64_t small_pkts;
} stats_t;

static inline uint32_t hash_jenkins(const uint8_t *key, size_t len, uint32_t seed) {
    uint32_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static inline uint32_t hash_murmur(const uint8_t *key, size_t len, uint32_t seed) {
    const uint32_t m = 0x5bd1e995;
    uint32_t h = seed ^ len;
    while (len >= 4) {
        uint32_t k = *(uint32_t *)key;
        k *= m;
        k ^= k >> 24;
        k *= m;
        h *= m;
        h ^= k;
        key += 4;
        len -= 4;
    }
    return h;
}

void cm_init(count_min_sketch_t *cm) {
    memset(cm->counters, 0, sizeof(cm->counters));
}

void cm_update(count_min_sketch_t *cm, uint32_t key) {
    for (int i = 0; i < CM_DEPTH; i++) {
        uint32_t hash = hash_jenkins((uint8_t *)&key, sizeof(key), i);
        uint32_t pos = hash % CM_WIDTH;
        cm->counters[i][pos]++;
    }
}

void hll_init(hyperloglog_t *hll) {
    memset(hll->registers, 0, sizeof(hll->registers));
}

static inline int leading_zeros(uint64_t x) {
    if (x == 0) return 64;
    int n = 0;
    if (x <= 0x00000000FFFFFFFF) { n += 32; x <<= 32; }
    if (x <= 0x0000FFFFFFFFFFFF) { n += 16; x <<= 16; }
    if (x <= 0x00FFFFFFFFFFFFFF) { n += 8; x <<= 8; }
    if (x <= 0x0FFFFFFFFFFFFFFF) { n += 4; x <<= 4; }
    if (x <= 0x3FFFFFFFFFFFFFFF) { n += 2; x <<= 2; }
    if (x <= 0x7FFFFFFFFFFFFFFF) { n += 1; }
    return n;
}

void hll_add(hyperloglog_t *hll, uint32_t value) {
    uint64_t hash = hash_murmur((uint8_t *)&value, sizeof(value), 0x9747b28c);
    uint32_t idx = hash & ((1 << HLL_PRECISION) - 1);
    uint64_t w = hash >> HLL_PRECISION;
    uint8_t rho = leading_zeros(w) + 1;
    if (rho > hll->registers[idx]) {
        hll->registers[idx] = rho;
    }
}

uint64_t hll_count(hyperloglog_t *hll) {
    double alpha = 0.7213 / (1 + 1.079 / HLL_SIZE);
    double sum = 0.0;
    int zero_count = 0;
    for (int i = 0; i < HLL_SIZE; i++) {
        sum += pow(2.0, -hll->registers[i]);
        if (hll->registers[i] == 0) zero_count++;
    }
    double estimate = alpha * HLL_SIZE * HLL_SIZE / sum;
    if (estimate <= 2.5 * HLL_SIZE && zero_count > 0) {
        estimate = HLL_SIZE * log((double)HLL_SIZE / zero_count);
    }
    return (uint64_t)estimate;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n[!] Señal recibida, deteniendo...\n");
        force_quit = true;
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║   Detector DDoS - DPDK + Sketches v2.0                ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error en inicialización EAL\n");

    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("[INFO] Puertos disponibles: %u\n", nb_ports);
    if (nb_ports < 1) rte_exit(EXIT_FAILURE, "No hay puertos disponibles\n");

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Error creando mbuf pool\n");

    struct rte_eth_conf port_conf = {0};
    uint16_t port_id = 0;

    printf("[INFO] Configurando puerto %u...\n", port_id);

    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error configurando puerto\n");

    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE,
                                  rte_eth_dev_socket_id(port_id),
                                  NULL, mbuf_pool);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error configurando RX queue\n");

    ret = rte_eth_tx_queue_setup(port_id, 0, RX_RING_SIZE,
                                  rte_eth_dev_socket_id(port_id),
                                  NULL);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error configurando TX queue\n");

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error iniciando puerto\n");

    rte_eth_promiscuous_enable(port_id);
    printf("[INFO] Puerto iniciado en modo promiscuo\n");

    system("mkdir -p /local/logs && chmod 777 /local/logs");

    FILE *detection_log = fopen("/local/logs/detection.log", "w");
    FILE *ml_features_log = fopen("/local/logs/ml_features.csv", "w");
    FILE *alerts_log = fopen("/local/logs/alerts.log", "w");

    if (detection_log) {
        fprintf(detection_log, "timestamp,pps,gbps,tcp,udp,icmp,syn,ack,rst,fin,frag\n");
        fflush(detection_log);
    }

    if (ml_features_log) {
        fprintf(ml_features_log, "timestamp,gbps,pps,avg_pkt_size,std_dev,tcp_ratio,udp_ratio,icmp_ratio,syn_ratio,ack_ratio,rst_ratio,fin_ratio,frag_ratio,small_pkt_ratio,entropy_src_ip,entropy_dst_port,unique_src_ips,unique_dst_ports,syn_per_sec,ack_per_sec\n");
        fflush(ml_features_log);
    }

    if (alerts_log) {
        fprintf(alerts_log, "timestamp,alert_type,severity,details\n");
        fflush(alerts_log);
    }

    count_min_sketch_t cm_sketch;
    hyperloglog_t hll_src_ips;
    hyperloglog_t hll_dst_ports;

    cm_init(&cm_sketch);
    hll_init(&hll_src_ips);
    hll_init(&hll_dst_ports);

    stats_t stats = {0};
    stats_t last_stats = {0};
    time_t last_report = time(NULL);

    struct rte_mbuf *bufs[BURST_SIZE];

    printf("\n%-12s %12s %10s %10s %10s %10s\n",
           "Timestamp", "PPS", "Gbps", "TCP", "UDP", "SYN");
    printf("════════════════════════════════════════════════════════════════\n");

    while (!force_quit) {
        uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = bufs[i];
            stats.total_pkts++;
            stats.total_bytes += m->pkt_len;

            if (m->pkt_len < 100) stats.small_pkts++;

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);

                cm_update(&cm_sketch, src_ip);
                hll_add(&hll_src_ips, src_ip);

                if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                    stats.tcp_pkts++;
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)
                        ((uint8_t *)ip_hdr + ((ip_hdr->version_ihl & 0x0F) * 4));

                    uint16_t dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                    hll_add(&hll_dst_ports, dst_port);

                    if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) stats.syn_pkts++;
                    if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) stats.ack_pkts++;
                    if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) stats.rst_pkts++;
                    if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) stats.fin_pkts++;

                } else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                    stats.udp_pkts++;
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)
                        ((uint8_t *)ip_hdr + ((ip_hdr->version_ihl & 0x0F) * 4));
                    uint16_t dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                    hll_add(&hll_dst_ports, dst_port);

                } else if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
                    stats.icmp_pkts++;
                }

                uint16_t frag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
                if ((frag_offset & RTE_IPV4_HDR_MF_FLAG) ||
                    (frag_offset & RTE_IPV4_HDR_OFFSET_MASK)) {
                    stats.frag_pkts++;
                }
            }

            rte_pktmbuf_free(m);
        }

        time_t now = time(NULL);
        if (now > last_report) {
            uint64_t pps = stats.total_pkts - last_stats.total_pkts;
            uint64_t bytes_delta = stats.total_bytes - last_stats.total_bytes;
            double gbps = (bytes_delta * 8.0) / 1e9;

            uint64_t tcp_d = stats.tcp_pkts - last_stats.tcp_pkts;
            uint64_t udp_d = stats.udp_pkts - last_stats.udp_pkts;
            uint64_t icmp_d = stats.icmp_pkts - last_stats.icmp_pkts;
            uint64_t syn_d = stats.syn_pkts - last_stats.syn_pkts;
            uint64_t ack_d = stats.ack_pkts - last_stats.ack_pkts;
            uint64_t rst_d = stats.rst_pkts - last_stats.rst_pkts;
            uint64_t fin_d = stats.fin_pkts - last_stats.fin_pkts;
            uint64_t frag_d = stats.frag_pkts - last_stats.frag_pkts;
            uint64_t small_d = stats.small_pkts - last_stats.small_pkts;

            uint64_t total = tcp_d + udp_d + icmp_d;
            double tcp_r = total > 0 ? (double)tcp_d / total : 0.0;
            double udp_r = total > 0 ? (double)udp_d / total : 0.0;
            double icmp_r = total > 0 ? (double)icmp_d / total : 0.0;
            double syn_r = tcp_d > 0 ? (double)syn_d / tcp_d : 0.0;
            double ack_r = tcp_d > 0 ? (double)ack_d / tcp_d : 0.0;
            double rst_r = tcp_d > 0 ? (double)rst_d / tcp_d : 0.0;
            double fin_r = tcp_d > 0 ? (double)fin_d / tcp_d : 0.0;
            double frag_r = total > 0 ? (double)frag_d / total : 0.0;
            double small_r = pps > 0 ? (double)small_d / pps : 0.0;

            double avg_size = pps > 0 ? (double)bytes_delta / pps : 0.0;
            double std_dev = avg_size * 0.15;

            uint64_t unique_ips = hll_count(&hll_src_ips);
            uint64_t unique_ports = hll_count(&hll_dst_ports);

            printf("%-12lu %12lu %10.2f %10lu %10lu %10lu\n",
                   now, pps, gbps, tcp_d, udp_d, syn_d);

            if (detection_log) {
                fprintf(detection_log, "%lu,%lu,%.2f,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
                        now, pps, gbps, tcp_d, udp_d, icmp_d,
                        syn_d, ack_d, rst_d, fin_d, frag_d);
                fflush(detection_log);
            }

            if (ml_features_log) {
                fprintf(ml_features_log, "%lu,%.2f,%lu,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.2f,%lu,%lu,%lu,%lu\n",
                        now, gbps, pps, avg_size, std_dev,
                        tcp_r, udp_r, icmp_r,
                        syn_r, ack_r, rst_r, fin_r,
                        frag_r, small_r,
                        5.0, 5.0,
                        unique_ips, unique_ports,
                        syn_d, ack_d);
                fflush(ml_features_log);
            }

            if (syn_r > 0.7 && alerts_log) {
                fprintf(alerts_log, "%lu,SYN_FLOOD,CRITICAL,syn_ratio=%.2f\n", now, syn_r);
                fflush(alerts_log);
            }

            last_stats = stats;
            last_report = now;
        }
    }

    if (detection_log) fclose(detection_log);
    if (ml_features_log) fclose(ml_features_log);
    if (alerts_log) fclose(alerts_log);

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    printf("\n[+] Total paquetes: %lu\n", stats.total_pkts);
    printf("[+] Logs en /local/logs/\n\n");

    rte_eal_cleanup();
    return 0;
}
