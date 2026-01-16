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
#include <dirent.h>
#include <libgen.h>

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
#define MAX_PCAP_PACKETS 50000000
#define MAX_PCAP_FILES 1024
#define MAX_PKT_LEN 4096

/* Target transmission rate for non-timed mode */
#define TARGET_GBPS 12.0

/* NEW: Multi-PCAP directory replay */
#define DEFAULT_PCAP_DIR "/proj/softmeasure-PG0/CICD/remapped/"

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

/* NEW: Attack phase definition for --adaptive-attack mode */
struct attack_phase {
    uint32_t duration_sec;   // Phase duration in seconds
    float syn_pct;           // SYN/ACK attack percentage (0.0-1.0)
    float udp_pct;           // UDP flood percentage
    float http_pct;          // HTTP flood percentage
    float dns_pct;           // DNS flood percentage
    float icmp_pct;          // ICMP/other percentage
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

/* NEW: Adaptive attack mode configuration */
struct adaptive_attack_config {
    uint8_t enabled;
    uint8_t loop_mode;                     // Loop indefinitely
    uint32_t duration_sec;                 // Total duration (0 = infinite)
    float target_gbps;                     // Target rate
    float jitter_pct;                      // PPS jitter
    struct attack_phase phases[MAX_PHASES];
    uint32_t num_phases;
};

static struct adaptive_attack_config attack_cfg = {
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

/* NEW: Attack packet classification for --adaptive-attack mode */
enum attack_type {
    ATTACK_SYN = 0,      // SYN/ACK packets
    ATTACK_UDP_FLOOD,    // UDP flood packets
    ATTACK_HTTP_FLOOD,   // HTTP flood packets
    ATTACK_DNS_FLOOD,    // DNS query flood packets
    ATTACK_ICMP_RANDOM,  // ICMP and other packets
    ATTACK_UNKNOWN,
    ATTACK_MAX
};

struct packet_data {
    uint8_t data[MAX_PKT_LEN];
    uint16_t len;
    struct timeval timestamp;      /* NEW: Store original PCAP timestamp */
    enum packet_protocol protocol; /* NEW: Protocol classification */
    enum attack_type attack_type;  /* NEW: Attack classification for --adaptive-attack */
};

static struct packet_data *pcap_packets = NULL;
static uint32_t num_pcap_packets = 0;
static uint32_t current_packet_idx = 0;

/* NEW: Multi-PCAP file management */
static char **pcap_file_list = NULL;
static uint32_t num_pcap_files = 0;
static uint32_t current_pcap_file_idx = 0;
static uint8_t multi_pcap_mode = 0;

/* NEW: Protocol-classified packet pools for adaptive mode */
static uint32_t *http_packets = NULL;   // Indices of HTTP packets
static uint32_t *dns_packets = NULL;    // Indices of DNS packets
static uint32_t *ssh_packets = NULL;    // Indices of SSH packets
static uint32_t *udp_packets = NULL;    // Indices of UDP/other packets
static uint32_t num_http = 0, num_dns = 0, num_ssh = 0, num_udp = 0;

/* NEW: Attack-classified packet pools for --adaptive-attack mode */
static uint32_t *syn_attack_packets = NULL;    // SYN/ACK attack packets
static uint32_t *udp_attack_packets = NULL;    // UDP flood packets
static uint32_t *http_attack_packets = NULL;   // HTTP flood packets
static uint32_t *dns_attack_packets = NULL;    // DNS query flood packets
static uint32_t *icmp_attack_packets = NULL;   // ICMP/other attack packets
static uint32_t num_syn_attack = 0, num_udp_attack = 0, num_http_attack = 0;
static uint32_t num_dns_attack = 0, num_icmp_attack = 0;

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

/* NEW: Classify packet by attack type for --adaptive-attack mode */
static enum attack_type classify_attack_packet(const uint8_t *data, uint16_t len)
{
    // Minimum Ethernet header size
    if (len < 14)
        return ATTACK_UNKNOWN;

    // Skip Ethernet header (14 bytes)
    const uint8_t *ip_hdr = data + 14;

    // Check if it's IPv4 (EtherType 0x0800)
    uint16_t ethertype = (data[12] << 8) | data[13];

    // Check for ICMP (EtherType 0x0800 with ICMP protocol)
    if (ethertype == 0x0800 && len >= 34) {
        uint8_t ip_proto = ip_hdr[9];

        // ICMP (protocol 1)
        if (ip_proto == 1)
            return ATTACK_ICMP_RANDOM;
    }

    if (ethertype != 0x0800 || len < 34)
        return ATTACK_UNKNOWN;

    // Get IP protocol field (byte 9 of IP header)
    uint8_t ip_proto = ip_hdr[9];

    // Get IP header length
    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    if (len < 14 + ihl + 4)
        return ATTACK_UNKNOWN;

    const uint8_t *transport_hdr = ip_hdr + ihl;

    // TCP (protocol 6) - Check for SYN/ACK flags
    if (ip_proto == 6) {
        if (len < 14 + ihl + 14)  // Need full TCP header
            return ATTACK_UNKNOWN;

        uint16_t src_port = (transport_hdr[0] << 8) | transport_hdr[1];
        uint16_t dst_port = (transport_hdr[2] << 8) | transport_hdr[3];
        uint8_t tcp_flags = transport_hdr[13];  // TCP flags byte

        uint8_t syn_flag = (tcp_flags & 0x02) >> 1;
        uint8_t ack_flag = (tcp_flags & 0x10) >> 4;

        // SYN or SYN-ACK packets (typical in SYN flood)
        if (syn_flag)
            return ATTACK_SYN;

        // HTTP flood (port 80, 443, 8080)
        if (src_port == 80 || dst_port == 80 ||
            src_port == 443 || dst_port == 443 ||
            src_port == 8080 || dst_port == 8080)
            return ATTACK_HTTP_FLOOD;

        // Other TCP with ACK (could be part of attack)
        if (ack_flag)
            return ATTACK_SYN;  // Classify ACK scans as SYN attack

        return ATTACK_UNKNOWN;
    }

    // UDP (protocol 17)
    if (ip_proto == 17) {
        uint16_t src_port = (transport_hdr[0] << 8) | transport_hdr[1];
        uint16_t dst_port = (transport_hdr[2] << 8) | transport_hdr[3];

        // DNS flood (port 53)
        if (src_port == 53 || dst_port == 53)
            return ATTACK_DNS_FLOOD;

        // UDP flood (any other UDP port)
        return ATTACK_UDP_FLOOD;
    }

    return ATTACK_UNKNOWN;
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

/* NEW: Parse attack phases JSON file for --adaptive-attack mode */
static int parse_attack_phases_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Error: Cannot open attack phases file: %s\n", filename);
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

    // Simple JSON parsing for attack phases
    // Format: [{"duration": 20, "syn": 0.60, "udp": 0.20, "http": 0.10, "dns": 0.10}, ...]

    char *ptr = content;
    attack_cfg.num_phases = 0;

    // Find opening bracket
    while (*ptr && *ptr != '[') ptr++;
    if (*ptr == '[') ptr++;

    // Parse each phase object
    while (*ptr && attack_cfg.num_phases < MAX_PHASES) {
        // Skip whitespace
        while (*ptr && isspace(*ptr)) ptr++;

        if (*ptr == ']' || *ptr == '\0') break;
        if (*ptr == ',') ptr++;

        // Skip to opening brace
        while (*ptr && *ptr != '{') ptr++;
        if (*ptr != '{') break;
        ptr++;

        struct attack_phase *phase = &attack_cfg.phases[attack_cfg.num_phases];
        phase->duration_sec = 20;  // Default
        phase->syn_pct = 0.0f;
        phase->udp_pct = 0.0f;
        phase->http_pct = 0.0f;
        phase->dns_pct = 0.0f;
        phase->icmp_pct = 0.0f;

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
                } else if (strcmp(key, "syn") == 0) {
                    phase->syn_pct = value;
                } else if (strcmp(key, "udp") == 0) {
                    phase->udp_pct = value;
                } else if (strcmp(key, "http") == 0) {
                    phase->http_pct = value;
                } else if (strcmp(key, "dns") == 0) {
                    phase->dns_pct = value;
                } else if (strcmp(key, "icmp") == 0) {
                    phase->icmp_pct = value;
                }
            } else {
                ptr++;
            }
        }

        if (*ptr == '}') ptr++;
        attack_cfg.num_phases++;
    }

    free(content);

    printf("\n[ADAPTIVE-ATTACK] Loaded %u attack phases from %s:\n", attack_cfg.num_phases, filename);
    for (uint32_t i = 0; i < attack_cfg.num_phases; i++) {
        struct attack_phase *p = &attack_cfg.phases[i];
        printf("  Phase %u: %us - SYN:%.0f%% UDP:%.0f%% HTTP:%.0f%% DNS:%.0f%% ICMP:%.0f%%\n",
               i+1, p->duration_sec,
               p->syn_pct*100, p->udp_pct*100, p->http_pct*100, p->dns_pct*100, p->icmp_pct*100);
    }
    printf("\n");

    return attack_cfg.num_phases > 0 ? 0 : -1;
}

/* NEW: Create default attack phases for --adaptive-attack mode */
static void create_default_attack_phases(void)
{
    // Phase 1: SYN Flood Dominance (60% SYN)
    attack_cfg.phases[0].duration_sec = 20;
    attack_cfg.phases[0].syn_pct = 0.60f;
    attack_cfg.phases[0].udp_pct = 0.20f;
    attack_cfg.phases[0].http_pct = 0.10f;
    attack_cfg.phases[0].dns_pct = 0.05f;
    attack_cfg.phases[0].icmp_pct = 0.05f;

    // Phase 2: UDP Flood Wave (50% UDP)
    attack_cfg.phases[1].duration_sec = 15;
    attack_cfg.phases[1].syn_pct = 0.30f;
    attack_cfg.phases[1].udp_pct = 0.50f;
    attack_cfg.phases[1].http_pct = 0.10f;
    attack_cfg.phases[1].dns_pct = 0.05f;
    attack_cfg.phases[1].icmp_pct = 0.05f;

    // Phase 3: HTTP/DNS Mixed Attack (40% HTTP + 30% DNS)
    attack_cfg.phases[2].duration_sec = 30;
    attack_cfg.phases[2].syn_pct = 0.20f;
    attack_cfg.phases[2].udp_pct = 0.10f;
    attack_cfg.phases[2].http_pct = 0.40f;
    attack_cfg.phases[2].dns_pct = 0.25f;
    attack_cfg.phases[2].icmp_pct = 0.05f;

    attack_cfg.num_phases = 3;

    printf("\n[ADAPTIVE-ATTACK] Using default attack phases (no file specified):\n");
    for (uint32_t i = 0; i < attack_cfg.num_phases; i++) {
        struct attack_phase *p = &attack_cfg.phases[i];
        printf("  Phase %u: %us - SYN:%.0f%% UDP:%.0f%% HTTP:%.0f%% DNS:%.0f%% ICMP:%.0f%%\n",
               i+1, p->duration_sec,
               p->syn_pct*100, p->udp_pct*100, p->http_pct*100, p->dns_pct*100, p->icmp_pct*100);
    }
    printf("\n");
}

/* Comparator function for qsort - alphanumeric sorting for CIC-DDoS-2019 PCAPs */
/* Sorts files like SAT-01-12-2018_0001.pcap, SAT-01-12-2018_0002.pcap, ... SAT-01-12-2018_0818.pcap */
static int compare_pcap_files(const void *a, const void *b)
{
    const char *file_a = *(const char **)a;
    const char *file_b = *(const char **)b;

    /* Extract numeric portion after last underscore: SAT-01-12-2018_NNNN.pcap */
    const char *num_a = strrchr(file_a, '_');
    const char *num_b = strrchr(file_b, '_');

    if (num_a && num_b) {
        /* Skip underscore and compare numerically */
        int num_val_a = atoi(num_a + 1);
        int num_val_b = atoi(num_b + 1);

        if (num_val_a != num_val_b) {
            return num_val_a - num_val_b;
        }
        /* If numeric parts are equal, fall through to string comparison */
    }

    /* Fallback to alphabetical string comparison */
    return strcmp(file_a, file_b);
}

/* NEW: Scan directory for .pcap files */
static int scan_pcap_directory(const char *dir_path)
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char full_path[1024];

    printf("\n[MULTI-PCAP] Scanning directory: %s\n", dir_path);

    dir = opendir(dir_path);
    if (!dir) {
        printf("Error: Cannot open directory: %s\n", dir_path);
        return -1;
    }

    /* Allocate file list */
    pcap_file_list = malloc(MAX_PCAP_FILES * sizeof(char *));
    if (!pcap_file_list) {
        printf("Error: Failed to allocate memory for file list\n");
        closedir(dir);
        return -1;
    }

    num_pcap_files = 0;

    /* Scan directory for .pcap files */
    while ((entry = readdir(dir)) != NULL && num_pcap_files < MAX_PCAP_FILES) {
        /* Check if file ends with .pcap */
        size_t name_len = strlen(entry->d_name);
        if (name_len < 5 || strcmp(entry->d_name + name_len - 5, ".pcap") != 0)
            continue;

        /* Build full path */
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        /* Check if it's a regular file */
        if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
            /* Allocate and store file path */
            pcap_file_list[num_pcap_files] = malloc(strlen(full_path) + 1);
            if (!pcap_file_list[num_pcap_files]) {
                printf("Error: Failed to allocate memory for file path\n");
                continue;
            }
            strcpy(pcap_file_list[num_pcap_files], full_path);
            num_pcap_files++;
        }
    }

    closedir(dir);

    if (num_pcap_files == 0) {
        printf("Error: No .pcap files found in directory: %s\n", dir_path);
        free(pcap_file_list);
        pcap_file_list = NULL;
        return -1;
    }

    /* ========== NEW: Sort files numerically ========== */
    /* For CIC-DDoS-2019 dataset with files like: SAT-01-12-2018_0001.pcap to SAT-01-12-2018_0818.pcap */
    printf("[MULTI-PCAP] Sorting files numerically...\n");
    qsort(pcap_file_list, num_pcap_files, sizeof(char *), compare_pcap_files);
    /* ================================================= */

    printf("[MULTI-PCAP] Found %u PCAP files (in order):\n", num_pcap_files);
    for (uint32_t i = 0; i < num_pcap_files && i < 10; i++) {
        printf("  [%u] %s\n", i + 1, basename(pcap_file_list[i]));
    }
    if (num_pcap_files > 10) {
        printf("  ... (%u more files)\n", num_pcap_files - 10);
    }
    printf("  Last file: [%u] %s\n", num_pcap_files, basename(pcap_file_list[num_pcap_files - 1]));
    printf("\n");

    multi_pcap_mode = 1;
    return 0;
}

/* NEW: Free PCAP data and prepare for next file */
static void free_current_pcap_data(void)
{
    if (pcap_packets) {
        free(pcap_packets);
        pcap_packets = NULL;
    }

    /* Free protocol classification arrays */
    if (http_packets) {
        free(http_packets);
        http_packets = NULL;
    }
    if (dns_packets) {
        free(dns_packets);
        dns_packets = NULL;
    }
    if (ssh_packets) {
        free(ssh_packets);
        ssh_packets = NULL;
    }
    if (udp_packets) {
        free(udp_packets);
        udp_packets = NULL;
    }

    /* Free attack classification arrays */
    if (syn_attack_packets) {
        free(syn_attack_packets);
        syn_attack_packets = NULL;
    }
    if (udp_attack_packets) {
        free(udp_attack_packets);
        udp_attack_packets = NULL;
    }
    if (http_attack_packets) {
        free(http_attack_packets);
        http_attack_packets = NULL;
    }
    if (dns_attack_packets) {
        free(dns_attack_packets);
        dns_attack_packets = NULL;
    }
    if (icmp_attack_packets) {
        free(icmp_attack_packets);
        icmp_attack_packets = NULL;
    }

    /* Reset counters */
    num_pcap_packets = 0;
    current_packet_idx = 0;
    num_http = 0;
    num_dns = 0;
    num_ssh = 0;
    num_udp = 0;
    num_syn_attack = 0;
    num_udp_attack = 0;
    num_http_attack = 0;
    num_dns_attack = 0;
    num_icmp_attack = 0;
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

        /* NEW: Classify packet for adaptive-attack mode */
        pcap_packets[num_pcap_packets].attack_type = classify_attack_packet(data, header->caplen);

        num_pcap_packets++;

        if (num_pcap_packets % 1000000 == 0)
            printf("Loaded %u packets...\n", num_pcap_packets);
    }

    pcap_close(pcap);
    printf("Loaded %u packets from PCAP\n", num_pcap_packets);

    /* NEW: Skip classification in multi-PCAP mode (just replay as-is) */
    if (multi_pcap_mode) {
        printf("\n[MULTI-PCAP MODE] Skipping packet classification - direct replay mode\n");
        printf("  All packets will be sent sequentially as they appear in the PCAP\n\n");
        return 0;
    }

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

    /* NEW: Build attack-classified indexes for --adaptive-attack mode */
    if (attack_cfg.enabled) {
        printf("Classifying packets by attack type for adaptive-attack mode...\n");

        // Allocate index arrays for attack types
        syn_attack_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        udp_attack_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        http_attack_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        dns_attack_packets = malloc(num_pcap_packets * sizeof(uint32_t));
        icmp_attack_packets = malloc(num_pcap_packets * sizeof(uint32_t));

        if (!syn_attack_packets || !udp_attack_packets || !http_attack_packets ||
            !dns_attack_packets || !icmp_attack_packets) {
            printf("Failed to allocate attack classification arrays\n");
            return -1;
        }

        // Classify all packets by attack type
        for (uint32_t i = 0; i < num_pcap_packets; i++) {
            switch (pcap_packets[i].attack_type) {
                case ATTACK_SYN:
                    syn_attack_packets[num_syn_attack++] = i;
                    break;
                case ATTACK_UDP_FLOOD:
                    udp_attack_packets[num_udp_attack++] = i;
                    break;
                case ATTACK_HTTP_FLOOD:
                    http_attack_packets[num_http_attack++] = i;
                    break;
                case ATTACK_DNS_FLOOD:
                    dns_attack_packets[num_dns_attack++] = i;
                    break;
                case ATTACK_ICMP_RANDOM:
                    icmp_attack_packets[num_icmp_attack++] = i;
                    break;
                default:
                    // Add unknown packets to ICMP/random pool
                    icmp_attack_packets[num_icmp_attack++] = i;
                    break;
            }
        }

        printf("\n[ATTACK CLASSIFICATION]\n");
        printf("  SYN/ACK:      %u packets (%.1f%%)\n", num_syn_attack, num_syn_attack*100.0f/num_pcap_packets);
        printf("  UDP Flood:    %u packets (%.1f%%)\n", num_udp_attack, num_udp_attack*100.0f/num_pcap_packets);
        printf("  HTTP Flood:   %u packets (%.1f%%)\n", num_http_attack, num_http_attack*100.0f/num_pcap_packets);
        printf("  DNS Flood:    %u packets (%.1f%%)\n", num_dns_attack, num_dns_attack*100.0f/num_pcap_packets);
        printf("  ICMP/Random:  %u packets (%.1f%%)\n", num_icmp_attack, num_icmp_attack*100.0f/num_pcap_packets);
        printf("\n");

        // Check if we have packets for all attack categories
        if (num_syn_attack == 0) printf("Warning: No SYN/ACK attack packets found!\n");
        if (num_udp_attack == 0) printf("Warning: No UDP flood packets found!\n");
        if (num_http_attack == 0) printf("Warning: No HTTP flood packets found!\n");
        if (num_dns_attack == 0) printf("Warning: No DNS flood packets found!\n");
        if (num_icmp_attack == 0) printf("Warning: No ICMP/random packets found!\n");
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

/* NEW: Multi-PCAP sequential sending loop (no classification, direct replay) */
static void send_loop_multi_pcap(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         DPDK PCAP SENDER v2.0 - MULTI-PCAP REPLAY MODE          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    printf("📁 Multi-PCAP Mode: ENABLED (%u files in queue)\n", num_pcap_files);
    printf("🔁 Loop Mode: INFINITE (will cycle through all PCAP files continuously)\n");
    printf("🎯 Target rate: %.1f Gbps\n", attack_cfg.target_gbps);
    printf("📦 Direct Replay: NO packet classification, sequential transmission\n");
    printf("🛑 Press Ctrl+C to stop\n\n");

    /* Rate limiting variables */
    const uint64_t target_bytes_per_sec = (uint64_t)(attack_cfg.target_gbps * 1e9 / 8.0);
    uint64_t bytes_sent_in_window = 0;
    uint64_t window_start_tsc = 0;

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    window_start_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        /* Multi-PCAP mode - Check if we need to load next file */
        if (current_packet_idx >= num_pcap_packets) {
            printf("\n[MULTI-PCAP] Finished PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Move to next PCAP file */
            current_pcap_file_idx = (current_pcap_file_idx + 1) % num_pcap_files;

            printf("[MULTI-PCAP] Loading next PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Free current PCAP data */
            free_current_pcap_data();

            /* Load next PCAP */
            if (load_pcap(pcap_file_list[current_pcap_file_idx]) != 0) {
                printf("Error: Failed to load next PCAP file, stopping\n");
                break;
            }

            printf("[MULTI-PCAP] Successfully loaded %u packets\n\n", num_pcap_packets);
        }

        /* Allocate fresh mbufs */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE) != 0) {
            rte_delay_us_block(100);
            continue;
        }

        /* Fill mbufs with PCAP data (sequential, no classification) */
        for (i = 0; i < BURST_SIZE; i++) {
            struct packet_data *pkt_data = &pcap_packets[current_packet_idx];

            char *pkt_buf = rte_pktmbuf_mtod(pkts[i], char *);
            rte_memcpy(pkt_buf, pkt_data->data, pkt_data->len);
            pkts[i]->data_len = pkt_data->len;
            pkts[i]->pkt_len = pkt_data->len;

            current_packet_idx++;
            if (current_packet_idx >= num_pcap_packets)
                break;  // Will load next file on next iteration
        }

        /* Adjust burst size if we hit end of file */
        uint32_t actual_burst = (i < BURST_SIZE) ? i : BURST_SIZE;

        /* Send burst */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts, actual_burst);
        total_packets_sent += nb_tx;

        /* Track bytes for rate limiting */
        for (i = 0; i < nb_tx; i++) {
            bytes_sent_in_window += pkts[i]->pkt_len;
            total_bytes_sent += pkts[i]->pkt_len;
        }

        /* Free unsent packets */
        if (unlikely(nb_tx < actual_burst)) {
            for (i = nb_tx; i < actual_burst; i++)
                rte_pktmbuf_free(pkts[i]);
        }

        /* Rate limiting */
        double elapsed_sec = (double)(cur_tsc - window_start_tsc) / hz;

        if (elapsed_sec >= 1.0) {
            /* Reset window every second */
            bytes_sent_in_window = 0;
            window_start_tsc = cur_tsc;
        } else if (bytes_sent_in_window > (uint64_t)(target_bytes_per_sec * elapsed_sec)) {
            /* Too fast, calculate sleep time */
            double bytes_expected = target_bytes_per_sec * elapsed_sec;
            double bytes_over = bytes_sent_in_window - bytes_expected;
            uint64_t sleep_ns = (uint64_t)((bytes_over * 8.0 * 1e9) / (attack_cfg.target_gbps * 1e9));

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

            printf("[%.1fs] PCAP [%u/%u] | %lu pkts (%.2f Mpps) | Avg: %.2f Gbps | Inst: %.2f Gbps\n",
                   elapsed, current_pcap_file_idx + 1, num_pcap_files,
                   total_packets_sent, mpps_cumulative, gbps_cumulative, gbps_instant);

            last_window_packets = total_packets_sent;
            last_window_bytes = total_bytes_sent;
            last_window_tsc = cur_tsc;
            last_stats_tsc = cur_tsc;
        }
    }

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                MULTI-PCAP REPLAY COMPLETE - FINAL STATS         ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total packets sent:  %lu\n", total_packets_sent);
    printf("Total bytes sent:    %lu\n", total_bytes_sent);
    printf("Duration:            %.2f seconds\n", elapsed);
    printf("Average throughput:  %.2f Gbps\n", gbps);
    printf("Average pps:         %.2f Mpps\n", mpps);
    printf("\n🛑 Multi-PCAP replay terminated.\n");
}

/* NEW: Multi-PCAP with timestamp-based replay (respects original timing) */
static void send_loop_multi_pcap_timed(void)
{
    uint16_t nb_tx;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    struct timeval prev_timestamp = {0, 0};
    uint8_t first_packet_in_pcap = 1;

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║    DPDK PCAP SENDER v2.0 - MULTI-PCAP TIMED REPLAY MODE         ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    printf("📁 Multi-PCAP Mode: ENABLED (%u files in queue)\n", num_pcap_files);
    printf("⏱️  Timestamp Mode: RESPECTING original PCAP timestamps\n");
    printf("🔁 Loop Mode: INFINITE (will cycle through all PCAP files continuously)\n");
    printf("⚡ Speedup: %lux (use --speedup to change)\n", replay_cfg.speedup_factor);
    printf("🎯 Jitter: ±%.1f%%\n", replay_cfg.jitter_pct);
    printf("🛑 Press Ctrl+C to stop\n\n");

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;

    srand(time(NULL));  // Initialize random for jitter

    while (!force_quit) {
        /* Multi-PCAP mode - Check if we need to load next file */
        if (current_packet_idx >= num_pcap_packets) {
            printf("\n[MULTI-PCAP] Finished PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Move to next PCAP file */
            current_pcap_file_idx = (current_pcap_file_idx + 1) % num_pcap_files;

            printf("[MULTI-PCAP] Loading next PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Free current PCAP data */
            free_current_pcap_data();

            /* Load next PCAP */
            if (load_pcap(pcap_file_list[current_pcap_file_idx]) != 0) {
                printf("Error: Failed to load next PCAP file, stopping\n");
                break;
            }

            printf("[MULTI-PCAP] Successfully loaded %u packets\n", num_pcap_packets);
            printf("[MULTI-PCAP] First timestamp: %ld.%06ld\n",
                   pcap_packets[0].timestamp.tv_sec,
                   pcap_packets[0].timestamp.tv_usec);
            printf("[MULTI-PCAP] Resuming timestamp-based replay...\n\n");

            /* Reset timestamp tracking for new PCAP */
            first_packet_in_pcap = 1;
        }

        struct packet_data *pkt_data = &pcap_packets[current_packet_idx];

        /* Calculate delay based on timestamp difference */
        if (!first_packet_in_pcap) {
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
        first_packet_in_pcap = 0;

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

            double window_duration = (double)(cur_tsc - last_window_tsc) / hz;
            uint64_t window_packets = total_packets_sent - last_window_packets;
            uint64_t window_bytes = total_bytes_sent - last_window_bytes;
            double gbps_instant = (window_bytes * 8.0) / (window_duration * 1e9);

            printf("[%.1fs] PCAP [%u/%u] | %lu pkts (%.2f Mpps) | Avg: %.2f Gbps | Inst: %.2f Gbps\n",
                   elapsed, current_pcap_file_idx + 1, num_pcap_files,
                   total_packets_sent, mpps_cumulative, gbps_cumulative, gbps_instant);

            last_window_packets = total_packets_sent;
            last_window_bytes = total_bytes_sent;
            last_window_tsc = cur_tsc;
            last_stats_tsc = cur_tsc;
        }
    }

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║         MULTI-PCAP TIMED REPLAY COMPLETE - FINAL STATS          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total packets sent:  %lu\n", total_packets_sent);
    printf("Total bytes sent:    %lu\n", total_bytes_sent);
    printf("Duration:            %.2f seconds\n", elapsed);
    printf("Average throughput:  %.2f Gbps\n", gbps);
    printf("Average pps:         %.2f Mpps\n", mpps);
    printf("\n🛑 Multi-PCAP timed replay terminated.\n");
}

/* NEW: Adaptive ATTACK mode - High-speed continuous attack with phase-based distribution */
static void send_loop_adaptive_attack(void)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    uint16_t nb_tx;
    uint32_t i;
    uint64_t hz = rte_get_tsc_hz();
    uint64_t last_stats_tsc = 0;

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║      DPDK PCAP SENDER v2.0 - ADAPTIVE ATTACK REPLAY MODE        ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    printf("⚡ Attack Mode: ENABLED\n");

    /* NEW: Show multi-PCAP mode status */
    if (multi_pcap_mode) {
        printf("📁 Multi-PCAP Mode: ENABLED (%u files in queue)\n", num_pcap_files);
        printf("🔁 Loop Mode: INFINITE (will cycle through all PCAP files continuously)\n");
    }

    printf("🎯 Target rate: %.1f Gbps  |  Jitter: ±%.1f%%  |  Loop: %s\n",
           attack_cfg.target_gbps, attack_cfg.jitter_pct,
           attack_cfg.loop_mode ? "YES (infinite)" : "NO");
    printf("⏱️  Duration: %s\n", attack_cfg.duration_sec == 0 ?
           "Infinite (until Ctrl+C)" : "Limited");
    printf("📊 Attack Phases: %u loaded\n", attack_cfg.num_phases);
    printf("🔥 Multi-core: Enabled (using all assigned cores)\n");
    printf("🛑 Press Ctrl+C to stop\n\n");

    if (num_syn_attack == 0 && num_udp_attack == 0 && num_http_attack == 0 &&
        num_dns_attack == 0 && num_icmp_attack == 0) {
        printf("ERROR: No classified attack packets available!\n");
        return;
    }

    /* Rate limiting variables */
    const uint64_t target_bytes_per_sec = (uint64_t)(attack_cfg.target_gbps * 1e9 / 8.0);
    uint64_t bytes_sent_in_window = 0;
    uint64_t window_start_tsc = 0;

    /* Phase tracking */
    uint32_t current_phase = 0;
    uint64_t phase_start_tsc = 0;
    uint64_t phase_duration_tsc = 0;

    /* Attack statistics */
    uint64_t syn_sent = 0, udp_sent = 0, http_sent = 0, dns_sent = 0, icmp_sent = 0;
    uint64_t last_syn = 0, last_udp = 0, last_http = 0, last_dns = 0, last_icmp = 0;

    start_tsc = rte_rdtsc();
    last_stats_tsc = start_tsc;
    window_start_tsc = start_tsc;
    last_window_tsc = start_tsc;
    last_window_packets = 0;
    last_window_bytes = 0;
    phase_start_tsc = start_tsc;

    srand(time(NULL));

    // Initialize first attack phase
    if (attack_cfg.num_phases > 0) {
        phase_duration_tsc = attack_cfg.phases[0].duration_sec * hz;
        printf("🔴 [PHASE 1/%u] Starting Attack - %us - SYN:%.0f%% UDP:%.0f%% HTTP:%.0f%% DNS:%.0f%% ICMP:%.0f%%\n",
               attack_cfg.num_phases,
               attack_cfg.phases[0].duration_sec,
               attack_cfg.phases[0].syn_pct*100,
               attack_cfg.phases[0].udp_pct*100,
               attack_cfg.phases[0].http_pct*100,
               attack_cfg.phases[0].dns_pct*100,
               attack_cfg.phases[0].icmp_pct*100);
    }

    uint64_t total_start_tsc = start_tsc;
    uint64_t total_duration_tsc = attack_cfg.duration_sec * hz;

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        /* NEW: Multi-PCAP mode - Check if we need to load next file */
        if (multi_pcap_mode && current_packet_idx >= num_pcap_packets) {
            printf("\n[MULTI-PCAP] Finished PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Move to next PCAP file */
            current_pcap_file_idx = (current_pcap_file_idx + 1) % num_pcap_files;

            printf("[MULTI-PCAP] Loading next PCAP [%u/%u]: %s\n",
                   current_pcap_file_idx + 1, num_pcap_files,
                   basename(pcap_file_list[current_pcap_file_idx]));

            /* Free current PCAP data */
            free_current_pcap_data();

            /* Load next PCAP */
            if (load_pcap(pcap_file_list[current_pcap_file_idx]) != 0) {
                printf("Error: Failed to load next PCAP file, stopping attack\n");
                break;
            }

            printf("[MULTI-PCAP] Successfully loaded %u packets\n\n", num_pcap_packets);

            /* Check if we have attack packets */
            if (num_syn_attack == 0 && num_udp_attack == 0 && num_http_attack == 0 &&
                num_dns_attack == 0 && num_icmp_attack == 0) {
                printf("Warning: No classified attack packets in this PCAP, skipping...\n");
                current_packet_idx = num_pcap_packets;  // Force skip to next file
                continue;
            }
        }

        // Check total duration limit
        if (attack_cfg.duration_sec > 0 &&
            (cur_tsc - total_start_tsc) >= total_duration_tsc) {
            printf("\n⏹️  [DURATION LIMIT] Reached %u seconds, stopping attack.\n",
                   attack_cfg.duration_sec);
            break;
        }

        // Check if we need to advance to next attack phase
        if (attack_cfg.num_phases > 0 &&
            (cur_tsc - phase_start_tsc) >= phase_duration_tsc) {

            // Loop back to phase 0 if in loop mode, otherwise stop
            if (current_phase == attack_cfg.num_phases - 1 && !attack_cfg.loop_mode) {
                printf("\n✅ All attack phases completed. Stopping (loop disabled).\n");
                break;
            }

            current_phase = (current_phase + 1) % attack_cfg.num_phases;
            phase_start_tsc = cur_tsc;
            phase_duration_tsc = attack_cfg.phases[current_phase].duration_sec * hz;

            printf("\n🔴 [PHASE %u/%u] Switching Attack - %us - SYN:%.0f%% UDP:%.0f%% HTTP:%.0f%% DNS:%.0f%% ICMP:%.0f%%\n",
                   current_phase + 1, attack_cfg.num_phases,
                   attack_cfg.phases[current_phase].duration_sec,
                   attack_cfg.phases[current_phase].syn_pct*100,
                   attack_cfg.phases[current_phase].udp_pct*100,
                   attack_cfg.phases[current_phase].http_pct*100,
                   attack_cfg.phases[current_phase].dns_pct*100,
                   attack_cfg.phases[current_phase].icmp_pct*100);
        }

        /* Allocate fresh mbufs */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, pkts, BURST_SIZE) != 0) {
            rte_delay_us_block(100);
            continue;
        }

        /* Fill mbufs based on current attack phase distribution */
        struct attack_phase *phase = &attack_cfg.phases[current_phase];

        for (i = 0; i < BURST_SIZE; i++) {
            uint32_t pkt_idx = 0;
            float r = (float)rand() / RAND_MAX;

            // Select attack type based on phase percentages
            if (r < phase->syn_pct && num_syn_attack > 0) {
                // SYN/ACK attack packet
                uint32_t idx = rand() % num_syn_attack;
                pkt_idx = syn_attack_packets[idx];
                syn_sent++;
            } else if (r < (phase->syn_pct + phase->udp_pct) && num_udp_attack > 0) {
                // UDP flood packet
                uint32_t idx = rand() % num_udp_attack;
                pkt_idx = udp_attack_packets[idx];
                udp_sent++;
            } else if (r < (phase->syn_pct + phase->udp_pct + phase->http_pct) && num_http_attack > 0) {
                // HTTP flood packet
                uint32_t idx = rand() % num_http_attack;
                pkt_idx = http_attack_packets[idx];
                http_sent++;
            } else if (r < (phase->syn_pct + phase->udp_pct + phase->http_pct + phase->dns_pct) && num_dns_attack > 0) {
                // DNS flood packet
                uint32_t idx = rand() % num_dns_attack;
                pkt_idx = dns_attack_packets[idx];
                dns_sent++;
            } else if (num_icmp_attack > 0) {
                // ICMP/random attack packet
                uint32_t idx = rand() % num_icmp_attack;
                pkt_idx = icmp_attack_packets[idx];
                icmp_sent++;
            } else {
                // Fallback to any attack packet
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

        /* Apply jitter if configured */
        if (attack_cfg.jitter_pct > 0.0f) {
            double jitter_mult = get_jitter_multiplier(attack_cfg.jitter_pct);
            uint64_t jitter_delay_ns = (uint64_t)(1000 * jitter_mult);
            if (jitter_delay_ns > 0 && jitter_delay_ns < 100000) {
                rte_delay_us_block(jitter_delay_ns / 1000);
            }
        }

        /* Rate limiting */
        double elapsed_sec = (double)(cur_tsc - window_start_tsc) / hz;

        if (elapsed_sec >= 1.0) {
            /* Reset window every second */
            bytes_sent_in_window = 0;
            window_start_tsc = cur_tsc;
        } else if (bytes_sent_in_window > (uint64_t)(target_bytes_per_sec * elapsed_sec)) {
            /* Too fast, calculate sleep time */
            double bytes_expected = target_bytes_per_sec * elapsed_sec;
            double bytes_over = bytes_sent_in_window - bytes_expected;
            uint64_t sleep_ns = (uint64_t)((bytes_over * 8.0 * 1e9) / (attack_cfg.target_gbps * 1e9));

            if (sleep_ns > 0 && sleep_ns < 100000) {
                rte_delay_us_block(sleep_ns / 1000);
            }
        }

        /* Print attack statistics every 5 seconds */
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

            /* Attack type distribution in last window */
            uint64_t window_syn = syn_sent - last_syn;
            uint64_t window_udp = udp_sent - last_udp;
            uint64_t window_http = http_sent - last_http;
            uint64_t window_dns = dns_sent - last_dns;
            uint64_t window_icmp = icmp_sent - last_icmp;

            printf("[%.1fs] Phase %u/%u | %lu pkts (%.2f Mpps) | Avg: %.2f Gbps | Inst: %.2f Gbps\n",
                   elapsed, current_phase + 1, attack_cfg.num_phases,
                   total_packets_sent, mpps_cumulative, gbps_cumulative, gbps_instant);
            printf("       Attack Mix: SYN:%.0f%% UDP:%.0f%% HTTP:%.0f%% DNS:%.0f%% ICMP:%.0f%%\n",
                   window_syn*100.0f/window_packets,
                   window_udp*100.0f/window_packets,
                   window_http*100.0f/window_packets,
                   window_dns*100.0f/window_packets,
                   window_icmp*100.0f/window_packets);

            /* Update window markers */
            last_window_packets = total_packets_sent;
            last_window_bytes = total_bytes_sent;
            last_window_tsc = cur_tsc;
            last_stats_tsc = cur_tsc;
            last_syn = syn_sent;
            last_udp = udp_sent;
            last_http = http_sent;
            last_dns = dns_sent;
            last_icmp = icmp_sent;
        }
    }

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                   ATTACK STATISTICS - FINAL                      ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    double elapsed = (double)(rte_rdtsc() - start_tsc) / hz;
    double gbps = (total_bytes_sent * 8.0) / (elapsed * 1e9);
    double mpps = (total_packets_sent / elapsed) / 1e6;

    printf("Total attack packets:  %lu\n", total_packets_sent);
    printf("Total bytes sent:      %lu\n", total_bytes_sent);
    printf("Attack duration:       %.2f seconds\n", elapsed);
    printf("Average throughput:    %.2f Gbps\n", gbps);
    printf("Average pps:           %.2f Mpps\n", mpps);
    printf("\nAttack Type Distribution:\n");
    printf("  SYN/ACK:      %lu packets (%.1f%%)\n", syn_sent, syn_sent*100.0f/total_packets_sent);
    printf("  UDP Flood:    %lu packets (%.1f%%)\n", udp_sent, udp_sent*100.0f/total_packets_sent);
    printf("  HTTP Flood:   %lu packets (%.1f%%)\n", http_sent, http_sent*100.0f/total_packets_sent);
    printf("  DNS Flood:    %lu packets (%.1f%%)\n", dns_sent, dns_sent*100.0f/total_packets_sent);
    printf("  ICMP/Random:  %lu packets (%.1f%%)\n", icmp_sent, icmp_sent*100.0f/total_packets_sent);
    printf("\nPhases completed:      %u cycles\n", current_phase / attack_cfg.num_phases);
    printf("\n🛑 Attack terminated.\n");
}

/* NEW: Print usage with new options */
static void print_usage(const char *prgname)
{
    printf("\nUsage: %s [EAL options] -- <pcap_file|--pcap-dir <directory>> [OPTIONS]\n\n", prgname);
    printf("INPUT OPTIONS:\n");
    printf("  <pcap_file>               Single PCAP file to replay\n");
    printf("  --pcap-dir <directory>    🔁 Directory with multiple PCAP files (automatic loop)\n");
    printf("                            Default: %s\n", DEFAULT_PCAP_DIR);
    printf("                            ⚠️  In multi-PCAP mode:\n");
    printf("                            - Adaptive/attack phases are DISABLED\n");
    printf("                            - NO packet classification (SYN/UDP/HTTP)\n");
    printf("                            - Direct sequential replay only\n");
    printf("                            - Infinite loop through all files\n");
    printf("\n");
    printf("MODES:\n");
    printf("  --pcap-timed              Replay PCAP respecting timestamps (temporal phases)\n");
    printf("  --adaptive                Adaptive high-speed replay with phase-based protocol mix (BENIGN)\n");
    printf("  --adaptive-attack         🔥 ATTACK MODE: Continuous DDoS with phase-based attack mix\n");
    printf("\n");
    printf("TIMED MODE OPTIONS:\n");
    printf("  --jitter <percent>        Add timing jitter (±X%%, e.g., 10 for ±10%%)\n");
    printf("  --speedup <factor>        Speedup factor (1=realtime, 10=10x faster, default: 1)\n");
    printf("\n");
    printf("ADAPTIVE MODE OPTIONS (BENIGN):\n");
    printf("  --rate-gbps <rate>        Target rate in Gbps (default: 12)\n");
    printf("  --jitter <percent>        PPS variation (±X%%)\n");
    printf("  --phases <file.json>      Phase definition file (optional, uses defaults if not provided)\n");
    printf("  --loop                    Loop indefinitely through phases\n");
    printf("  --duration <seconds>      Run for specified duration (0=infinite, default: 0)\n");
    printf("\n");
    printf("ADAPTIVE-ATTACK MODE OPTIONS:\n");
    printf("  --rate-gbps <rate>        Target attack rate in Gbps (default: 12)\n");
    printf("  --jitter <percent>        Attack PPS variation (±X%%)\n");
    printf("  --attack-phases <file>    Attack phase definition file (JSON, optional)\n");
    printf("  --loop                    Loop indefinitely through attack phases (infinite attack)\n");
    printf("  --duration <seconds>      Attack duration (0=infinite, default: 0)\n");
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
    printf("  # 🔥 ATTACK MODE: Single PCAP at 10Gbps (infinite loop):\n");
    printf("  %s -l 0-7 -- attack_mirai_10M_v2.pcap --adaptive-attack --rate-gbps 10 --loop\n\n", prgname);
    printf("  # 🔥 ATTACK MODE: DDoS with custom phases, jitter, 300s duration:\n");
    printf("  %s -l 0-7 -- attack.pcap --adaptive-attack --attack-phases phases_attack.json --jitter 15 --duration 300\n\n", prgname);
    printf("  # 🔥🔁 MULTI-PCAP MODE: Auto-load all PCAPs from directory (infinite loop, fixed rate):\n");
    printf("  %s -l 0-7 -- --pcap-dir /proj/softmeasure-PG0/CICD/remapped/ --rate-gbps 10\n\n", prgname);
    printf("  # 🔥🔁⏱️  MULTI-PCAP TIMED MODE: Respect original timestamps (CIC-DDoS-2019):\n");
    printf("  %s -l 0-7 -- --pcap-dir /proj/softmeasure-PG0/CICD/remapped/ --pcap-timed --speedup 100\n\n", prgname);
    printf("  # 🔥🔁 MULTI-PCAP MODE: Use default directory with 12 Gbps:\n");
    printf("  %s -l 0-7 -- --pcap-dir --rate-gbps 12\n\n", prgname);
    printf("  # Note: --adaptive-attack and --attack-phases are IGNORED in multi-PCAP mode\n");
    printf("  #       Use --pcap-timed to see attacks at their original time windows\n\n");
    printf("\nPHASE FILE FORMAT (BENIGN - JSON):\n");
    printf("  [{\"duration\": 30, \"http\": 0.60, \"dns\": 0.20, \"ssh\": 0.10, \"udp\": 0.10},\n");
    printf("   {\"duration\": 15, \"http\": 0.30, \"dns\": 0.50, \"ssh\": 0.10, \"udp\": 0.10}]\n");
    printf("\n");
    printf("ATTACK PHASE FILE FORMAT (ATTACK - JSON):\n");
    printf("  [{\"duration\": 20, \"syn\": 0.60, \"udp\": 0.20, \"http\": 0.10, \"dns\": 0.05, \"icmp\": 0.05},\n");
    printf("   {\"duration\": 15, \"syn\": 0.30, \"udp\": 0.50, \"http\": 0.10, \"dns\": 0.05, \"icmp\": 0.05},\n");
    printf("   {\"duration\": 30, \"syn\": 0.20, \"udp\": 0.10, \"http\": 0.40, \"dns\": 0.25, \"icmp\": 0.05}]\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int ret;
    char *pcap_file = NULL;
    char *pcap_dir = NULL;
    int opt;
    int option_index;
    char *phases_file = NULL;
    char *attack_phases_file = NULL;
    float jitter;  // Declare here to avoid error in switch

    /* NEW: Long options for temporal replay, adaptive mode, and adaptive-attack mode */
    static struct option long_options[] = {
        {"pcap-dir", optional_argument, NULL, 'D'},
        {"pcap-timed", no_argument, NULL, 't'},
        {"adaptive", no_argument, NULL, 'a'},
        {"adaptive-attack", no_argument, NULL, 'A'},
        {"jitter", required_argument, NULL, 'j'},
        {"phase-mode", no_argument, NULL, 'p'},
        {"speedup", required_argument, NULL, 's'},
        {"rate-gbps", required_argument, NULL, 'r'},
        {"phases", required_argument, NULL, 'f'},
        {"attack-phases", required_argument, NULL, 'F'},
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

    /* Parse application arguments (after --) */
    optind = 1;
    while ((opt = getopt_long(argc, argv, "D::taAj:ps:r:f:F:ld:h", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'D':
            /* --pcap-dir option */
            if (optarg) {
                pcap_dir = optarg;
            } else {
                pcap_dir = (char *)DEFAULT_PCAP_DIR;
            }
            printf("[CONFIG] PCAP directory mode: %s\n", pcap_dir);
            break;
        case 't':
            replay_cfg.pcap_timed = 1;
            printf("[CONFIG] Timed replay enabled\n");
            break;
        case 'a':
            adaptive_cfg.enabled = 1;
            printf("[CONFIG] Adaptive mode enabled (BENIGN)\n");
            break;
        case 'A':
            attack_cfg.enabled = 1;
            printf("[CONFIG] 🔥 ADAPTIVE-ATTACK mode enabled (DDoS)\n");
            break;
        case 'j':
            jitter = atof(optarg);
            if (jitter < 0 || jitter > 100) {
                printf("Error: Jitter must be between 0 and 100\n");
                return -1;
            }
            // Apply to all configs (whichever mode is active will use it)
            replay_cfg.jitter_pct = jitter;
            adaptive_cfg.jitter_pct = jitter;
            attack_cfg.jitter_pct = jitter;
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
            attack_cfg.target_gbps = atof(optarg);  // Apply to attack mode too
            if (adaptive_cfg.target_gbps <= 0 || adaptive_cfg.target_gbps > 100) {
                printf("Error: Rate must be between 0 and 100 Gbps\n");
                return -1;
            }
            printf("[CONFIG] Target rate: %.1f Gbps\n", adaptive_cfg.target_gbps);
            break;
        case 'f':
            phases_file = optarg;
            printf("[CONFIG] Benign phases file: %s\n", phases_file);
            break;
        case 'F':
            attack_phases_file = optarg;
            printf("[CONFIG] Attack phases file: %s\n", attack_phases_file);
            break;
        case 'l':
            adaptive_cfg.loop_mode = 1;
            attack_cfg.loop_mode = 1;  // Apply to attack mode too
            printf("[CONFIG] Loop mode enabled (infinite)\n");
            break;
        case 'd':
            adaptive_cfg.duration_sec = atoi(optarg);
            attack_cfg.duration_sec = atoi(optarg);  // Apply to attack mode too
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

    /* NEW: Override adaptive/attack modes if multi-PCAP is enabled */
    if (pcap_dir && (adaptive_cfg.enabled || attack_cfg.enabled)) {
        printf("\n⚠️  WARNING: Multi-PCAP mode detected!\n");
        printf("    --adaptive and --adaptive-attack flags will be IGNORED\n");
        printf("    Multi-PCAP mode uses direct sequential replay (no packet classification)\n\n");
        adaptive_cfg.enabled = 0;
        attack_cfg.enabled = 0;
    }

    /* Load or create phases for adaptive mode (only if NOT multi-PCAP) */
    if (adaptive_cfg.enabled && !pcap_dir) {
        if (phases_file) {
            if (parse_phases_file(phases_file) != 0) {
                printf("Error: Failed to parse phases file, using defaults\n");
                create_default_phases();
            }
        } else {
            create_default_phases();
        }
    }

    /* NEW: Load or create attack phases for adaptive-attack mode (only if NOT multi-PCAP) */
    if (attack_cfg.enabled && !pcap_dir) {
        if (attack_phases_file) {
            if (parse_attack_phases_file(attack_phases_file) != 0) {
                printf("Error: Failed to parse attack phases file, using defaults\n");
                create_default_attack_phases();
            }
        } else {
            create_default_attack_phases();
        }
    }

    /* Validate mode selection */
    if (adaptive_cfg.enabled && attack_cfg.enabled) {
        printf("Error: Cannot enable both --adaptive and --adaptive-attack modes simultaneously\n");
        return -1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports available\n");

    /* NEW: Use larger mbuf size (4096) to avoid "packet too large" warnings */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, MAX_PKT_LEN + RTE_PKTMBUF_HEADROOM, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(port_id, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", port_id);

    /* NEW: Handle multi-PCAP directory mode or single file mode */
    if (pcap_dir) {
        /* Multi-PCAP mode: scan directory and load all .pcap files */
        if (scan_pcap_directory(pcap_dir) != 0)
            rte_exit(EXIT_FAILURE, "Failed to scan PCAP directory\n");

        /* Load first PCAP file from the list */
        printf("[MULTI-PCAP] Loading first PCAP: %s\n", pcap_file_list[0]);
        if (load_pcap(pcap_file_list[0]) != 0)
            rte_exit(EXIT_FAILURE, "Failed to load first PCAP file\n");
    } else {
        /* Single PCAP mode: check if pcap_file was provided */
        if (!pcap_file) {
            /* No file and no directory specified, check if there's a positional argument */
            if (optind < argc) {
                pcap_file = argv[optind];
            } else {
                printf("Error: No PCAP file or directory specified\n");
                print_usage(argv[0]);
                return -1;
            }
        }

        printf("[SINGLE-PCAP] Loading: %s\n", pcap_file);
        if (load_pcap(pcap_file) != 0)
            rte_exit(EXIT_FAILURE, "Failed to load PCAP file\n");
    }

    /* NEW: Choose sending loop based on configuration */
    if (multi_pcap_mode) {
        /* NEW: Multi-PCAP mode - Check if timestamp-based or rate-limited */
        if (replay_cfg.pcap_timed) {
            /* Multi-PCAP with timestamp-based replay (CIC-DDoS-2019 temporal replay) */
            printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
            printf("║      🔁⏱️  LAUNCHING MULTI-PCAP TIMED REPLAY MODE ⏱️🔁          ║\n");
            printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
            printf("⚠️  WARNING: Attack traffic will be replayed from multiple PCAPs\n");
            printf("⚠️  CRITICAL: Use ONLY CloudLab INTERNAL network!\n");
            printf("    ✅ ALLOWED:  10.10.1.x (benign) and 10.10.3.x (attack)\n");
            printf("    ✅ NIC:      ens1f0 (PCI 0000:41:00.0)\n");
            printf("    ❌ FORBIDDEN: 192.168.x.x (control network - experiment will be TERMINATED!)\n");
            printf("    ❌ FORBIDDEN: eno33 (control interface)\n");
            printf("⚠️  Mode: Timestamp-based replay (respecting original PCAP timing)\n");
            printf("    → Attacks will appear at their original time windows\n");
            printf("    → Example: PortMap (9:43-9:51), NetBIOS (10:00-10:09), etc.\n");
            printf("⚠️  Press Ctrl+C to stop\n\n");
            send_loop_multi_pcap_timed();
        } else {
            /* Multi-PCAP with rate limiting (fast continuous replay) */
            printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
            printf("║          🔁🔁🔁 LAUNCHING MULTI-PCAP REPLAY MODE 🔁🔁🔁         ║\n");
            printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
            printf("⚠️  WARNING: Attack traffic will be generated from multiple PCAPs\n");
            printf("⚠️  CRITICAL: Use ONLY CloudLab INTERNAL network!\n");
            printf("    ✅ ALLOWED:  10.10.1.x (benign) and 10.10.3.x (attack)\n");
            printf("    ✅ NIC:      ens1f0 (PCI 0000:41:00.0)\n");
            printf("    ❌ FORBIDDEN: 192.168.x.x (control network - experiment will be TERMINATED!)\n");
            printf("    ❌ FORBIDDEN: eno33 (control interface)\n");
            printf("⚠️  Mode: Direct sequential replay at fixed rate (NO timestamp respect)\n");
            printf("    → All attacks blended together\n");
            printf("    → Use --pcap-timed to see individual attack phases\n");
            printf("⚠️  Press Ctrl+C to stop\n\n");
            send_loop_multi_pcap();
        }
    } else if (attack_cfg.enabled) {
        /* NEW: Adaptive-attack mode with phase-based DDoS attack distribution */
        printf("\n╔═══════════════════════════════════════════════════════════════════╗\n");
        printf("║          🔥🔥🔥 LAUNCHING ADAPTIVE ATTACK MODE 🔥🔥🔥            ║\n");
        printf("╚═══════════════════════════════════════════════════════════════════╝\n\n");
        printf("⚠️  WARNING: Continuous DDoS attack traffic will be generated\n");
        printf("⚠️  CRITICAL: Use ONLY CloudLab INTERNAL network!\n");
        printf("    ✅ ALLOWED:  10.10.1.x (benign) and 10.10.2.x (attack)\n");
        printf("    ✅ NIC:      ens1f0 (PCI 0000:41:00.0)\n");
        printf("    ❌ FORBIDDEN: 192.168.x.x (control network - experiment will be TERMINATED!)\n");
        printf("    ❌ FORBIDDEN: eno33 (control interface)\n");
        printf("⚠️  Verify PCAP IPs before running: tcpdump -r <file> -n | head\n");
        printf("⚠️  Press Ctrl+C to stop attack\n\n");
        send_loop_adaptive_attack();
    } else if (adaptive_cfg.enabled) {
        /* Adaptive mode with phase-based protocol distribution (BENIGN) */
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

    /* NEW: Cleanup attack classification arrays */
    if (syn_attack_packets) free(syn_attack_packets);
    if (udp_attack_packets) free(udp_attack_packets);
    if (http_attack_packets) free(http_attack_packets);
    if (dns_attack_packets) free(dns_attack_packets);
    if (icmp_attack_packets) free(icmp_attack_packets);

    /* NEW: Cleanup multi-PCAP file list */
    if (pcap_file_list) {
        printf("Freeing PCAP file list...\n");
        for (uint32_t i = 0; i < num_pcap_files; i++) {
            if (pcap_file_list[i])
                free(pcap_file_list[i]);
        }
        free(pcap_file_list);
    }

    printf("Cleanup complete.\n");
    printf("Sender stopped.\n");
    return 0;
}
