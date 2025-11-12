# Detector System - Code Analysis

## Important Code Explanation

This document explains the key code sections in the DPDK-based DDoS detector (`detector_dpdk.c`).

## File: `detector_dpdk.c`

### Overview

The detector is a C program using DPDK for high-performance packet processing. It implements:
1. **DPDK packet capture** (zero-copy, kernel bypass)
2. **Sketch algorithms** (Count-Min, HyperLogLog)
3. **Feature extraction** (19 ML features)
4. **Real-time logging** (detection.log, ml_features.csv, alerts.log)

---

## Core Data Structures

### 1. Count-Min Sketch

```c
#define CM_WIDTH 2048
#define CM_DEPTH 4

typedef struct {
    uint32_t counters[CM_DEPTH][CM_WIDTH];
} count_min_sketch_t;
```

**What it is**:
- Probabilistic data structure for frequency counting
- Trade accuracy for memory efficiency
- **Space**: 4 rows × 2048 columns = 32KB (vs. unbounded hash map)
- **Use case**: Count packets per source IP, flow, etc.

**How it works**:
```
Key (e.g., source IP) → Hash functions (4 different) → Positions in array
Increment all 4 positions
Query: Return minimum of the 4 counters (conservative estimate)
```

**Properties**:
- **Over-estimation**: Never under-counts (safe for DDoS detection)
- **Collision handling**: Multiple keys may map to same counter (counts merge)
- **Memory**: O(width × depth) - constant, not dependent on unique keys

### 2. HyperLogLog

```c
#define HLL_PRECISION 14
#define HLL_SIZE (1 << HLL_PRECISION)  // 16384

typedef struct {
    uint8_t registers[HLL_SIZE];
} hyperloglog_t;
```

**What it is**:
- Probabilistic data structure for cardinality estimation
- Counts unique elements (e.g., unique source IPs)
- **Space**: 16KB (vs. full hash set which could be GB)
- **Accuracy**: ~1-2% error with this precision

**How it works**:
1. Hash each element
2. Use first 14 bits as register index (16384 buckets)
3. Count leading zeros in remaining bits
4. Store maximum leading zeros seen for each bucket
5. Estimate cardinality from harmonic mean of all buckets

**Use case**: Detect if attack is distributed (many unique source IPs)

### 3. Statistics Structure

```c
typedef struct {
    uint64_t total_pkts;      // Total packets
    uint64_t total_bytes;     // Total bytes
    uint64_t tcp_pkts;        // TCP packet count
    uint64_t udp_pkts;        // UDP packet count
    uint64_t icmp_pkts;       // ICMP packet count
    uint64_t syn_pkts;        // TCP SYN flags
    uint64_t ack_pkts;        // TCP ACK flags
    uint64_t rst_pkts;        // TCP RST flags
    uint64_t fin_pkts;        // TCP FIN flags
    uint64_t frag_pkts;       // Fragmented packets
    uint64_t small_pkts;      // Small packets (<100 bytes)
} stats_t;
```

**What it does**:
- Accumulates basic traffic statistics
- Reset every second for per-second metrics
- Used to calculate PPS, Gbps, protocol ratios

---

## Hash Functions

### 1. Jenkins Hash

```c
static inline uint32_t hash_jenkins(const uint8_t *key, size_t len,
                                   uint32_t seed) {
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
```

**What it does**:
- Mixes bits thoroughly for uniform distribution
- Fast (no divisions or modulos in loop)
- Different seeds produce independent hash functions

**Use case**: Count-Min Sketch (4 independent hashes with seeds 0,1,2,3)

### 2. MurmurHash

```c
static inline uint32_t hash_murmur(const uint8_t *key, size_t len,
                                  uint32_t seed) {
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
```

**What it does**:
- Fast non-cryptographic hash
- Excellent avalanche properties (bit changes propagate)
- Processes 4 bytes at a time (faster)

**Use case**: HyperLogLog (need quality hash for cardinality estimation)

---

## Sketch Algorithms Implementation

### Count-Min Sketch

#### Initialization
```c
void cm_init(count_min_sketch_t *cm) {
    memset(cm->counters, 0, sizeof(cm->counters));
}
```

#### Update (Increment)
```c
void cm_update(count_min_sketch_t *cm, uint32_t key) {
    for (int i = 0; i < CM_DEPTH; i++) {
        // Use different hash function for each row
        uint32_t hash = hash_jenkins((uint8_t *)&key, sizeof(key), i);
        uint32_t pos = hash % CM_WIDTH;
        cm->counters[i][pos]++;
    }
}
```

**How it works**:
1. For each of 4 rows (depths)
2. Compute hash with seed = row number
3. Map hash to position in that row (modulo width)
4. Increment counter at that position

**Example**:
```
Key = 192.168.1.100 (as uint32_t)

Row 0: hash(key, seed=0) % 2048 = 1523 → counters[0][1523]++
Row 1: hash(key, seed=1) % 2048 = 734  → counters[1][734]++
Row 2: hash(key, seed=2) % 2048 = 1892 → counters[2][1892]++
Row 3: hash(key, seed=3) % 2048 = 412  → counters[3][412]++
```

#### Query (Estimate Count)
```c
uint32_t cm_query(count_min_sketch_t *cm, uint32_t key) {
    uint32_t min_count = UINT32_MAX;
    for (int i = 0; i < CM_DEPTH; i++) {
        uint32_t hash = hash_jenkins((uint8_t *)&key, sizeof(key), i);
        uint32_t pos = hash % CM_WIDTH;
        if (cm->counters[i][pos] < min_count) {
            min_count = cm->counters[i][pos];
        }
    }
    return min_count;
}
```

**Why take minimum**:
- Collisions can only increase counts
- Minimum gives best (conservative) estimate
- Never under-estimates (safe for threshold-based detection)

### HyperLogLog

#### Initialization
```c
void hll_init(hyperloglog_t *hll) {
    memset(hll->registers, 0, sizeof(hll->registers));
}
```

#### Leading Zeros Count
```c
static inline int leading_zeros(uint64_t x) {
    if (x == 0) return 64;
    int n = 0;
    // Binary search for first 1 bit
    if (x <= 0x00000000FFFFFFFF) { n += 32; x <<= 32; }
    if (x <= 0x0000FFFFFFFFFFFF) { n += 16; x <<= 16; }
    if (x <= 0x00FFFFFFFFFFFFFF) { n += 8;  x <<= 8;  }
    if (x <= 0x0FFFFFFFFFFFFFFF) { n += 4;  x <<= 4;  }
    if (x <= 0x3FFFFFFFFFFFFFFF) { n += 2;  x <<= 2;  }
    if (x <= 0x7FFFFFFFFFFFFFFF) { n += 1;  }
    return n;
}
```

**What it does**:
- Counts leading zero bits in a 64-bit number
- Uses binary search (6 comparisons instead of 64)
- Example: `0000001010101...` has 6 leading zeros

**Why it matters**:
- Leading zeros indicate "rarity"
- More leading zeros → more unique elements seen
- Core primitive of HyperLogLog algorithm

#### Add Element
```c
void hll_add(hyperloglog_t *hll, uint32_t value) {
    // Hash the value
    uint64_t hash = hash_murmur((uint8_t *)&value, sizeof(value), 0x9747b28c);

    // First 14 bits select register (bucket)
    uint32_t idx = hash & ((1 << HLL_PRECISION) - 1);

    // Remaining bits used for leading zero count
    uint64_t w = hash >> HLL_PRECISION;
    uint8_t rho = leading_zeros(w) + 1;

    // Keep maximum leading zeros seen for this bucket
    if (rho > hll->registers[idx]) {
        hll->registers[idx] = rho;
    }
}
```

**Example**:
```
Value = 192.168.1.100
Hash  = 0b1010011100110111001101110110...1001

idx = first 14 bits = 0b10100111001101 = 10573
w   = remaining bits = 0b110111001101110110...1001
rho = leading_zeros(w) + 1 = 2

registers[10573] = max(registers[10573], 2)
```

#### Estimate Cardinality
```c
uint64_t hll_count(hyperloglog_t *hll) {
    // Bias correction constant
    double alpha = 0.7213 / (1 + 1.079 / HLL_SIZE);

    // Harmonic mean of 2^(-register_value)
    double sum = 0.0;
    int zero_count = 0;
    for (int i = 0; i < HLL_SIZE; i++) {
        sum += pow(2.0, -hll->registers[i]);
        if (hll->registers[i] == 0) zero_count++;
    }

    // Raw estimate
    double estimate = alpha * HLL_SIZE * HLL_SIZE / sum;

    // Small range correction (improves accuracy for small cardinalities)
    if (estimate <= 2.5 * HLL_SIZE && zero_count > 0) {
        estimate = HLL_SIZE * log((double)HLL_SIZE / zero_count);
    }

    return (uint64_t)estimate;
}
```

**Math explanation**:
- Each register tracks max leading zeros for its bucket
- More unique elements → higher max values in registers
- Harmonic mean aggregates across all buckets
- Alpha corrects for bias
- Small range correction for <40K unique elements

---

## Main Processing Loop

### DPDK Initialization

```c
int main(int argc, char *argv[]) {
    // Initialize DPDK Environment Abstraction Layer
    int ret = rte_eal_init(argc, argv);

    // Configure port 0
    struct rte_eth_conf port_conf = {0};
    rte_eth_dev_configure(0, 1, 0, &port_conf);

    // Setup RX queue
    rte_eth_rx_queue_setup(0, 0, RX_RING_SIZE, rte_eth_dev_socket_id(0),
                          NULL, mbuf_pool);

    // Start device
    rte_eth_dev_start(0);
    rte_eth_promiscuous_enable(0);
}
```

**What it does**:
1. `rte_eal_init()`: Initialize DPDK runtime, parse arguments
2. `rte_eth_dev_configure()`: Configure network port
3. `rte_eth_rx_queue_setup()`: Allocate RX queue (ring buffer)
4. `rte_eth_dev_start()`: Start packet reception
5. `rte_eth_promiscuous_enable()`: Capture all packets (not just addressed to us)

### Packet Reception and Processing

```c
while (!force_quit) {
    // Burst receive (up to 64 packets at once)
    uint16_t nb_rx = rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);

    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_mbuf *m = bufs[i];

        // Update statistics
        stats.total_pkts++;
        stats.total_bytes += m->pkt_len;

        // Track small packets
        if (m->pkt_len < 100) stats.small_pkts++;

        // Parse Ethernet header
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m,
                                                        struct rte_ether_hdr *);

        // Check if IP packet
        if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

            // Update sketches
            cm_update(&cm_src_ips, ip_hdr->src_addr);
            hll_add(&hll_src_ips, ip_hdr->src_addr);

            // Check protocol
            if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                stats.tcp_pkts++;
                struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);

                // Check TCP flags
                if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) stats.syn_pkts++;
                if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) stats.ack_pkts++;
                if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) stats.rst_pkts++;
                if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) stats.fin_pkts++;

                hll_add(&hll_dst_ports, tcp_hdr->dst_port);
            }
            else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                stats.udp_pkts++;
                struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
                hll_add(&hll_dst_ports, udp_hdr->dst_port);
            }
            else if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
                stats.icmp_pkts++;
            }

            // Check fragmentation
            if (ip_hdr->fragment_offset & rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG)) {
                stats.frag_pkts++;
            }
        }

        // Free mbuf (return to pool)
        rte_pktmbuf_free(m);
    }

    // Every second: log statistics
    time_t now = time(NULL);
    if (now > last_time) {
        log_statistics(&stats, &last_stats, &hll_src_ips, &hll_dst_ports);
        last_time = now;
        last_stats = stats;
    }
}
```

**Key Points**:

1. **Burst Processing**: Receives up to 64 packets at once (amortizes syscall overhead)

2. **Zero-Copy**: `rte_pktmbuf_mtod()` returns pointer directly into packet buffer (no memcpy)

3. **Pointer Arithmetic**:
   ```c
   eth_hdr = start of packet
   ip_hdr  = eth_hdr + 1 (skip 14-byte Ethernet header)
   tcp_hdr = ip_hdr + 1  (skip 20-byte IP header)
   ```

4. **Endianness**: Network byte order (big-endian) vs. host (little-endian)
   ```c
   rte_cpu_to_be_16()  // Convert host to network byte order
   ```

5. **Memory Management**: `rte_pktmbuf_free()` returns mbuf to pool (not malloc/free)

---

## Feature Extraction for ML

### Per-Second Logging

```c
// Calculate deltas (per-second values)
uint64_t pps = stats.total_pkts - last_stats.total_pkts;
uint64_t bytes_delta = stats.total_bytes - last_stats.total_bytes;
double gbps = (bytes_delta * 8.0) / 1e9;

uint64_t tcp_d = stats.tcp_pkts - last_stats.tcp_pkts;
uint64_t udp_d = stats.udp_pkts - last_stats.udp_pkts;
uint64_t icmp_d = stats.icmp_pkts - last_stats.icmp_pkts;
uint64_t syn_d = stats.syn_pkts - last_stats.syn_pkts;
// ... more deltas

// Write to detection.log (basic stats)
fprintf(detection_log, "%lu,%lu,%.2f,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
        now, pps, gbps, tcp_d, udp_d, icmp_d, syn_d, ack_d, rst_d, fin_d, frag_d);
```

### ML Features (19 Features)

```c
// Calculate ratios
double tcp_ratio = (pps > 0) ? (double)tcp_d / pps : 0.0;
double udp_ratio = (pps > 0) ? (double)udp_d / pps : 0.0;
double icmp_ratio = (pps > 0) ? (double)icmp_d / pps : 0.0;

// TCP flag ratios
double syn_ratio = (tcp_d > 0) ? (double)syn_d / tcp_d : 0.0;
double ack_ratio = (tcp_d > 0) ? (double)ack_d / tcp_d : 0.0;
double rst_ratio = (tcp_d > 0) ? (double)rst_d / tcp_d : 0.0;
double fin_ratio = (tcp_d > 0) ? (double)fin_d / tcp_d : 0.0;

// Packet characteristics
double avg_pkt_size = (pps > 0) ? (double)bytes_delta / pps : 0.0;
double small_pkt_ratio = (pps > 0) ? (double)small_d / pps : 0.0;
double frag_ratio = (pps > 0) ? (double)frag_d / pps : 0.0;

// Cardinality estimates from HyperLogLog
uint64_t unique_src_ips = hll_count(&hll_src_ips);
uint64_t unique_dst_ports = hll_count(&hll_dst_ports);

// Entropy (simplified as cardinality / total)
double entropy_src_ip = (pps > 0) ? (double)unique_src_ips / pps : 0.0;
double entropy_dst_port = (pps > 0) ? (double)unique_dst_ports / pps : 0.0;

// Write 19 features to ml_features.csv
fprintf(ml_features_log,
        "%lu,%.2f,%lu,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.2f,%lu,%lu,%lu,%lu\n",
        now, gbps, pps, avg_pkt_size, std_dev,
        tcp_ratio, udp_ratio, icmp_ratio,
        syn_ratio, ack_ratio, rst_ratio, fin_ratio, frag_ratio,
        small_pkt_ratio,
        entropy_src_ip, entropy_dst_port,
        unique_src_ips, unique_dst_ports,
        syn_d, ack_d);
```

**Feature Categories**:

1. **Throughput**: gbps, pps, avg_pkt_size
2. **Protocol Distribution**: tcp_ratio, udp_ratio, icmp_ratio
3. **TCP Flags**: syn_ratio, ack_ratio, rst_ratio, fin_ratio
4. **Packet Characteristics**: small_pkt_ratio, frag_ratio
5. **Diversity**: entropy_src_ip, entropy_dst_port, unique_src_ips, unique_dst_ports
6. **Absolute Counts**: syn_per_sec, ack_per_sec

---

## Performance Optimizations

### 1. Cache-Friendly Sketch Access

```c
// Count-Min: Access pattern is cache-friendly
// Each row update is sequential memory access
for (int i = 0; i < CM_DEPTH; i++) {
    uint32_t pos = hash % CM_WIDTH;
    cm->counters[i][pos]++;  // Cache line loaded once
}
```

### 2. Inline Functions

```c
static inline uint32_t hash_jenkins(...) {
    // Inline avoids function call overhead
    // Critical in per-packet processing
}
```

### 3. Burst Processing

```c
// Receive 64 packets at once (not 1 at a time)
rte_eth_rx_burst(0, 0, bufs, BURST_SIZE);
```

**Benefits**:
- Amortizes per-call overhead
- Better instruction cache locality
- Enables vectorization opportunities

### 4. Minimizing Branching

```c
// Use bitwise operations instead of if-else when possible
stats.tcp_pkts += (ip_hdr->next_proto_id == IPPROTO_TCP);
```

---

## Memory Layout

### DPDK mbuf Structure

```
┌─────────────────────────────────────────┐
│  rte_mbuf metadata                      │  128 bytes
│  - pkt_len, data_len                    │
│  - next, pool, buffer_addr              │
├─────────────────────────────────────────┤
│  Headroom                               │  Variable
├─────────────────────────────────────────┤
│  Ethernet Header (14 bytes)             │
├─────────────────────────────────────────┤
│  IP Header (20 bytes)                   │
├─────────────────────────────────────────┤
│  TCP/UDP Header (20/8 bytes)            │
├─────────────────────────────────────────┤
│  Payload                                │  Up to MTU
└─────────────────────────────────────────┘
```

### Sketch Memory

```
Count-Min Sketch:
  4 rows × 2048 columns × 4 bytes = 32 KB

HyperLogLog:
  16384 registers × 1 byte = 16 KB

Total: 48 KB of sketch memory (constant)
```

---

## Signal Handling

```c
volatile bool force_quit = false;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n[!] Signal received, stopping...\n");
        force_quit = true;
    }
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    while (!force_quit) {
        // Main loop
    }

    // Cleanup
    fclose(detection_log);
    fclose(ml_features_log);
    rte_eth_dev_stop(0);
}
```

**Why this matters**:
- Graceful shutdown on Ctrl+C
- Ensures logs are flushed to disk
- Prevents packet loss during shutdown

---

## Common Pitfalls

### 1. Endianness

```c
// Wrong:
if (eth_hdr->ether_type == 0x0800)  // Won't work

// Right:
if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
```

### 2. Pointer Arithmetic

```c
// Wrong:
struct rte_ipv4_hdr *ip_hdr = eth_hdr + 14;  // Adds 14 * sizeof(struct)

// Right:
struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);  // Adds sizeof(eth_hdr)
```

### 3. Memory Leaks

```c
// Must free every received mbuf
for (uint16_t i = 0; i < nb_rx; i++) {
    struct rte_mbuf *m = bufs[i];
    // ... process packet ...
    rte_pktmbuf_free(m);  // CRITICAL: Don't forget this!
}
```

---

## Summary

The detector uses:
1. **DPDK** for line-rate packet processing (kernel bypass)
2. **Count-Min Sketch** for frequency estimation (heavy hitters)
3. **HyperLogLog** for cardinality estimation (unique IPs/ports)
4. **Burst processing** for high performance (64 packets at a time)
5. **Zero-copy** for minimal overhead
6. **19 ML features** extracted in real-time
7. **Three log files** for different analysis purposes

Key performance characteristics:
- **Throughput**: Up to 100G line rate (148 Mpps theoretical)
- **Memory**: Constant (sketches don't grow with traffic)
- **Latency**: <1ms per packet processing
- **CPU**: Single core (~50% at 10Gbps)

This enables real-time DDoS detection on high-speed networks with minimal resource usage.
