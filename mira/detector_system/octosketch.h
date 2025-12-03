/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 MIRA Project
 *
 * OctoSketch - Memory-efficient sketch for DDoS detection
 *
 * Based on: "Elastic Sketch: Adaptive and Fast Network-wide Measurements" (SIGCOMM 2018)
 * Optimized for DPDK multi-core environments with atomic operations
 */

#ifndef OCTOSKETCH_H
#define OCTOSKETCH_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_atomic.h>
#include <rte_jhash.h>

/* Sketch configuration */
#define SKETCH_ROWS 8          /* Number of hash functions */
#define SKETCH_COLS 4096       /* Buckets per row (must be power of 2) */
#define SKETCH_MASK (SKETCH_COLS - 1)
#define SKETCH_TOP_K 10        /* Track top-10 heavy hitters */

/* Flow key for hashing */
struct flow_key {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t padding[3];
} __attribute__((packed));

/* Counter cell - atomic for lock-free updates */
struct sketch_cell {
    rte_atomic32_t count;
} __rte_cache_aligned;

/* Heavy hitter entry */
struct heavy_hitter {
    uint32_t ip;
    uint32_t count;
};

/* OctoSketch structure - one per attack type */
struct octosketch {
    /* Counter matrix: ROWS x COLS */
    struct sketch_cell counters[SKETCH_ROWS][SKETCH_COLS];

    /* Hash seeds for each row */
    uint32_t seeds[SKETCH_ROWS];

    /* Statistics */
    rte_atomic64_t total_updates;
    rte_atomic64_t total_bytes;

    /* Per-IP tracking for heavy hitters (simplified) */
    rte_atomic32_t ip_counts[65536];  /* Hash table for Top-K */

    /* Metadata */
    char name[32];
    uint64_t window_start_tsc;
} __rte_cache_aligned;

/* Initialize sketch with name and seeds */
static inline void octosketch_init(struct octosketch *sketch, const char *name)
{
    memset(sketch, 0, sizeof(struct octosketch));
    strncpy(sketch->name, name, sizeof(sketch->name) - 1);

    /* Initialize counters */
    for (int i = 0; i < SKETCH_ROWS; i++) {
        for (int j = 0; j < SKETCH_COLS; j++) {
            rte_atomic32_init(&sketch->counters[i][j].count);
        }
    }

    /* Initialize IP counts */
    for (int i = 0; i < 65536; i++) {
        rte_atomic32_init(&sketch->ip_counts[i]);
    }

    /* Initialize hash seeds (different per row) */
    sketch->seeds[0] = 0xdeadbeef;
    sketch->seeds[1] = 0xc0ffee00;
    sketch->seeds[2] = 0xbaadf00d;
    sketch->seeds[3] = 0xfeedface;
    sketch->seeds[4] = 0xcafebabe;
    sketch->seeds[5] = 0x12345678;
    sketch->seeds[6] = 0x9abcdef0;
    sketch->seeds[7] = 0x11223344;

    rte_atomic64_init(&sketch->total_updates);
    rte_atomic64_init(&sketch->total_bytes);
}

/* Hash function for sketch row */
static inline uint32_t octosketch_hash(uint32_t key, uint32_t seed)
{
    return rte_jhash_1word(key, seed) & SKETCH_MASK;
}

/* Update sketch with IP address (lock-free) */
static inline void octosketch_update_ip(struct octosketch *sketch, uint32_t ip, uint32_t increment)
{
    /* Update all rows with different hash functions */
    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        rte_atomic32_add(&sketch->counters[i][col].count, increment);
    }

    /* Update IP-specific counter for heavy hitter tracking */
    uint32_t ip_idx = (ip >> 16) ^ (ip & 0xFFFF);  /* Simple hash */
    ip_idx = ip_idx % 65536;
    rte_atomic32_add(&sketch->ip_counts[ip_idx], increment);

    /* Update statistics */
    rte_atomic64_add(&sketch->total_updates, increment);
}

/* Update sketch with bytes */
static inline void octosketch_update_bytes(struct octosketch *sketch, uint64_t bytes)
{
    rte_atomic64_add(&sketch->total_bytes, bytes);
}

/* Query sketch for IP count (min across all rows - Conservative Update) */
static inline uint32_t octosketch_query_ip(struct octosketch *sketch, uint32_t ip)
{
    uint32_t min_count = UINT32_MAX;

    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        uint32_t count = rte_atomic32_read(&sketch->counters[i][col].count);
        if (count < min_count) {
            min_count = count;
        }
    }

    return min_count;
}

/* Get total count across sketch (sum of first row - approximation) */
static inline uint64_t octosketch_get_total(struct octosketch *sketch)
{
    return rte_atomic64_read(&sketch->total_updates);
}

/* Get total bytes */
static inline uint64_t octosketch_get_bytes(struct octosketch *sketch)
{
    return rte_atomic64_read(&sketch->total_bytes);
}

/* Find Top-K heavy hitters (simplified: scan IP hash table) */
static inline void octosketch_top_k(struct octosketch *sketch, int k,
                                   struct heavy_hitter *results)
{
    /* Simple heap-based Top-K from IP counts */
    memset(results, 0, k * sizeof(struct heavy_hitter));

    for (uint32_t i = 0; i < 65536; i++) {
        uint32_t count = rte_atomic32_read(&sketch->ip_counts[i]);
        if (count == 0) continue;

        /* Reconstruct approximate IP from hash index */
        uint32_t approx_ip = (i << 16) | i;  /* Simplified reconstruction */

        /* Insert into Top-K if larger than smallest */
        for (int j = 0; j < k; j++) {
            if (count > results[j].count) {
                /* Shift down */
                for (int l = k - 1; l > j; l--) {
                    results[l] = results[l - 1];
                }
                results[j].ip = approx_ip;
                results[j].count = count;
                break;
            }
        }
    }
}

/* Reset sketch for new window */
static inline void octosketch_reset(struct octosketch *sketch)
{
    /* Reset counters */
    for (int i = 0; i < SKETCH_ROWS; i++) {
        for (int j = 0; j < SKETCH_COLS; j++) {
            rte_atomic32_set(&sketch->counters[i][j].count, 0);
        }
    }

    /* Reset IP counts */
    for (int i = 0; i < 65536; i++) {
        rte_atomic32_set(&sketch->ip_counts[i], 0);
    }

    /* Reset statistics */
    rte_atomic64_set(&sketch->total_updates, 0);
    rte_atomic64_set(&sketch->total_bytes, 0);
}

/* Get memory footprint */
static inline size_t octosketch_memory_size(void)
{
    return sizeof(struct octosketch);
}

/* Calculate packets per second from sketch */
static inline double octosketch_pps(struct octosketch *sketch, double window_sec)
{
    if (window_sec < 0.001) return 0.0;
    uint64_t total = octosketch_get_total(sketch);
    return (double)total / window_sec;
}

/* Calculate throughput in Gbps from sketch */
static inline double octosketch_gbps(struct octosketch *sketch, double window_sec)
{
    if (window_sec < 0.001) return 0.0;
    uint64_t total_bytes = octosketch_get_bytes(sketch);
    return (total_bytes * 8.0) / (window_sec * 1e9);
}

#endif /* OCTOSKETCH_H */
