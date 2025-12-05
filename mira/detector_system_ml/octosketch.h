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

/* OctoSketch structure - per-worker (NO ATOMICS) */
struct octosketch {
    /* Counter matrix: ROWS x COLS - LOCAL counters (no atomics needed) */
    uint32_t counters[SKETCH_ROWS][SKETCH_COLS];

    /* Hash seeds for each row */
    uint32_t seeds[SKETCH_ROWS];

    /* Statistics - LOCAL (no atomics) */
    uint64_t total_updates;
    uint64_t total_bytes;

    /* Per-IP tracking for heavy hitters - LOCAL (no atomics) */
    uint32_t ip_counts[65536];  /* Hash table for Top-K */

    /* Metadata */
    char name[32];
    uint64_t window_start_tsc;
} __rte_cache_aligned;

/* Initialize sketch with name and seeds */
static inline void octosketch_init(struct octosketch *sketch, const char *name)
{
    memset(sketch, 0, sizeof(struct octosketch));
    strncpy(sketch->name, name, sizeof(sketch->name) - 1);

    /* Initialize hash seeds (different per row) */
    sketch->seeds[0] = 0xdeadbeef;
    sketch->seeds[1] = 0xc0ffee00;
    sketch->seeds[2] = 0xbaadf00d;
    sketch->seeds[3] = 0xfeedface;
    sketch->seeds[4] = 0xcafebabe;
    sketch->seeds[5] = 0x12345678;
    sketch->seeds[6] = 0x9abcdef0;
    sketch->seeds[7] = 0x11223344;
}

/* Hash function for sketch row */
static inline uint32_t octosketch_hash(uint32_t key, uint32_t seed)
{
    return rte_jhash_1word(key, seed) & SKETCH_MASK;
}

/* Update sketch with IP address (LOCAL - no atomics) */
static inline void octosketch_update_ip(struct octosketch *sketch, uint32_t ip, uint32_t increment)
{
    /* Update all rows with different hash functions */
    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        sketch->counters[i][col] += increment;
    }

    /* Update IP-specific counter for heavy hitter tracking */
    uint32_t ip_idx = (ip >> 16) ^ (ip & 0xFFFF);  /* Simple hash */
    ip_idx = ip_idx % 65536;
    sketch->ip_counts[ip_idx] += increment;

    /* Update statistics */
    sketch->total_updates += increment;
}

/* Update sketch with bytes */
static inline void octosketch_update_bytes(struct octosketch *sketch, uint64_t bytes)
{
    sketch->total_bytes += bytes;
}

/* Query sketch for IP count (min across all rows - Conservative Update) */
static inline uint32_t octosketch_query_ip(struct octosketch *sketch, uint32_t ip)
{
    uint32_t min_count = UINT32_MAX;

    for (int i = 0; i < SKETCH_ROWS; i++) {
        uint32_t col = octosketch_hash(ip, sketch->seeds[i]);
        uint32_t count = sketch->counters[i][col];
        if (count < min_count) {
            min_count = count;
        }
    }

    return min_count;
}

/* Get total count across sketch */
static inline uint64_t octosketch_get_total(struct octosketch *sketch)
{
    return sketch->total_updates;
}

/* Get total bytes */
static inline uint64_t octosketch_get_bytes(struct octosketch *sketch)
{
    return sketch->total_bytes;
}

/* Merge multiple sketches (coordinator aggregation) */
static inline void octosketch_merge(struct octosketch *dst, struct octosketch *src[], int num_sketches)
{
    /* Zero out destination */
    memset(dst->counters, 0, sizeof(dst->counters));
    memset(dst->ip_counts, 0, sizeof(dst->ip_counts));
    dst->total_updates = 0;
    dst->total_bytes = 0;

    /* Sum counters from all source sketches */
    for (int s = 0; s < num_sketches; s++) {
        for (int i = 0; i < SKETCH_ROWS; i++) {
            for (int j = 0; j < SKETCH_COLS; j++) {
                dst->counters[i][j] += src[s]->counters[i][j];
            }
        }

        /* Merge IP counts */
        for (int i = 0; i < 65536; i++) {
            dst->ip_counts[i] += src[s]->ip_counts[i];
        }

        /* Sum statistics */
        dst->total_updates += src[s]->total_updates;
        dst->total_bytes += src[s]->total_bytes;
    }
}

/* Find Top-K heavy hitters (LOCAL - no atomics) */
static inline void octosketch_top_k(struct octosketch *sketch, int k,
                                   struct heavy_hitter *results)
{
    /* Simple heap-based Top-K from IP counts */
    memset(results, 0, k * sizeof(struct heavy_hitter));

    for (uint32_t i = 0; i < 65536; i++) {
        uint32_t count = sketch->ip_counts[i];
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
    memset(sketch->counters, 0, sizeof(sketch->counters));

    /* Reset IP counts */
    memset(sketch->ip_counts, 0, sizeof(sketch->ip_counts));

    /* Reset statistics */
    sketch->total_updates = 0;
    sketch->total_bytes = 0;
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
