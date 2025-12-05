/**
 * ML Inference - EMBEDDED in DPDK Detector
 * NO HTTP, NO sockets, NO external processes
 */

#ifndef ML_INFERENCE_H
#define ML_INFERENCE_H

#include <stdint.h>
#include <stdbool.h>

#define ML_NUM_FEATURES 13
#define ML_NUM_CLASSES 5

// Feature vector from sketch stats
struct ml_features {
    float total_packets;
    float total_bytes;
    float udp_packets;
    float tcp_packets;
    float icmp_packets;
    float syn_packets;
    float http_requests;
    float baseline_packets;
    float attack_packets;
    float udp_tcp_ratio;
    float syn_total_ratio;
    float baseline_attack_ratio;
    float bytes_per_packet;
};

// ML prediction result
struct ml_prediction {
    int predicted_class;      // 0=benign, 1=udp_flood, 2=syn_flood, 3=icmp_flood, 4=mixed
    float confidence;
    float probabilities[ML_NUM_CLASSES];
};

// Opaque model handle
typedef void* ml_model_handle;

// Initialize model (call once in main)
ml_model_handle ml_init(const char *model_path);

// Predict (call in coordinator every 50ms)
int ml_predict(ml_model_handle model, const struct ml_features *features, struct ml_prediction *prediction);

// Cleanup
void ml_cleanup(ml_model_handle model);

// Helper to build features
void ml_build_features(struct ml_features *feat,
                       uint64_t total_pkts, uint64_t total_bytes,
                       uint64_t udp_pkts, uint64_t tcp_pkts, uint64_t icmp_pkts,
                       uint64_t syn_pkts, uint64_t http_reqs,
                       uint64_t baseline_pkts, uint64_t attack_pkts);

// Get class name
const char* ml_get_class_name(int class_id);

#endif
