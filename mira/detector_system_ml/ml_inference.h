/**
 * ML Inference - EMBEDDED in DPDK Detector
 * NO HTTP, NO sockets, NO external processes
 *
 * Features: 56 total (42 base + 14 temporal/multi-scale)
 */

#ifndef ML_INFERENCE_H
#define ML_INFERENCE_H

#include <stdint.h>
#include <stdbool.h>

#define ML_NUM_FEATURES 56
#define ML_NUM_CLASSES 14

// Feature vector from sketch stats (56 features)
struct ml_features {
    // Base features (1-14)
    float total_packets;
    float total_bytes;
    float udp_packets;
    float tcp_packets;
    float icmp_packets;
    float syn_packets;
    float http_requests;
    float dns_queries;
    float baseline_packets;
    float attack_packets;
    float udp_tcp_ratio;
    float syn_total_ratio;
    float baseline_attack_ratio;
    float bytes_per_packet;

    // Protocol-specific features (15-36)
    float ntp_monlist_queries;
    float ntp_responses;
    float avg_ntp_response_size;
    float dns_any_queries;
    float dns_txt_queries;
    float dns_responses;
    float avg_dns_response_size;
    float snmp_getbulk_requests;
    float snmp_responses;
    float avg_snmp_response_size;
    float ssdp_msearch_packets;
    float ssdp_responses;
    float portmap_getport_calls;
    float portmap_dump_calls;
    float netbios_name_queries;
    float netbios_dgram_packets;
    float ldap_bind_requests;
    float ldap_search_requests;
    float mssql_sqlbatch_packets;
    float mssql_rpc_packets;
    float tftp_rrq_packets;
    float tftp_wrq_packets;

    // Derived amplification features (37-42)
    float ntp_amplification_factor;
    float dns_amplification_factor;
    float snmp_amplification_factor;
    float query_response_ratio;
    float fragmentation_ratio;
    float syn_ack_ratio;

    // NEW: Temporal features from Ring Buffer (43-47)
    float delta_pps_5w;         // Delta PPS over 250ms
    float delta_pps_10w;        // Delta PPS over 500ms
    float pps_variance;         // Variance over last 20 windows
    float pps_baseline;         // Running average baseline
    float ratio_vs_baseline;    // Current / baseline ratio

    // NEW: Multi-scale features from Sketches (48-56)
    float top_ip_pps_50ms;      // Top attacker PPS (instantaneous)
    float top_ip_pps_1s;        // Top attacker PPS (1 second)
    float top_ip_pps_1min;      // Top attacker PPS (1 minute)
    float ratio_50ms_1min;      // Burst ratio (50ms / 1min)
    float num_heavy_hitters;    // Number of IPs exceeding threshold
    float ip_concentration;     // Top1 / total ratio
    float new_ips_ratio;        // Ratio of new IPs (placeholder)
    float attack_entropy;       // 1 - concentration
    float adaptive_threshold;   // Calculated threshold (for ML only)
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

// Get class name
const char* ml_get_class_name(int class_id);

#endif
