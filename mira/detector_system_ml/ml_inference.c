/**
 * ML Inference Implementation using LightGBM C API
 * EMBEDDED - no external processes
 */

#include "ml_inference.h"
#include <LightGBM/c_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static const char *CLASS_NAMES[] = {
    "benign", "udp_flood", "syn_flood", "icmp_flood", "mixed_attack"
};

struct ml_model_handle_internal {
    BoosterHandle booster;
    int num_features;
    int num_classes;
};

ml_model_handle ml_init(const char *model_path)
{
    struct ml_model_handle_internal *model = calloc(1, sizeof(*model));
    if (!model) {
        fprintf(stderr, "[ML] Failed to allocate model\n");
        return NULL;
    }

    int num_iterations = 0;
    int ret = LGBM_BoosterCreateFromModelfile(model_path, &num_iterations, &model->booster);
    if (ret != 0) {
        fprintf(stderr, "[ML] Failed to load model from %s\n", model_path);
        free(model);
        return NULL;
    }

    ret = LGBM_BoosterGetNumFeature(model->booster, &model->num_features);
    ret |= LGBM_BoosterGetNumClasses(model->booster, &model->num_classes);

    if (ret != 0) {
        fprintf(stderr, "[ML] Failed to get model metadata\n");
        LGBM_BoosterFree(model->booster);
        free(model);
        return NULL;
    }

    printf("[ML] Model loaded: %d features, %d classes\n", model->num_features, model->num_classes);
    return (ml_model_handle)model;
}

int ml_predict(ml_model_handle handle, const struct ml_features *features, struct ml_prediction *prediction)
{
    if (!handle || !features || !prediction) return -1;

    struct ml_model_handle_internal *model = (struct ml_model_handle_internal*)handle;

    // Convert features to array
    double feature_array[ML_NUM_FEATURES] = {
        features->total_packets, features->total_bytes,
        features->udp_packets, features->tcp_packets, features->icmp_packets,
        features->syn_packets, features->http_requests,
        features->baseline_packets, features->attack_packets,
        features->udp_tcp_ratio, features->syn_total_ratio,
        features->baseline_attack_ratio, features->bytes_per_packet
    };

    int64_t out_len;
    double out_result[ML_NUM_CLASSES];

    int ret = LGBM_BoosterPredictForMat(
        model->booster,
        feature_array,
        C_API_DTYPE_FLOAT64,
        1,                    // nrow
        ML_NUM_FEATURES,     // ncol
        1,                    // is_row_major
        C_API_PREDICT_NORMAL,
        0,                    // start_iteration
        -1,                   // num_iteration (use best)
        "",                   // parameter
        &out_len,
        out_result
    );

    if (ret != 0 || out_len != model->num_classes) {
        return -1;
    }

    // Find argmax
    int max_idx = 0;
    double max_prob = out_result[0];
    for (int i = 1; i < model->num_classes; i++) {
        if (out_result[i] > max_prob) {
            max_prob = out_result[i];
            max_idx = i;
        }
    }

    prediction->predicted_class = max_idx;
    prediction->confidence = (float)max_prob;
    for (int i = 0; i < ML_NUM_CLASSES; i++) {
        prediction->probabilities[i] = (float)out_result[i];
    }

    return 0;
}

void ml_cleanup(ml_model_handle handle)
{
    if (handle) {
        struct ml_model_handle_internal *model = (struct ml_model_handle_internal*)handle;
        LGBM_BoosterFree(model->booster);
        free(model);
        printf("[ML] Model cleaned up\n");
    }
}

void ml_build_features(struct ml_features *feat,
                       uint64_t total_pkts, uint64_t total_bytes,
                       uint64_t udp_pkts, uint64_t tcp_pkts, uint64_t icmp_pkts,
                       uint64_t syn_pkts, uint64_t http_reqs,
                       uint64_t baseline_pkts, uint64_t attack_pkts)
{
    feat->total_packets = (float)total_pkts;
    feat->total_bytes = (float)total_bytes;
    feat->udp_packets = (float)udp_pkts;
    feat->tcp_packets = (float)tcp_pkts;
    feat->icmp_packets = (float)icmp_pkts;
    feat->syn_packets = (float)syn_pkts;
    feat->http_requests = (float)http_reqs;
    feat->baseline_packets = (float)baseline_pkts;
    feat->attack_packets = (float)attack_pkts;

    // Derived features
    feat->udp_tcp_ratio = (tcp_pkts > 0) ? ((float)udp_pkts / tcp_pkts) : (float)udp_pkts;
    feat->syn_total_ratio = (total_pkts > 0) ? ((float)syn_pkts / total_pkts) : 0.0f;
    feat->baseline_attack_ratio = (attack_pkts > 0) ? ((float)baseline_pkts / attack_pkts) : (float)baseline_pkts;
    feat->bytes_per_packet = (total_pkts > 0) ? ((float)total_bytes / total_pkts) : 0.0f;
}

const char* ml_get_class_name(int class_id)
{
    if (class_id >= 0 && class_id < ML_NUM_CLASSES) {
        return CLASS_NAMES[class_id];
    }
    return "unknown";
}
