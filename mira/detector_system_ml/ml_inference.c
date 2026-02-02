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
        features->syn_packets, features->http_requests, features->dns_queries,
        features->baseline_packets, features->attack_packets,
        features->udp_tcp_ratio, features->syn_total_ratio,
        features->baseline_attack_ratio, features->bytes_per_packet,
        features->ntp_monlist_queries, features->ntp_responses, features->avg_ntp_response_size,
        features->dns_any_queries, features->dns_txt_queries, features->dns_responses, features->avg_dns_response_size,
        features->snmp_getbulk_requests, features->snmp_responses, features->avg_snmp_response_size,
        features->ssdp_msearch_packets, features->ssdp_responses,
        features->portmap_getport_calls, features->portmap_dump_calls,
        features->netbios_name_queries, features->netbios_dgram_packets,
        features->ldap_bind_requests, features->ldap_search_requests,
        features->mssql_sqlbatch_packets, features->mssql_rpc_packets,
        features->tftp_rrq_packets, features->tftp_wrq_packets,
        features->ntp_amplification_factor, features->dns_amplification_factor, features->snmp_amplification_factor,
        features->query_response_ratio, features->fragmentation_ratio, features->syn_ack_ratio
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

const char* ml_get_class_name(int class_id)
{
    if (class_id >= 0 && class_id < ML_NUM_CLASSES) {
        return CLASS_NAMES[class_id];
    }
    return "unknown";
}
