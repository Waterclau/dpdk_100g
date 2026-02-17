/**
 * ML Inference Implementation using LightGBM C API
 * EMBEDDED - no external processes
 *
 * Loads:
 *   lightgbm_model.txt  - LightGBM model
 *   feature_scaler.json - StandardScaler mean/scale (simple JSON parser)
 *   label_mapping.json  - Class index -> name mapping
 */

#include "ml_inference.h"
#include <LightGBM/c_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct ml_model_internal {
    BoosterHandle booster;
    int num_features;
    int num_classes;

    /* Feature scaler (StandardScaler: (x - mean) / scale) */
    double scaler_mean[ML_MAX_FEATURES];
    double scaler_scale[ML_MAX_FEATURES];
    bool scaler_loaded;

    /* Class names */
    char class_names[ML_MAX_CLASSES][ML_MAX_CLASS_NAME];
    int class_count;
};

/* ========== Minimal JSON number array parser ========== */

/**
 * Parse a JSON array of numbers: [1.23, 4.56, ...]
 * Returns number of values parsed.
 */
static int parse_json_array(const char *json, const char *key, double *out, int max_count)
{
    /* Find "key": [ */
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *pos = strstr(json, search);
    if (!pos) return 0;

    /* Find opening bracket */
    pos = strchr(pos, '[');
    if (!pos) return 0;
    pos++; /* skip '[' */

    int count = 0;
    while (*pos && *pos != ']' && count < max_count) {
        /* Skip whitespace and commas */
        while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r' || *pos == ',')
            pos++;
        if (*pos == ']') break;

        /* Parse number */
        char *end;
        double val = strtod(pos, &end);
        if (end == pos) break; /* parse error */
        out[count++] = val;
        pos = end;
    }

    return count;
}

/**
 * Parse a JSON string value: "key": "value"
 * Returns 1 on success, 0 on failure.
 */
static int parse_json_string(const char *json, const char *key_prefix, int key_idx,
                              char *out, int max_len)
{
    /* Find "key_idx": "value" */
    char search[64];
    snprintf(search, sizeof(search), "\"%d\"", key_idx);
    const char *pos = strstr(json, search);
    if (!pos) return 0;

    /* Find the colon, then the opening quote of the value */
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return 0;
    pos++;
    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos != '"') return 0;
    pos++; /* skip opening quote */

    /* Copy until closing quote */
    int i = 0;
    while (*pos && *pos != '"' && i < max_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';

    (void)key_prefix;
    return 1;
}

/* ========== Read entire file into buffer ========== */

static char* read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 10 * 1024 * 1024) {  /* max 10 MB */
        fclose(f);
        return NULL;
    }

    char *buf = malloc(size + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t read = fread(buf, 1, size, f);
    buf[read] = '\0';
    fclose(f);
    return buf;
}

/* ========== Public API ========== */

ml_model_handle ml_init(const char *model_dir)
{
    struct ml_model_internal *model = calloc(1, sizeof(*model));
    if (!model) {
        fprintf(stderr, "[ML] Failed to allocate model\n");
        return NULL;
    }

    /* Build file paths */
    char model_path[512], scaler_path[512], mapping_path[512];
    snprintf(model_path, sizeof(model_path), "%s/lightgbm_model.txt", model_dir);
    snprintf(scaler_path, sizeof(scaler_path), "%s/feature_scaler.json", model_dir);
    snprintf(mapping_path, sizeof(mapping_path), "%s/label_mapping.json", model_dir);

    /* 1. Load LightGBM model */
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

    printf("[ML] Model loaded: %d features, %d classes, %d iterations\n",
           model->num_features, model->num_classes, num_iterations);

    /* 2. Load feature scaler (optional but strongly recommended) */
    char *scaler_json = read_file(scaler_path);
    if (scaler_json) {
        int n_mean = parse_json_array(scaler_json, "mean", model->scaler_mean, ML_MAX_FEATURES);
        int n_scale = parse_json_array(scaler_json, "scale", model->scaler_scale, ML_MAX_FEATURES);
        free(scaler_json);

        if (n_mean == model->num_features && n_scale == model->num_features) {
            model->scaler_loaded = true;
            printf("[ML] Scaler loaded: %d features (mean/std normalization)\n", n_mean);
        } else {
            fprintf(stderr, "[ML] WARNING: Scaler dimension mismatch (got %d/%d, expected %d)\n",
                    n_mean, n_scale, model->num_features);
            model->scaler_loaded = false;
        }
    } else {
        fprintf(stderr, "[ML] WARNING: No scaler found at %s - using raw features\n", scaler_path);
        model->scaler_loaded = false;
    }

    /* 3. Load label mapping */
    char *mapping_json = read_file(mapping_path);
    if (mapping_json) {
        model->class_count = 0;
        for (int i = 0; i < model->num_classes && i < ML_MAX_CLASSES; i++) {
            if (parse_json_string(mapping_json, "", i, model->class_names[i], ML_MAX_CLASS_NAME)) {
                model->class_count++;
            } else {
                snprintf(model->class_names[i], ML_MAX_CLASS_NAME, "class_%d", i);
                model->class_count++;
            }
        }
        free(mapping_json);
        printf("[ML] Label mapping loaded: %d classes [", model->class_count);
        for (int i = 0; i < model->class_count; i++) {
            printf("%s%s", model->class_names[i], i < model->class_count - 1 ? ", " : "");
        }
        printf("]\n");
    } else {
        fprintf(stderr, "[ML] WARNING: No label mapping at %s - using generic names\n", mapping_path);
        for (int i = 0; i < model->num_classes && i < ML_MAX_CLASSES; i++) {
            snprintf(model->class_names[i], ML_MAX_CLASS_NAME, "class_%d", i);
        }
        model->class_count = model->num_classes;
    }

    return (ml_model_handle)model;
}

int ml_predict(ml_model_handle handle, const double *features, int num_features,
               struct ml_prediction *prediction)
{
    if (!handle || !features || !prediction) return -1;

    struct ml_model_internal *model = (struct ml_model_internal *)handle;

    if (num_features != model->num_features) {
        fprintf(stderr, "[ML] Feature count mismatch: got %d, expected %d\n",
                num_features, model->num_features);
        return -1;
    }

    /* Apply scaler: (x - mean) / scale */
    double scaled[ML_MAX_FEATURES];
    if (model->scaler_loaded) {
        for (int i = 0; i < num_features; i++) {
            double s = model->scaler_scale[i];
            scaled[i] = (s > 1e-15) ? (features[i] - model->scaler_mean[i]) / s : 0.0;
        }
    } else {
        memcpy(scaled, features, num_features * sizeof(double));
    }

    /* Run LightGBM prediction */
    int64_t out_len;
    double out_result[ML_MAX_CLASSES];

    int ret = LGBM_BoosterPredictForMat(
        model->booster,
        scaled,
        C_API_DTYPE_FLOAT64,
        1,                    /* nrow */
        num_features,         /* ncol */
        1,                    /* is_row_major */
        C_API_PREDICT_NORMAL,
        0,                    /* start_iteration */
        -1,                   /* num_iteration (use best) */
        "",                   /* parameter */
        &out_len,
        out_result
    );

    if (ret != 0 || out_len != model->num_classes) {
        return -1;
    }

    /* Find argmax */
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
    for (int i = 0; i < model->num_classes && i < ML_MAX_CLASSES; i++) {
        prediction->probabilities[i] = (float)out_result[i];
    }

    return 0;
}

int ml_get_num_features(ml_model_handle handle)
{
    if (!handle) return 0;
    return ((struct ml_model_internal *)handle)->num_features;
}

int ml_get_num_classes(ml_model_handle handle)
{
    if (!handle) return 0;
    return ((struct ml_model_internal *)handle)->num_classes;
}

const char* ml_get_class_name(ml_model_handle handle, int class_id)
{
    if (!handle) return "unknown";
    struct ml_model_internal *model = (struct ml_model_internal *)handle;
    if (class_id >= 0 && class_id < model->class_count) {
        return model->class_names[class_id];
    }
    return "unknown";
}

void ml_cleanup(ml_model_handle handle)
{
    if (handle) {
        struct ml_model_internal *model = (struct ml_model_internal *)handle;
        LGBM_BoosterFree(model->booster);
        free(model);
        printf("[ML] Model cleaned up\n");
    }
}
