/**
 * ML Inference - EMBEDDED in DPDK Detector
 * NO HTTP, NO sockets, NO external processes
 *
 * Generic interface: supports any feature count and class count.
 * Loads model, scaler (mean/std), and label mapping from files.
 *
 * Modes:
 *   dpi_sketch  (75 features, 14 classes)
 *   sketch_adv  (64 features, 14 classes)
 */

#ifndef ML_INFERENCE_H
#define ML_INFERENCE_H

#include <stdint.h>
#include <stdbool.h>

#define ML_MAX_FEATURES 128
#define ML_MAX_CLASSES  32
#define ML_MAX_CLASS_NAME 32

/* ML prediction result */
struct ml_prediction {
    int predicted_class;
    float confidence;
    float probabilities[ML_MAX_CLASSES];
};

/* Opaque model handle */
typedef void* ml_model_handle;

/**
 * Initialize ML model from directory containing:
 *   lightgbm_model.txt    - trained LightGBM model
 *   feature_scaler.json   - {"mean": [...], "scale": [...]}
 *   label_mapping.json    - {"0": "benign", "1": "dns", ...}
 *
 * Returns handle or NULL on failure.
 */
ml_model_handle ml_init(const char *model_dir);

/**
 * Predict on a raw feature array (UNSCALED).
 * Scaling is applied internally using loaded scaler.
 *
 * @param model      Model handle from ml_init()
 * @param features   Raw feature values (num_features doubles)
 * @param num_features  Number of features in array
 * @param prediction Output prediction result
 * @return 0 on success, -1 on error
 */
int ml_predict(ml_model_handle model, const double *features, int num_features,
               struct ml_prediction *prediction);

/* Get number of features the model expects */
int ml_get_num_features(ml_model_handle model);

/* Get number of classes */
int ml_get_num_classes(ml_model_handle model);

/* Get class name by index */
const char* ml_get_class_name(ml_model_handle model, int class_id);

/* Cleanup */
void ml_cleanup(ml_model_handle model);

#endif
