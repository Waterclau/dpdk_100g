#!/usr/bin/env python3
"""
Sketch Feature Definitions

14 features from OctoSketch multi-scale + Ring Buffer temporal analysis.
"""

SKETCH_FEATURES = [
    # Temporal features from Ring Buffer (5)
    'delta_pps_5w',          # PPS change over 5 windows (250ms)
    'delta_pps_10w',         # PPS change over 10 windows (500ms)
    'pps_variance',          # Variance over last 20 windows
    'pps_baseline',          # Running average (adaptive baseline)
    'ratio_vs_baseline',     # Current / baseline ratio
    # Multi-scale features from OctoSketch (9)
    'top_ip_pps_50ms',       # Top attacker PPS (50ms scale)
    'top_ip_pps_1s',         # Top attacker PPS (1s scale)
    'top_ip_pps_1min',       # Top attacker PPS (1min scale)
    'ratio_50ms_1min',       # Burst ratio: 50ms / 1min
    'num_heavy_hitters',     # IPs exceeding threshold
    'ip_concentration',      # Top1 count / total count
    'new_ips_ratio',         # New IPs vs known IPs
    'attack_entropy',        # Distribution entropy
    'adaptive_threshold',    # Current adaptive threshold
]


def get_feature_columns():
    """Return sketch feature column names"""
    return list(SKETCH_FEATURES)


def filter_dataframe(df):
    """Filter DataFrame to keep only sketch features + label"""
    available = [c for c in SKETCH_FEATURES if c in df.columns]
    missing = [c for c in SKETCH_FEATURES if c not in df.columns]
    if missing:
        print(f"[WARNING] Missing columns: {missing}")
    keep = available + ['label']
    if 'run_id' in df.columns:
        keep.append('run_id')
    return df[keep]
