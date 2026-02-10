#!/usr/bin/env python3
"""
Sketch Feature Definitions

14 base features from OctoSketch multi-scale + Ring Buffer temporal analysis.
+ 50 optional SKETCH-ADV features (48 per-protocol + 2 packet size).
Total: 64 features when --sketch-adv is enabled.
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

# Per-protocol sketch features (4 features × 12 protocols = 48)
SKETCH_ADV_PROTOCOLS = [
    'dns', 'ntp', 'snmp', 'ssdp', 'portmap', 'netbios',
    'ldap', 'mssql', 'tftp', 'syn', 'http', 'udp_other',
]

SKETCH_ADV_PER_PROTO = ['pps', 'heavy_hitters', 'ip_concentration', 'ratio_vs_total']

SKETCH_ADV_FEATURES = []
for proto in SKETCH_ADV_PROTOCOLS:
    for feat in SKETCH_ADV_PER_PROTO:
        SKETCH_ADV_FEATURES.append(f'{feat}_{proto}')

# Packet size features (2)
SKETCH_ADV_FEATURES += ['avg_packet_size', 'packet_size_variance']

# Combined: 14 + 50 = 64
SKETCH_FEATURES_ALL = SKETCH_FEATURES + SKETCH_ADV_FEATURES


def get_feature_columns(include_adv=False):
    """Return sketch feature column names"""
    if include_adv:
        return list(SKETCH_FEATURES_ALL)
    return list(SKETCH_FEATURES)


def filter_dataframe(df, include_adv=False):
    """Filter DataFrame to keep only sketch features + label"""
    features = SKETCH_FEATURES_ALL if include_adv else SKETCH_FEATURES
    available = [c for c in features if c in df.columns]
    missing = [c for c in features if c not in df.columns]
    if missing:
        print(f"[WARNING] Missing columns: {missing}")
    keep = available + ['label']
    if 'run_id' in df.columns:
        keep.append('run_id')
    return df[keep]
