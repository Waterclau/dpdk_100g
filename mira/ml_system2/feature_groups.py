#!/usr/bin/env python3
"""
Feature Definitions for ml_system2

Three feature sets:
  - DPI+Sketch (73):  59 DPI + 14 sketch  (from .log, detector_system original)
  - Sketch-only (14): 14 sketch            (from .log, detector_system2 sin --sketch-adv)
  - Sketch-ADV (64):  14 global + 48 per-protocol + 2 pkt size (from .bin)
"""

# ============================================================
# SKETCH FEATURES (14) - OctoSketch multi-scale + Ring Buffer
# ============================================================
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

# ============================================================
# DPI FEATURES (59) - Deep Packet Inspection counters + ratios + normalized
# ============================================================
DPI_FEATURES = [
    # Original 14 counters + ratios
    'total_packets', 'total_bytes',
    'udp_packets', 'tcp_packets', 'icmp_packets',
    'syn_packets', 'http_requests', 'dns_queries',
    'baseline_packets', 'attack_packets',
    'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio',
    'bytes_per_packet',
    # Protocol-specific counters (22)
    'ntp_monlist_queries', 'ntp_responses', 'avg_ntp_response_size',
    'dns_any_queries', 'dns_txt_queries', 'dns_responses', 'avg_dns_response_size',
    'snmp_getbulk_requests', 'snmp_responses', 'avg_snmp_response_size',
    'ssdp_msearch_packets', 'ssdp_responses',
    'portmap_getport_calls', 'portmap_dump_calls',
    'netbios_name_queries', 'netbios_dgram_packets',
    'ldap_bind_requests', 'ldap_search_requests',
    'mssql_sqlbatch_packets', 'mssql_rpc_packets',
    'tftp_rrq_packets', 'tftp_wrq_packets',
    # Derived amplification ratios (6)
    'ntp_amplification_factor', 'dns_amplification_factor', 'snmp_amplification_factor',
    'query_response_ratio', 'fragmentation_ratio', 'syn_ack_ratio',
    # SYN/WebDDoS discrimination + mixed detection (4)
    'syn_only_packets', 'http_payload_packets', 'active_attack_protocols',
    'syn_http_ratio',
    # Normalized ratios - volume-invariant (13)
    'syn_only_ratio', 'http_payload_ratio', 'dns_query_ratio',
    'ntp_monlist_ratio', 'snmp_ratio', 'ssdp_ratio', 'icmp_ratio',
    'http_request_ratio', 'portmap_ratio', 'netbios_ratio',
    'ldap_ratio', 'mssql_ratio', 'tftp_ratio',
]

# DPI + Sketch = 59 + 14 = 73
DPI_SKETCH_FEATURES = DPI_FEATURES + SKETCH_FEATURES

# ============================================================
# DPI RATIOS-ONLY (31) - Volume-invariant features for cross-run generalization
# ============================================================
DPI_RATIOS_FEATURES = [
    # Basic ratios (4)
    'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio', 'bytes_per_packet',
    # Amplification ratios (6)
    'ntp_amplification_factor', 'dns_amplification_factor', 'snmp_amplification_factor',
    'query_response_ratio', 'fragmentation_ratio', 'syn_ack_ratio',
    # SYN/WebDDoS discrimination (2)
    'active_attack_protocols', 'syn_http_ratio',
    # Normalized protocol ratios (13)
    'syn_only_ratio', 'http_payload_ratio', 'dns_query_ratio',
    'ntp_monlist_ratio', 'snmp_ratio', 'ssdp_ratio', 'icmp_ratio',
    'http_request_ratio', 'portmap_ratio', 'netbios_ratio',
    'ldap_ratio', 'mssql_ratio', 'tftp_ratio',
    # Sketch ratios (6)
    'ratio_vs_baseline', 'ratio_50ms_1min',
    'num_heavy_hitters', 'ip_concentration', 'new_ips_ratio', 'attack_entropy',
]

# ============================================================
# SKETCH-ADV PER-PROTOCOL FEATURES (50)
# ============================================================
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

# Sketch-ADV total: 14 + 50 = 64
SKETCH_FEATURES_ALL = SKETCH_FEATURES + SKETCH_ADV_FEATURES


def get_feature_columns(mode='sketch_adv'):
    """Return feature column names for a given mode.

    Args:
        mode: 'dpi_sketch' (73), 'sketch' (14), 'sketch_adv' (64), or 'dpi_ratios' (31)
    """
    if mode == 'dpi_sketch':
        return list(DPI_SKETCH_FEATURES)
    elif mode == 'dpi_ratios':
        return list(DPI_RATIOS_FEATURES)
    elif mode == 'sketch':
        return list(SKETCH_FEATURES)
    elif mode == 'sketch_adv':
        return list(SKETCH_FEATURES_ALL)
    else:
        raise ValueError(f"Unknown mode: {mode}. Use 'dpi_sketch', 'dpi_ratios', 'sketch', or 'sketch_adv'")


def filter_dataframe(df, mode='sketch_adv'):
    """Filter DataFrame to keep only features for the given mode + label"""
    features = get_feature_columns(mode)
    available = [c for c in features if c in df.columns]
    missing = [c for c in features if c not in df.columns]
    if missing:
        print(f"[WARNING] Missing {len(missing)} columns: {missing[:5]}...")
    keep = available + ['label']
    if 'run_id' in df.columns:
        keep.append('run_id')
    return df[keep]
