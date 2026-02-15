#!/usr/bin/env python3
"""
Feature Extractor for MIRA Detector Logs (Multi-Class Version)
Parses detector output logs and extracts ML features for CIC-DDoS-2019 multi-attack detection
Supports 14 attack classes and 60 features (46 base + 14 temporal/multi-scale)
"""

import re
import argparse
import math
import pandas as pd
from typing import Dict, List, Optional
import sys

# Legacy 3-class labels (backward compatibility)
LEGACY_LABELS = ['benign', 'attack', 'mixed']

# Multi-class attack types (14+ classes for CIC-DDoS-2019)
SPECIFIC_ATTACK_TYPES = [
    'portmap',      # RPC portmapper amplification
    'netbios',      # NetBIOS name service amplification
    'ldap',         # LDAP amplification
    'mssql',        # MSSQL amplification
    'udp',          # Generic UDP flood (same as udp_flood)
    'udp_flood',    # Generic UDP flood
    'udp_lag',      # UDP with lag/delay
    'syn',          # SYN flood attack (same as syn_flood)
    'syn_flood',    # SYN flood attack
    'ntp',          # NTP amplification
    'dns',          # DNS amplification
    'snmp',         # SNMP amplification
    'ssdp',         # SSDP amplification
    'webddos',      # HTTP/HTTPS flood
    'tftp',         # TFTP amplification
    'portscan',     # Port scanning attack
]

# Combined: accept both legacy (3 classes) and specific attack types
ALL_LABELS = LEGACY_LABELS + SPECIFIC_ATTACK_TYPES

MIXED_MIN_SHARE = 0.10

class LogParser:
    """Parses MIRA detector logs and extracts features"""

    def __init__(self):
        self.feature_records = []

    def parse_log_file(self, log_path: str, label: str,
                       baseline_before: float = None,
                       attack_duration: float = None,
                       baseline_after: float = None) -> pd.DataFrame:
        """
        Parse detector log file and extract features

        Args:
            log_path: Path to log file
            label: Label for the data (attack type for temporal labeling, or fixed label)
            baseline_before: Seconds of benign before attack (enables temporal labeling)
            attack_duration: Seconds of attack traffic
            baseline_after: Seconds of benign after attack

        Returns:
            DataFrame with extracted features
        """
        print(f"[INFO] Parsing log file: {log_path}")
        print(f"[INFO] Label: {label}")

        # Temporal labeling mode
        temporal = (baseline_before is not None and attack_duration is not None
                    and baseline_after is not None)
        if temporal:
            attack_start = baseline_before
            attack_end = baseline_before + attack_duration
            total_duration = attack_end + baseline_after
            print(f"[INFO] Temporal labeling: {baseline_before}s benign → "
                  f"{attack_duration}s {label} → {baseline_after}s benign "
                  f"(total {total_duration}s)")

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()

        # Split log into detection windows (separated by PACKET COUNTERS)
        windows = re.split(r'\[PACKET COUNTERS - GLOBAL\]', log_content)

        print(f"[INFO] Found {len(windows)-1} detection windows in log")

        stats = {'benign': 0, 'attack': 0, 'no_time': 0}
        for idx, window in enumerate(windows[1:], 1):  # Skip first empty split
            # Determine label for this window
            window_label = label
            if temporal:
                elapsed = self._extract_elapsed_time(window)
                if elapsed is not None:
                    if elapsed < attack_start or elapsed >= attack_end:
                        window_label = 'benign'
                        stats['benign'] += 1
                    else:
                        window_label = label
                        stats['attack'] += 1
                else:
                    stats['no_time'] += 1
                    continue  # Skip windows without timestamp

            features = self._extract_features_from_window(window, window_label)
            if features:
                self.feature_records.append(features)
                if idx % 100 == 0:
                    print(f"[PROGRESS] Processed {idx} windows...")

        print(f"[INFO] Extracted {len(self.feature_records)} feature records")
        if temporal:
            print(f"[LABELING] Benign: {stats['benign']}  "
                  f"Attack ({label}): {stats['attack']}  "
                  f"No timestamp: {stats['no_time']}")

        # Convert to DataFrame
        df = pd.DataFrame(self.feature_records)
        return df

    def _extract_elapsed_time(self, window_text: str) -> Optional[float]:
        """Extract elapsed seconds from cumulative traffic section.

        Matches: 'Since first packet (77.1s)' or 'Since first packet (123.4s)'
        """
        match = re.search(r'Since first packet \(([\d.]+)s\)', window_text)
        if match:
            return float(match.group(1))
        return None

    def _extract_features_from_window(self, window_text: str, label: str) -> Optional[Dict]:
        """Extract 40+ features from a single detection window"""

        features = {}

        # ========== ORIGINAL 14 FEATURES ==========
        # Feature 1-2: Total packets and bytes
        match = re.search(r'Total packets:\s+(\d+)', window_text)
        if not match:
            return None
        features['total_packets'] = int(match.group(1))

        # Extract total bytes from cumulative traffic section
        match = re.search(r'Total received:\s+\d+ pkts.*?\|\s+([\d.]+) Gbps \|\s+(\d+) bytes', window_text)
        if match:
            features['total_bytes'] = int(match.group(2))
        else:
            # Fallback: estimate from avg packet size
            match_avg = re.search(r'avg pkt:\s+([\d.]+) bytes', window_text)
            if match_avg:
                avg_pkt_size = float(match_avg.group(1))
                features['total_bytes'] = int(features['total_packets'] * avg_pkt_size)
            else:
                features['total_bytes'] = features['total_packets'] * 100  # Default estimate

        # Feature 3-5: Protocol distribution
        match = re.search(r'TCP packets:\s+(\d+)', window_text)
        features['tcp_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'UDP packets:\s+(\d+)', window_text)
        features['udp_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'ICMP packets:\s+(\d+)', window_text)
        features['icmp_packets'] = int(match.group(1)) if match else 0

        # Feature 6: SYN packets
        match = re.search(r'SYN packets:\s+(\d+)', window_text)
        features['syn_packets'] = int(match.group(1)) if match else 0

        # Feature 7: HTTP requests
        match = re.search(r'HTTP requests:\s+(\d+)', window_text)
        features['http_requests'] = int(match.group(1)) if match else 0

        # Feature 8: DNS queries
        match = re.search(r'DNS queries:\s+(\d+)', window_text)
        features['dns_queries'] = int(match.group(1)) if match else 0

        # Feature 9-10: Baseline vs Attack packets
        match = re.search(r'Baseline \((?:192\.168\.1|10\.10\.2)[^)]*\):\s+(\d+)', window_text)
        features['baseline_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'Attack \((?:192\.168\.2|10\.10\.3)[^)]*\):\s+(\d+)', window_text)
        features['attack_packets'] = int(match.group(1)) if match else 0

        # Feature 11-14: Derived ratios
        features['udp_tcp_ratio'] = (
            features['udp_packets'] / features['tcp_packets']
            if features['tcp_packets'] > 0 else 0.0
        )

        features['syn_total_ratio'] = (
            features['syn_packets'] / features['total_packets']
            if features['total_packets'] > 0 else 0.0
        )

        features['baseline_attack_ratio'] = (
            features['baseline_packets'] / features['attack_packets']
            if features['attack_packets'] > 0 else 999.0  # High value = no attack
        )

        features['bytes_per_packet'] = (
            features['total_bytes'] / features['total_packets']
            if features['total_packets'] > 0 else 0.0
        )

        # ========== NEW: 26 PROTOCOL-SPECIFIC FEATURES ==========
        # NTP Amplification (3 features)
        match = re.search(r'Monlist queries:\s+(\d+)', window_text)
        features['ntp_monlist_queries'] = int(match.group(1)) if match else 0

        match = re.search(r'NTP Amplification:.*?Responses:\s+(\d+)', window_text, re.DOTALL)
        features['ntp_responses'] = int(match.group(1)) if match else 0

        match = re.search(r'NTP Amplification:.*?avg size:\s+(\d+) bytes', window_text, re.DOTALL)
        features['avg_ntp_response_size'] = int(match.group(1)) if match else 0

        # DNS Amplification (4 features)
        match = re.search(r'ANY queries:\s+(\d+)', window_text)
        features['dns_any_queries'] = int(match.group(1)) if match else 0

        match = re.search(r'TXT queries:\s+(\d+)', window_text)
        features['dns_txt_queries'] = int(match.group(1)) if match else 0

        match = re.search(r'DNS Amplification:.*?Responses:\s+(\d+)', window_text, re.DOTALL)
        features['dns_responses'] = int(match.group(1)) if match else 0

        match = re.search(r'DNS Amplification:.*?avg size:\s+(\d+) bytes', window_text, re.DOTALL)
        features['avg_dns_response_size'] = int(match.group(1)) if match else 0

        # SNMP Amplification (3 features)
        match = re.search(r'GetBulk requests:\s+(\d+)', window_text)
        features['snmp_getbulk_requests'] = int(match.group(1)) if match else 0

        match = re.search(r'SNMP Amplification:.*?Responses:\s+(\d+)', window_text, re.DOTALL)
        features['snmp_responses'] = int(match.group(1)) if match else 0

        match = re.search(r'SNMP Amplification:.*?avg size:\s+(\d+) bytes', window_text, re.DOTALL)
        features['avg_snmp_response_size'] = int(match.group(1)) if match else 0

        # SSDP (2 features)
        match = re.search(r'M-SEARCH packets:\s+(\d+)', window_text)
        features['ssdp_msearch_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'SSDP:.*?Responses:\s+(\d+)', window_text, re.DOTALL)
        features['ssdp_responses'] = int(match.group(1)) if match else 0

        # PortMapper (2 features)
        match = re.search(r'GETPORT calls:\s+(\d+)', window_text)
        features['portmap_getport_calls'] = int(match.group(1)) if match else 0

        match = re.search(r'DUMP calls:\s+(\d+)', window_text)
        features['portmap_dump_calls'] = int(match.group(1)) if match else 0

        # NetBIOS (2 features)
        match = re.search(r'Name queries:\s+(\d+)', window_text)
        features['netbios_name_queries'] = int(match.group(1)) if match else 0

        match = re.search(r'Datagram packets:\s+(\d+)', window_text)
        features['netbios_dgram_packets'] = int(match.group(1)) if match else 0

        # LDAP (2 features)
        match = re.search(r'Bind requests:\s+(\d+)', window_text)
        features['ldap_bind_requests'] = int(match.group(1)) if match else 0

        match = re.search(r'Search requests:\s+(\d+)', window_text)
        features['ldap_search_requests'] = int(match.group(1)) if match else 0

        # MSSQL (2 features)
        match = re.search(r'SQLBatch packets:\s+(\d+)', window_text)
        features['mssql_sqlbatch_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'RPC packets:\s+(\d+)', window_text)
        features['mssql_rpc_packets'] = int(match.group(1)) if match else 0

        # TFTP (2 features)
        match = re.search(r'RRQ \(read\) pkts:\s+(\d+)', window_text)
        features['tftp_rrq_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'WRQ \(write\) pkts:\s+(\d+)', window_text)
        features['tftp_wrq_packets'] = int(match.group(1)) if match else 0

        # ========== DERIVED AMPLIFICATION FEATURES (6 ratios) ==========
        # Amplification factors
        features['ntp_amplification_factor'] = (
            features['avg_ntp_response_size'] / 48.0  # NTP query typically 48 bytes
            if features['ntp_monlist_queries'] > 0 else 0.0
        )

        features['dns_amplification_factor'] = (
            features['avg_dns_response_size'] / 60.0  # DNS query typically 60 bytes
            if features['dns_any_queries'] > 0 or features['dns_txt_queries'] > 0 else 0.0
        )

        features['snmp_amplification_factor'] = (
            features['avg_snmp_response_size'] / 150.0  # SNMP request typically 150 bytes
            if features['snmp_getbulk_requests'] > 0 else 0.0
        )

        # Query/Response ratio (imbalance indicator)
        total_queries = (features['ntp_monlist_queries'] + features['dns_any_queries'] +
                        features['dns_txt_queries'] + features['snmp_getbulk_requests'])
        total_responses = (features['ntp_responses'] + features['dns_responses'] +
                          features['snmp_responses'])

        features['query_response_ratio'] = (
            total_queries / total_responses
            if total_responses > 0 else 0.0
        )

        # Fragmentation ratio (placeholder - would need fragmented packet counter)
        features['fragmentation_ratio'] = 0.0

        # SYN/ACK ratio
        match = re.search(r'SYN-ACK packets:\s+(\d+)', window_text)
        syn_ack_packets = int(match.group(1)) if match else 0
        features['syn_ack_ratio'] = (
            features['syn_packets'] / syn_ack_packets
            if syn_ack_packets > 0 else 0.0
        )

        # ========== NEW: SYN/WebDDoS discrimination + mixed detection ==========
        match = re.search(r'SYN-only \(non-HTTP\):\s*(\d+)', window_text)
        features['syn_only_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'HTTP with payload:\s+(\d+)', window_text)
        features['http_payload_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'Active protocols:\s+(\d+)', window_text)
        features['active_attack_protocols'] = int(match.group(1)) if match else 0

        # Derived ratio: SYN-only / HTTP-payload (discriminates SYN flood vs WebDDoS)
        syn_o = features['syn_only_packets']
        http_p = features['http_payload_packets']
        features['syn_http_ratio'] = syn_o / http_p if http_p > 0 else (float(syn_o) if syn_o > 0 else 0.0)

        # ========== NEW: 14 TEMPORAL & MULTI-SCALE FEATURES ==========
        # Temporal Features (from Ring Buffer) - Features 43-47
        match = re.search(r'Delta PPS \(250ms\):\s+([+-]?[\d.]+)', window_text)
        features['delta_pps_5w'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Delta PPS \(500ms\):\s+([+-]?[\d.]+)', window_text)
        features['delta_pps_10w'] = float(match.group(1)) if match else 0.0

        match = re.search(r'PPS Variance:\s+([\d.]+)', window_text)
        features['pps_variance'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Running baseline(?:\s*\(ML\))?:\s+([\d.]+) pps', window_text)
        features['pps_baseline'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Ratio vs Baseline:\s+([\d.]+)x', window_text)
        features['ratio_vs_baseline'] = float(match.group(1)) if match else 1.0

        # Multi-Scale Features (from Sketches) - Features 48-56
        match = re.search(r'Top IP \(50ms\):\s+([\d.]+) pps', window_text)
        features['top_ip_pps_50ms'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Top IP \(1s\):\s+([\d.]+) pps', window_text)
        features['top_ip_pps_1s'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Top IP \(1min\):\s+([\d.]+) pps', window_text)
        features['top_ip_pps_1min'] = float(match.group(1)) if match else 0.0

        match = re.search(r'Burst Ratio \(50ms/1min\):\s+([\d.]+)x', window_text)
        features['ratio_50ms_1min'] = float(match.group(1)) if match else 1.0

        match = re.search(r'Heavy-hitters detected:\s+(\d+)', window_text)
        features['num_heavy_hitters'] = int(match.group(1)) if match else 0

        match = re.search(r'IP Concentration:\s+([\d.]+)%', window_text)
        features['ip_concentration'] = float(match.group(1)) / 100.0 if match else 0.0

        # ========== SKETCH-ADV: Per-Protocol Features (50) ==========
        sketch_adv_section = re.search(
            r'\[SKETCH-ADV PER-PROTOCOL FEATURES\](.*)',
            window_text, re.DOTALL)

        if sketch_adv_section:
            adv_text = sketch_adv_section.group(1)

            # Protocol order must match C code and feature_groups.py
            proto_map = {
                'DNS':       'dns',
                'NTP':       'ntp',
                'SNMP':      'snmp',
                'SSDP':      'ssdp',
                'PortMap':   'portmap',
                'NetBIOS':   'netbios',
                'LDAP':      'ldap',
                'MSSQL':     'mssql',
                'TFTP':      'tftp',
                'SYN':       'syn',
                'HTTP':      'http',
                'UDP-Other': 'udp_other',
            }

            for display_name, feat_name in proto_map.items():
                # Match each protocol block
                pattern = re.escape(f'[{display_name}') + r'[^\]]*\]\s*' \
                    r'PPS:\s+([\d.]+)\s*' \
                    r'Heavy-hitters:\s+(\d+)\s*' \
                    r'IP Concentration:\s+([\d.]+)%\s*' \
                    r'Ratio vs Total:\s+([\d.]+)'
                m = re.search(pattern, adv_text)
                if m:
                    features[f'pps_{feat_name}'] = float(m.group(1))
                    features[f'heavy_hitters_{feat_name}'] = int(m.group(2))
                    features[f'ip_concentration_{feat_name}'] = float(m.group(3)) / 100.0
                    features[f'ratio_vs_total_{feat_name}'] = float(m.group(4))
                else:
                    features[f'pps_{feat_name}'] = 0.0
                    features[f'heavy_hitters_{feat_name}'] = 0
                    features[f'ip_concentration_{feat_name}'] = 0.0
                    features[f'ratio_vs_total_{feat_name}'] = 0.0

            # Packet size features
            m = re.search(r'Avg Packet Size:\s+([\d.]+)', adv_text)
            features['avg_packet_size'] = float(m.group(1)) if m else 0.0

            m = re.search(r'Packet Size Variance:\s+([\d.]+)', adv_text)
            features['packet_size_variance'] = float(m.group(1)) if m else 0.0

        # Derived features (mix signature) - helps mixed class separation
        attack_signals = {
            'ntp': features['ntp_monlist_queries'],
            'dns': features['dns_any_queries'] + features['dns_txt_queries'],
            'snmp': features['snmp_getbulk_requests'],
            'ssdp': features['ssdp_msearch_packets'],
            'portmap': features['portmap_getport_calls'],
            'netbios': features['netbios_name_queries'],
            'ldap': features['ldap_search_requests'],
            'mssql': features['mssql_sqlbatch_packets'],
            'tftp': features['tftp_rrq_packets'],
            'syn': features['syn_packets'],
            'web': features['http_requests'],
        }
        active_types = 0
        total_signal = 0.0
        for value in attack_signals.values():
            if value > 0:
                total_signal += float(value)

        if features['attack_packets'] == 0:
            active_types = 0
            total_signal = 0.0

        if total_signal > 0.0:
            active_types = sum(
                (float(value) / total_signal) >= MIXED_MIN_SHARE
                for value in attack_signals.values()
            )

        if total_signal > 0.0:
            entropy = 0.0
            for value in attack_signals.values():
                if value <= 0:
                    continue
                p = float(value) / total_signal
                entropy -= p * math.log2(p)
            max_entropy = math.log2(len(attack_signals))
            features['attack_entropy'] = entropy / max_entropy if max_entropy > 0 else 0.0
        else:
            features['attack_entropy'] = 0.0

        features['new_ips_ratio'] = active_types / float(len(attack_signals))
        features['adaptive_threshold'] = 0.0  # Calculated but not used for detection

        # Filter: for specific attack labels, drop windows without attack traffic
        if label not in LEGACY_LABELS and label != 'mixed':
            if features['attack_packets'] == 0:
                return None

        if label == 'mixed':
            if total_signal == 0.0:
                return None
            if active_types < 2:
                dominant = max(attack_signals.items(), key=lambda item: item[1])[0]
                if dominant == 'syn':
                    label = 'syn_flood'
                elif dominant == 'web':
                    label = 'webddos'
                else:
                    label = dominant

        # Label
        features['label'] = label

        return features

    def save_to_csv(self, df: pd.DataFrame, output_path: str):
        """Save DataFrame to CSV file"""

        # Define column order (56 features total: 42 base + 14 temporal/multi-scale)
        columns = [
            # Original 14 features (1-14)
            'total_packets', 'total_bytes',
            'udp_packets', 'tcp_packets', 'icmp_packets',
            'syn_packets', 'http_requests', 'dns_queries',
            'baseline_packets', 'attack_packets',
            'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio',
            'bytes_per_packet',
            # Protocol-specific features (15-36)
            'ntp_monlist_queries', 'ntp_responses', 'avg_ntp_response_size',
            'dns_any_queries', 'dns_txt_queries', 'dns_responses', 'avg_dns_response_size',
            'snmp_getbulk_requests', 'snmp_responses', 'avg_snmp_response_size',
            'ssdp_msearch_packets', 'ssdp_responses',
            'portmap_getport_calls', 'portmap_dump_calls',
            'netbios_name_queries', 'netbios_dgram_packets',
            'ldap_bind_requests', 'ldap_search_requests',
            'mssql_sqlbatch_packets', 'mssql_rpc_packets',
            'tftp_rrq_packets', 'tftp_wrq_packets',
            # Derived amplification features (37-42)
            'ntp_amplification_factor', 'dns_amplification_factor', 'snmp_amplification_factor',
            'query_response_ratio', 'fragmentation_ratio', 'syn_ack_ratio',
            # SYN/WebDDoS discrimination + mixed detection (43-46)
            'syn_only_packets', 'http_payload_packets', 'active_attack_protocols',
            'syn_http_ratio',
            # NEW: Temporal features from Ring Buffer (43-47)
            'delta_pps_5w', 'delta_pps_10w', 'pps_variance',
            'pps_baseline', 'ratio_vs_baseline',
            # NEW: Multi-scale features from Sketches (48-56)
            'top_ip_pps_50ms', 'top_ip_pps_1s', 'top_ip_pps_1min',
            'ratio_50ms_1min', 'num_heavy_hitters', 'ip_concentration',
            'new_ips_ratio', 'attack_entropy', 'adaptive_threshold',
        ]

        # SKETCH-ADV: Add per-protocol features if present in data
        sketch_adv_protocols = [
            'dns', 'ntp', 'snmp', 'ssdp', 'portmap', 'netbios',
            'ldap', 'mssql', 'tftp', 'syn', 'http', 'udp_other',
        ]
        sketch_adv_per_proto = ['pps', 'heavy_hitters', 'ip_concentration', 'ratio_vs_total']
        sketch_adv_cols = []
        for proto in sketch_adv_protocols:
            for feat in sketch_adv_per_proto:
                sketch_adv_cols.append(f'{feat}_{proto}')
        sketch_adv_cols += ['avg_packet_size', 'packet_size_variance']

        has_sketch_adv = 'pps_dns' in df.columns
        if has_sketch_adv:
            columns += sketch_adv_cols

        # Label (must be last)
        columns.append('label')

        # Reorder columns (only keep those present)
        columns = [c for c in columns if c in df.columns]
        df = df[columns]

        # Save to CSV
        df.to_csv(output_path, index=False)
        print(f"[SUCCESS] Saved {len(df)} records to {output_path}")

        # Print summary statistics
        print("\n[SUMMARY STATISTICS]")
        print(f"  Total records:     {len(df)}")
        print(f"  Labels:            {dict(df['label'].value_counts())}")
        print(f"  Avg packets/win:   {df['total_packets'].mean():.0f}")
        print(f"  Avg bytes/win:     {df['total_bytes'].mean():.0f}")
        print(f"  UDP/TCP ratio:     {df['udp_tcp_ratio'].mean():.3f}")
        print(f"  SYN/Total ratio:   {df['syn_total_ratio'].mean():.3f}")
        print(f"  Bytes/packet:      {df['bytes_per_packet'].mean():.1f}")

        # NEW: Protocol-specific summaries
        print(f"\n[PROTOCOL-SPECIFIC FEATURES]")
        print(f"  NTP queries:       {df['ntp_monlist_queries'].sum()}")
        print(f"  DNS ANY/TXT:       {df['dns_any_queries'].sum() + df['dns_txt_queries'].sum()}")
        print(f"  SNMP GetBulk:      {df['snmp_getbulk_requests'].sum()}")
        print(f"  SSDP M-SEARCH:     {df['ssdp_msearch_packets'].sum()}")
        print(f"  PortMapper:        {df['portmap_getport_calls'].sum()}")
        print(f"  NetBIOS:           {df['netbios_name_queries'].sum()}")
        print(f"  LDAP:              {df['ldap_bind_requests'].sum()}")
        print(f"  MSSQL:             {df['mssql_sqlbatch_packets'].sum()}")
        print(f"  TFTP:              {df['tftp_rrq_packets'].sum()}")

        # SKETCH-ADV summary
        if has_sketch_adv:
            total_features = len([c for c in df.columns if c != 'label'])
            print(f"\n[SKETCH-ADV FEATURES] ({total_features} total features)")
            print(f"  Avg packet size:   {df['avg_packet_size'].mean():.1f}")
            print(f"  Pkt size variance: {df['packet_size_variance'].mean():.1f}")
            for proto in sketch_adv_protocols:
                avg_pps = df[f'pps_{proto}'].mean()
                if avg_pps > 0:
                    print(f"  {proto:12s} avg PPS: {avg_pps:.1f}")

        # Check for potential issues
        if len(df) < 10:
            print("\n[WARNING] Very few records extracted (<10). Check log file format.")

        if df['total_packets'].min() == 0:
            print("[WARNING] Some windows have 0 packets. These may be noise.")

def main():
    parser = argparse.ArgumentParser(
        description='Extract ML features from MIRA detector logs (Multi-Class)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # FIXED LABEL (all windows get the same label):
  python3 feature_extractor.py \\
      --input attack_dns_run1.log \\
      --output ../datasets/processed/dns_run1.csv \\
      --label dns

  # TEMPORAL LABELING (200s experiment: 70s benign + 80s attack + 60s benign):
  python3 feature_extractor.py \\
      --input attack_dns_run1.log \\
      --output ../datasets/processed/dns_run1.csv \\
      --label dns \\
      --baseline-before 70 --attack-duration 80 --baseline-after 60

  Timing diagram (detector_system2, 210s run):
    t=0     t=10    t=70              t=150   t=200  t=210
    |  no   | benign |    attack       | benign | no  |
    |traffic| only   |    active       | only   |traf.|
    |<------benign------>|<--attack-->|<----benign---->|

Supported labels:
  - Legacy (3 classes): benign, attack, mixed
  - CIC-DDoS-2019 (specific): portmap, netbios, ldap, mssql, udp, udp_lag,
    syn, ntp, dns, snmp, ssdp, webddos, tftp, portscan
        """
    )

    parser.add_argument('--input', type=str, required=True,
                       help='Input log file path')
    parser.add_argument('--output', type=str, required=True,
                       help='Output CSV file path')
    parser.add_argument('--label', type=str, required=True,
                       choices=ALL_LABELS,
                       help='Traffic label (benign/attack/mixed OR specific attack type)')
    parser.add_argument('--baseline-before', type=float, default=None,
                       help='Seconds of benign before attack (default: None = no temporal labeling)')
    parser.add_argument('--attack-duration', type=float, default=None,
                       help='Seconds of attack traffic (default: None)')
    parser.add_argument('--baseline-after', type=float, default=None,
                       help='Seconds of benign after attack (default: None)')

    args = parser.parse_args()

    # Validate input file exists
    try:
        with open(args.input, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)

    # Validate temporal labeling args (all or none)
    temporal_args = [args.baseline_before, args.attack_duration, args.baseline_after]
    if any(a is not None for a in temporal_args) and not all(a is not None for a in temporal_args):
        print("[ERROR] --baseline-before, --attack-duration, --baseline-after must all be specified together")
        sys.exit(1)

    # Parse log file
    parser_obj = LogParser()
    df = parser_obj.parse_log_file(
        args.input, args.label,
        baseline_before=args.baseline_before,
        attack_duration=args.attack_duration,
        baseline_after=args.baseline_after
    )

    if df.empty:
        print("[ERROR] No features extracted. Check log file format.")
        sys.exit(1)

    # Save to CSV
    parser_obj.save_to_csv(df, args.output)

    print("\n[DONE] Feature extraction complete!")

if __name__ == '__main__':
    main()
