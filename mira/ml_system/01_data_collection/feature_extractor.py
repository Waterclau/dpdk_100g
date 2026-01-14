#!/usr/bin/env python3
"""
Feature Extractor for MIRA Detector Logs (Multi-Class Version)
Parses detector output logs and extracts ML features for CIC-DDoS-2019 multi-attack detection
Supports 14 attack classes and 40+ features
"""

import re
import argparse
import pandas as pd
from typing import Dict, List, Optional
import sys

# Multi-class attack types (14 classes for CIC-DDoS-2019)
ATTACK_TYPES = [
    'benign',       # Normal traffic
    'portmap',      # RPC portmapper amplification
    'netbios',      # NetBIOS name service amplification
    'ldap',         # LDAP amplification
    'mssql',        # MSSQL amplification
    'udp_flood',    # Generic UDP flood
    'udp_lag',      # UDP with lag/delay
    'syn_flood',    # SYN flood attack
    'ntp',          # NTP amplification
    'dns',          # DNS amplification
    'snmp',         # SNMP amplification
    'ssdp',         # SSDP amplification
    'webddos',      # HTTP/HTTPS flood
    'tftp',         # TFTP amplification
    'mixed'         # Multiple attack types simultaneously
]

class LogParser:
    """Parses MIRA detector logs and extracts features"""

    def __init__(self):
        self.feature_records = []

    def parse_log_file(self, log_path: str, label: str) -> pd.DataFrame:
        """
        Parse detector log file and extract features

        Args:
            log_path: Path to log file
            label: Label for the data (benign, attack, mixed)

        Returns:
            DataFrame with extracted features
        """
        print(f"[INFO] Parsing log file: {log_path}")
        print(f"[INFO] Label: {label}")

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()

        # Split log into detection windows (separated by PACKET COUNTERS)
        windows = re.split(r'\[PACKET COUNTERS - GLOBAL\]', log_content)

        print(f"[INFO] Found {len(windows)-1} detection windows in log")

        for idx, window in enumerate(windows[1:], 1):  # Skip first empty split
            features = self._extract_features_from_window(window, label)
            if features:
                self.feature_records.append(features)
                if idx % 100 == 0:
                    print(f"[PROGRESS] Processed {idx} windows...")

        print(f"[INFO] Extracted {len(self.feature_records)} feature records")

        # Convert to DataFrame
        df = pd.DataFrame(self.feature_records)
        return df

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

        # Label
        features['label'] = label

        return features

    def save_to_csv(self, df: pd.DataFrame, output_path: str):
        """Save DataFrame to CSV file"""

        # Define column order (46 features total: 14 original + 26 protocol + 6 derived)
        columns = [
            # Original 14 features
            'total_packets', 'total_bytes',
            'udp_packets', 'tcp_packets', 'icmp_packets',
            'syn_packets', 'http_requests', 'dns_queries',
            'baseline_packets', 'attack_packets',
            'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio',
            'bytes_per_packet',
            # NEW: Protocol-specific features (26)
            'ntp_monlist_queries', 'ntp_responses', 'avg_ntp_response_size',
            'dns_any_queries', 'dns_txt_queries', 'dns_responses', 'avg_dns_response_size',
            'snmp_getbulk_requests', 'snmp_responses', 'avg_snmp_response_size',
            'ssdp_msearch_packets', 'ssdp_responses',
            'portmap_getport_calls', 'portmap_dump_calls',
            'netbios_name_queries', 'netbios_dgram_packets',
            'ldap_bind_requests', 'ldap_search_requests',
            'mssql_sqlbatch_packets', 'mssql_rpc_packets',
            'tftp_rrq_packets', 'tftp_wrq_packets',
            # NEW: Derived amplification features (6)
            'ntp_amplification_factor', 'dns_amplification_factor', 'snmp_amplification_factor',
            'query_response_ratio', 'fragmentation_ratio', 'syn_ack_ratio',
            # Label (must be last)
            'label'
        ]

        # Reorder columns
        df = df[columns]

        # Save to CSV
        df.to_csv(output_path, index=False)
        print(f"[SUCCESS] Saved {len(df)} records to {output_path}")

        # Print summary statistics
        print("\n[SUMMARY STATISTICS]")
        print(f"  Total records:     {len(df)}")
        print(f"  Label:             {df['label'].iloc[0]}")
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
  # Extract benign traffic features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/benign_baseline.log \\
      --output ../datasets/processed/benign_baseline.csv \\
      --label benign

  # Extract NTP amplification attack features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/ntp_attack.log \\
      --output ../datasets/processed/ntp_attack.csv \\
      --label ntp

  # Extract DNS amplification attack features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/dns_attack.log \\
      --output ../datasets/processed/dns_attack.csv \\
      --label dns

  # Extract SYN flood attack features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/syn_flood.log \\
      --output ../datasets/processed/syn_flood.csv \\
      --label syn_flood

Supported attack types (14 classes):
  benign, portmap, netbios, ldap, mssql, udp_flood, udp_lag,
  syn_flood, ntp, dns, snmp, ssdp, webddos, tftp, mixed
        """
    )

    parser.add_argument('--input', type=str, required=True,
                       help='Input log file path')
    parser.add_argument('--output', type=str, required=True,
                       help='Output CSV file path')
    parser.add_argument('--label', type=str, required=True,
                       choices=ATTACK_TYPES,
                       help='Traffic label (one of 14 attack types)')

    args = parser.parse_args()

    # Validate input file exists
    try:
        with open(args.input, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {args.input}")
        sys.exit(1)

    # Parse log file
    parser_obj = LogParser()
    df = parser_obj.parse_log_file(args.input, args.label)

    if df.empty:
        print("[ERROR] No features extracted. Check log file format.")
        sys.exit(1)

    # Save to CSV
    parser_obj.save_to_csv(df, args.output)

    print("\n[DONE] Feature extraction complete!")

if __name__ == '__main__':
    main()
