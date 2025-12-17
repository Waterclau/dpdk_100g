#!/usr/bin/env python3
"""
Feature Extractor for MIRA Detector Logs
Parses detector output logs and extracts ML features for training
"""

import re
import argparse
import pandas as pd
from typing import Dict, List, Optional
import sys

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
        """Extract 13 features from a single detection window"""

        features = {}

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

        # Feature 8: DNS queries (estimate from UDP packets if not explicitly shown)
        match = re.search(r'DNS queries:\s+(\d+)', window_text)
        if match:
            features['dns_queries'] = int(match.group(1))
        else:
            # Heuristic: ~10% of UDP packets are typically DNS in normal traffic
            features['dns_queries'] = int(features['udp_packets'] * 0.1)

        # Feature 9-10: Baseline vs Attack packets
        # Try both old format (192.168.x) and new format (10.10.x)
        match = re.search(r'Baseline \((?:192\.168\.1|10\.10\.1)[^)]*\):\s+(\d+)', window_text)
        features['baseline_packets'] = int(match.group(1)) if match else 0

        match = re.search(r'Attack \((?:192\.168\.2|10\.10\.2)[^)]*\):\s+(\d+)', window_text)
        features['attack_packets'] = int(match.group(1)) if match else 0

        # Feature 11-13: Derived ratios
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

        # Label
        features['label'] = label

        return features

    def save_to_csv(self, df: pd.DataFrame, output_path: str):
        """Save DataFrame to CSV file"""

        # Define column order
        columns = [
            'total_packets', 'total_bytes',
            'udp_packets', 'tcp_packets', 'icmp_packets',
            'syn_packets', 'http_requests', 'dns_queries',
            'baseline_packets', 'attack_packets',
            'udp_tcp_ratio', 'syn_total_ratio', 'baseline_attack_ratio',
            'bytes_per_packet',
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

        # Check for potential issues
        if len(df) < 10:
            print("\n[WARNING] Very few records extracted (<10). Check log file format.")

        if df['total_packets'].min() == 0:
            print("[WARNING] Some windows have 0 packets. These may be noise.")

def main():
    parser = argparse.ArgumentParser(
        description='Extract ML features from MIRA detector logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract benign traffic features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/benign_baseline.log \\
      --output ../datasets/processed/benign_baseline.csv \\
      --label benign

  # Extract attack traffic features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/attack_cic_ids.log \\
      --output ../datasets/processed/attack_cic_ids.csv \\
      --label attack

  # Extract mixed traffic features
  python3 feature_extractor.py \\
      --input ../datasets/raw_logs/mixed_traffic.log \\
      --output ../datasets/processed/mixed_traffic.csv \\
      --label mixed
        """
    )

    parser.add_argument('--input', type=str, required=True,
                       help='Input log file path')
    parser.add_argument('--output', type=str, required=True,
                       help='Output CSV file path')
    parser.add_argument('--label', type=str, required=True,
                       choices=['benign', 'attack', 'mixed'],
                       help='Traffic label (benign, attack, or mixed)')

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
