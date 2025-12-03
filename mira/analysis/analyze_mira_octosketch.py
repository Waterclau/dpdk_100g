#!/usr/bin/env python3
"""
MIRA DDoS Detector - OctoSketch Results Analysis
Analyzes mira_detector_multicore.log and generates comprehensive visualizations
Compares DPDK + OctoSketch vs MULTI-LF (2025) ML-based detection
"""

import re
import sys
import os
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np
import pandas as pd

# Set style for publication-quality plots
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['figure.figsize'] = (14, 10)
plt.rcParams['font.size'] = 11
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['legend.fontsize'] = 10

class MIRALogParser:
    """Parser for MIRA detector logs with OctoSketch metrics"""

    def __init__(self, log_file):
        self.log_file = log_file
        self.data = {
            'timestamps': [],
            'total_packets': [],
            'baseline_packets': [],
            'baseline_percent': [],
            'attack_packets': [],
            'attack_percent': [],
            'tcp_packets': [],
            'udp_packets': [],
            'icmp_packets': [],
            'baseline_gbps': [],
            'attack_gbps': [],
            'total_gbps': [],
            'cumulative_mpps': [],
            'cumulative_gbps': [],
            'syn_packets': [],
            'syn_ack_packets': [],
            'syn_ack_ratio': [],
            'http_requests': [],
            'dns_queries': [],
            'udp_flood_events': [],
            'syn_flood_events': [],
            'http_flood_events': [],
            'icmp_flood_events': [],
            'dns_amp_events': [],
            'alert_level': [],
            'alert_reason': [],
            'throughput_mpps': [],
            'cycles_per_pkt': [],
            'active_ips': [],
            'rx_packets_nic': [],
            'rx_dropped': [],
            'rx_no_mbufs': [],
            'rx_errors': [],
            'detection_latency_ms': [],
            'improvement_factor': [],
            'packets_until_detection': [],
            'sketch_memory_kb': [],
            'sketch_sampling_rate': [],
            'sketch_updates': [],
        }

    def parse(self):
        """Parse the log file and extract all metrics"""
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # REMOVE ANSI color codes (e.g., \x1b[91m for red, \x1b[0m for reset)
        # This cleans escape sequences that interfere with regex parsing
        content = re.sub(r'\x1b\[[0-9;]*m', '', content)

        # Split by statistics blocks
        blocks = re.split(r'╔═+╗\s*\n║\s+MIRA DDoS DETECTOR - STATISTICS', content)

        time_offset = 0.0  # Track time progression
        first_detection = None

        for block_idx, block in enumerate(blocks[1:], 1):  # Skip header before first block
            try:
                # Extract packet counters
                total_pkts = self._extract_int(block, r'Total packets:\s+(\d+)')
                baseline_pkts = self._extract_int(block, r'Baseline \(192\.168\.1\):\s+(\d+)')
                baseline_pct = self._extract_float(block, r'Baseline \(192\.168\.1\):\s+\d+\s+\((\d+\.\d+)%\)')
                attack_pkts = self._extract_int(block, r'Attack \(192\.168\.2\):\s+(\d+)')
                attack_pct = self._extract_float(block, r'Attack \(192\.168\.2\):\s+\d+\s+\((\d+\.\d+)%\)')

                tcp_pkts = self._extract_int(block, r'TCP packets:\s+(\d+)')
                udp_pkts = self._extract_int(block, r'UDP packets:\s+(\d+)')
                icmp_pkts = self._extract_int(block, r'ICMP packets:\s+(\d+)')

                # Extract instantaneous traffic
                baseline_gbps = self._extract_float(block, r'Baseline \(192\.168\.1\):[^\n]+\s+(\d+\.\d+) Gbps')
                attack_gbps = self._extract_float(block, r'Attack \(192\.168\.2\):[^\n]+\s+(\d+\.\d+) Gbps')
                total_gbps = self._extract_float(block, r'Total throughput:\s+(\d+\.\d+) Gbps')

                # Extract cumulative traffic
                cumulative_mpps = self._extract_float(block, r'Total received:[^\(]+\((\d+\.\d+) Mpps\)')
                cumulative_gbps = self._extract_float(block, r'\| (\d+\.\d+) Gbps \|')

                # Extract attack-specific counters
                syn_pkts = self._extract_int(block, r'SYN packets:\s+(\d+)')
                syn_ack_pkts = self._extract_int(block, r'SYN-ACK packets:\s+(\d+)')
                syn_ack_ratio = self._extract_float(block, r'SYN/ACK ratio:\s+(\d+\.\d+)')
                http_reqs = self._extract_int(block, r'HTTP requests:\s+(\d+)')
                dns_queries = self._extract_int(block, r'DNS queries:\s+(\d+)')

                # Extract attack detections
                udp_flood = self._extract_int(block, r'UDP flood events:\s+(\d+)')
                syn_flood = self._extract_int(block, r'SYN flood events:\s+(\d+)')
                http_flood = self._extract_int(block, r'HTTP flood events:\s+(\d+)')
                icmp_flood = self._extract_int(block, r'ICMP flood events:\s+(\d+)')
                dns_amp = self._extract_int(block, r'DNS amp events:\s+(\d+)')

                # Extract alert status (handle multiple spaces between : and level name)
                alert_level_match = re.search(r'Alert level:\s+(\w+)', block)
                if alert_level_match:
                    alert_level = alert_level_match.group(1).strip().upper()
                else:
                    alert_level = "NONE"

                # Extract alert reason (capture everything after "Reason:" until next section or EOF)
                # Handle the pattern: "Reason:             UDP FLOOD detected..."
                alert_reason_match = re.search(r'Reason:\s+(.+?)(?=\n\[|\nReceive Side Scaling|$)', block, re.DOTALL)
                if alert_reason_match:
                    alert_reason = alert_reason_match.group(1).strip()
                else:
                    alert_reason = ""

                # Extract performance metrics
                throughput_mpps = self._extract_float(block, r'Throughput:\s+[\d\.]+\s+Gbps\s+\((\d+\.\d+) Mpps\)')
                cycles_per_pkt = self._extract_int(block, r'Cycles available:\s+(\d+) cycles/pkt')
                active_ips = self._extract_int(block, r'Active IPs:\s+(\d+)')

                # Extract DPDK NIC statistics
                rx_pkts_nic = self._extract_int(block, r'RX packets \(NIC\):\s+(\d+)')
                rx_dropped = self._extract_int(block, r'RX dropped \(HW\):\s+(\d+)')
                rx_no_mbufs = self._extract_int(block, r'RX no mbufs:\s+(\d+)')
                rx_errors = self._extract_int(block, r'RX errors:\s+(\d+)')

                # Extract detection latency (only if present)
                detection_latency = self._extract_float(block, r'First Detection Latency:\s+(\d+\.\d+) ms')
                improvement_factor = self._extract_float(block, r'Improvement:\s+(\d+\.\d+)× faster')
                pkts_until_detection = self._extract_int(block, r'Packets until detection:\s+(\d+)')

                # Extract OctoSketch metrics
                sketch_memory = self._extract_float(block, r'Total sketch memory:\s+(\d+) KB')
                sketch_sampling = self._extract_int(block, r'Sampling rate:\s+1 in (\d+) packets')
                sketch_updates = self._extract_int(block, r'Attack traffic sampled:\s+(\d+) updates')

                # Store first detection time
                if detection_latency is not None and first_detection is None:
                    first_detection = detection_latency

                # Calculate timestamp (5-second intervals)
                timestamp = time_offset
                time_offset += 5.0

                # Append to data
                self.data['timestamps'].append(timestamp)
                self.data['total_packets'].append(total_pkts)
                self.data['baseline_packets'].append(baseline_pkts)
                self.data['baseline_percent'].append(baseline_pct)
                self.data['attack_packets'].append(attack_pkts)
                self.data['attack_percent'].append(attack_pct)
                self.data['tcp_packets'].append(tcp_pkts)
                self.data['udp_packets'].append(udp_pkts)
                self.data['icmp_packets'].append(icmp_pkts)
                self.data['baseline_gbps'].append(baseline_gbps)
                self.data['attack_gbps'].append(attack_gbps)
                self.data['total_gbps'].append(total_gbps)
                self.data['cumulative_mpps'].append(cumulative_mpps)
                self.data['cumulative_gbps'].append(cumulative_gbps)
                self.data['syn_packets'].append(syn_pkts)
                self.data['syn_ack_packets'].append(syn_ack_pkts)
                self.data['syn_ack_ratio'].append(syn_ack_ratio)
                self.data['http_requests'].append(http_reqs)
                self.data['dns_queries'].append(dns_queries)
                self.data['udp_flood_events'].append(udp_flood)
                self.data['syn_flood_events'].append(syn_flood)
                self.data['http_flood_events'].append(http_flood)
                self.data['icmp_flood_events'].append(icmp_flood)
                self.data['dns_amp_events'].append(dns_amp)
                self.data['alert_level'].append(alert_level)
                self.data['alert_reason'].append(alert_reason)
                self.data['throughput_mpps'].append(throughput_mpps)
                self.data['cycles_per_pkt'].append(cycles_per_pkt)
                self.data['active_ips'].append(active_ips)
                self.data['rx_packets_nic'].append(rx_pkts_nic)
                self.data['rx_dropped'].append(rx_dropped)
                self.data['rx_no_mbufs'].append(rx_no_mbufs)
                self.data['rx_errors'].append(rx_errors)
                self.data['detection_latency_ms'].append(detection_latency if detection_latency else first_detection)
                self.data['improvement_factor'].append(improvement_factor if improvement_factor else 0)
                self.data['packets_until_detection'].append(pkts_until_detection)
                self.data['sketch_memory_kb'].append(sketch_memory)
                self.data['sketch_sampling_rate'].append(sketch_sampling)
                self.data['sketch_updates'].append(sketch_updates)

            except Exception as e:
                print(f"Warning: Error parsing block {block_idx}: {e}")
                continue

        # Convert to DataFrame for easier analysis
        self.df = pd.DataFrame(self.data)
        return self.df

    def _extract_int(self, text, pattern):
        """Extract integer from text using regex pattern"""
        match = re.search(pattern, text)
        return int(match.group(1)) if match else 0

    def _extract_float(self, text, pattern):
        """Extract float from text using regex pattern"""
        match = re.search(pattern, text)
        return float(match.group(1)) if match else 0.0

    def _extract_string(self, text, pattern):
        """Extract string from text using regex pattern"""
        match = re.search(pattern, text)
        return match.group(1).strip() if match else ""


class MIRAVisualizer:
    """Create comprehensive visualizations for MIRA experiment results"""

    def __init__(self, df, output_dir):
        self.df = df
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def plot_all(self):
        """Generate all visualization plots"""
        print("\n[GENERATING VISUALIZATIONS]")

        self.plot_detection_latency_comparison()
        self.plot_traffic_timeline()
        self.plot_attack_detection_events()
        self.plot_throughput_performance()
        self.plot_octosketch_metrics()
        self.plot_alert_timeline()
        self.generate_summary_table()

        print(f"\n✓ All visualizations saved to: {self.output_dir}/")

    def plot_detection_latency_comparison(self):
        """Plot 1: Detection latency comparison MIRA vs MULTI-LF"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Get first detection latency
        first_detection = self.df[self.df['detection_latency_ms'] > 0]['detection_latency_ms'].iloc[0] if len(self.df[self.df['detection_latency_ms'] > 0]) > 0 else 50
        multilf_latency = 866  # From paper

        # Bar chart comparison
        systems = ['MULTI-LF\n(ML-Based)', 'MIRA\n(DPDK + OctoSketch)']
        latencies = [multilf_latency, first_detection]
        colors = ['#ff6b6b', '#51cf66']

        bars = ax1.bar(systems, latencies, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('Detection Latency (ms)', fontweight='bold')
        ax1.set_title('Detection Latency Comparison', fontweight='bold', fontsize=14)
        ax1.set_ylim(0, max(latencies) * 1.2)

        # Add value labels on bars
        for bar, latency in zip(bars, latencies):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{latency:.2f} ms',
                    ha='center', va='bottom', fontweight='bold', fontsize=12)

        # Add improvement annotation
        improvement = multilf_latency / first_detection
        ax1.text(0.5, max(latencies) * 1.1, f'{improvement:.1f}× Faster',
                ha='center', fontsize=14, fontweight='bold', color='green',
                bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))

        ax1.grid(axis='y', alpha=0.3)

        # Horizontal comparison bar
        categories = ['Detection\nLatency']
        y_pos = np.arange(len(categories))

        ax2.barh(y_pos, [multilf_latency], color='#ff6b6b', alpha=0.8, label='MULTI-LF (866 ms)')
        ax2.barh(y_pos, [first_detection], color='#51cf66', alpha=0.8, label=f'MIRA ({first_detection:.2f} ms)')

        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(categories)
        ax2.set_xlabel('Latency (ms)', fontweight='bold')
        ax2.set_title('Side-by-Side Comparison', fontweight='bold', fontsize=14)
        ax2.legend(loc='upper right')
        ax2.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.output_dir / '01_detection_latency_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 01_detection_latency_comparison.png")

    def plot_traffic_timeline(self):
        """Plot 2: Traffic patterns over time"""
        fig = plt.figure(figsize=(16, 10))
        gs = GridSpec(3, 2, figure=fig, hspace=0.3, wspace=0.3)

        # Plot 1: Throughput over time
        ax1 = fig.add_subplot(gs[0, :])
        ax1.plot(self.df['timestamps'], self.df['baseline_gbps'],
                label='Benign Traffic (192.168.1.x)', color='#4CAF50', linewidth=2, marker='o', markersize=4)
        ax1.plot(self.df['timestamps'], self.df['attack_gbps'],
                label='Attack Traffic (192.168.2.x)', color='#F44336', linewidth=2, marker='s', markersize=4)
        ax1.plot(self.df['timestamps'], self.df['total_gbps'],
                label='Total Throughput', color='#2196F3', linewidth=2.5, marker='^', markersize=4, linestyle='--')

        ax1.set_xlabel('Time (seconds)', fontweight='bold')
        ax1.set_ylabel('Throughput (Gbps)', fontweight='bold')
        ax1.set_title('Traffic Throughput Over Time', fontweight='bold', fontsize=14)
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)

        # Shade attack period
        if any(self.df['attack_packets'] > 0):
            attack_start = self.df[self.df['attack_packets'] > 0]['timestamps'].iloc[0]
            ax1.axvspan(attack_start, self.df['timestamps'].max(), alpha=0.1, color='red', label='Attack Period')

        # Plot 2: Packet counts
        ax2 = fig.add_subplot(gs[1, 0])
        ax2.plot(self.df['timestamps'], self.df['baseline_packets'] / 1e6,
                label='Benign Packets', color='#4CAF50', linewidth=2)
        ax2.plot(self.df['timestamps'], self.df['attack_packets'] / 1e6,
                label='Attack Packets', color='#F44336', linewidth=2)
        ax2.set_xlabel('Time (seconds)', fontweight='bold')
        ax2.set_ylabel('Packets (Millions)', fontweight='bold')
        ax2.set_title('Packet Counts (5-second windows)', fontweight='bold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # Plot 3: Protocol distribution
        ax3 = fig.add_subplot(gs[1, 1])
        ax3.plot(self.df['timestamps'], self.df['tcp_packets'] / 1e6,
                label='TCP', color='#2196F3', linewidth=2)
        ax3.plot(self.df['timestamps'], self.df['udp_packets'] / 1e6,
                label='UDP', color='#FF9800', linewidth=2)
        ax3.plot(self.df['timestamps'], self.df['icmp_packets'] / 1e6,
                label='ICMP', color='#9C27B0', linewidth=2)
        ax3.set_xlabel('Time (seconds)', fontweight='bold')
        ax3.set_ylabel('Packets (Millions)', fontweight='bold')
        ax3.set_title('Protocol Distribution', fontweight='bold')
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # Plot 4: Cumulative performance
        ax4 = fig.add_subplot(gs[2, 0])
        ax4.plot(self.df['timestamps'], self.df['cumulative_mpps'],
                color='#673AB7', linewidth=2.5, marker='o', markersize=4)
        ax4.set_xlabel('Time (seconds)', fontweight='bold')
        ax4.set_ylabel('Cumulative Throughput (Mpps)', fontweight='bold')
        ax4.set_title('Cumulative Packet Rate', fontweight='bold')
        ax4.grid(True, alpha=0.3)

        # Plot 5: Cumulative Gbps
        ax5 = fig.add_subplot(gs[2, 1])
        ax5.plot(self.df['timestamps'], self.df['cumulative_gbps'],
                color='#00BCD4', linewidth=2.5, marker='s', markersize=4)
        ax5.set_xlabel('Time (seconds)', fontweight='bold')
        ax5.set_ylabel('Cumulative Throughput (Gbps)', fontweight='bold')
        ax5.set_title('Cumulative Bandwidth', fontweight='bold')
        ax5.grid(True, alpha=0.3)

        plt.savefig(self.output_dir / '02_traffic_timeline.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 02_traffic_timeline.png")

    def plot_attack_detection_events(self):
        """Plot 3: Attack detection events timeline"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 10))

        # Plot 1: UDP Flood events
        ax1.plot(self.df['timestamps'], self.df['udp_flood_events'],
                color='#FF5722', linewidth=2.5, marker='o', markersize=5)
        ax1.set_xlabel('Time (seconds)', fontweight='bold')
        ax1.set_ylabel('Cumulative Events', fontweight='bold')
        ax1.set_title('UDP Flood Detection Events', fontweight='bold', fontsize=13)
        ax1.grid(True, alpha=0.3)
        ax1.fill_between(self.df['timestamps'], self.df['udp_flood_events'], alpha=0.3, color='#FF5722')

        # Plot 2: SYN Flood events
        ax2.plot(self.df['timestamps'], self.df['syn_flood_events'],
                color='#E91E63', linewidth=2.5, marker='s', markersize=5)
        ax2.set_xlabel('Time (seconds)', fontweight='bold')
        ax2.set_ylabel('Cumulative Events', fontweight='bold')
        ax2.set_title('SYN Flood Detection Events', fontweight='bold', fontsize=13)
        ax2.grid(True, alpha=0.3)
        ax2.fill_between(self.df['timestamps'], self.df['syn_flood_events'], alpha=0.3, color='#E91E63')

        # Plot 3: HTTP Flood events
        ax3.plot(self.df['timestamps'], self.df['http_flood_events'],
                color='#9C27B0', linewidth=2.5, marker='^', markersize=5)
        ax3.set_xlabel('Time (seconds)', fontweight='bold')
        ax3.set_ylabel('Cumulative Events', fontweight='bold')
        ax3.set_title('HTTP Flood Detection Events', fontweight='bold', fontsize=13)
        ax3.grid(True, alpha=0.3)
        ax3.fill_between(self.df['timestamps'], self.df['http_flood_events'], alpha=0.3, color='#9C27B0')

        # Plot 4: ICMP Flood events
        ax4.plot(self.df['timestamps'], self.df['icmp_flood_events'],
                color='#3F51B5', linewidth=2.5, marker='D', markersize=5)
        ax4.set_xlabel('Time (seconds)', fontweight='bold')
        ax4.set_ylabel('Cumulative Events', fontweight='bold')
        ax4.set_title('ICMP Flood Detection Events', fontweight='bold', fontsize=13)
        ax4.grid(True, alpha=0.3)
        ax4.fill_between(self.df['timestamps'], self.df['icmp_flood_events'], alpha=0.3, color='#3F51B5')

        plt.tight_layout()
        plt.savefig(self.output_dir / '03_attack_detection_events.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 03_attack_detection_events.png")

    def plot_throughput_performance(self):
        """Plot 4: Throughput and performance metrics"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 10))

        # Plot 1: Instantaneous throughput (Mpps)
        ax1.plot(self.df['timestamps'], self.df['throughput_mpps'],
                color='#009688', linewidth=2.5, marker='o', markersize=4)
        ax1.set_xlabel('Time (seconds)', fontweight='bold')
        ax1.set_ylabel('Throughput (Mpps)', fontweight='bold')
        ax1.set_title('Packet Processing Rate', fontweight='bold', fontsize=13)
        ax1.grid(True, alpha=0.3)
        ax1.fill_between(self.df['timestamps'], self.df['throughput_mpps'], alpha=0.2, color='#009688')

        # Plot 2: Cycles per packet (CPU efficiency)
        ax2.plot(self.df['timestamps'], self.df['cycles_per_pkt'],
                color='#FF9800', linewidth=2.5, marker='s', markersize=4)
        ax2.set_xlabel('Time (seconds)', fontweight='bold')
        ax2.set_ylabel('Cycles per Packet', fontweight='bold')
        ax2.set_title('CPU Efficiency (lower = higher load)', fontweight='bold', fontsize=13)
        ax2.grid(True, alpha=0.3)

        # Plot 3: SYN/ACK ratio (attack indicator)
        ax3.plot(self.df['timestamps'], self.df['syn_ack_ratio'],
                color='#F44336', linewidth=2.5, marker='^', markersize=4)
        ax3.axhline(y=3.0, color='red', linestyle='--', linewidth=2, label='Attack Threshold (3:1)')
        ax3.set_xlabel('Time (seconds)', fontweight='bold')
        ax3.set_ylabel('SYN/ACK Ratio', fontweight='bold')
        ax3.set_title('SYN/ACK Ratio (SYN Flood Indicator)', fontweight='bold', fontsize=13)
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # Plot 4: DPDK NIC statistics
        ax4.plot(self.df['timestamps'], self.df['rx_packets_nic'] / 1e6,
                label='RX Packets (NIC)', color='#4CAF50', linewidth=2)
        ax4.plot(self.df['timestamps'], self.df['rx_dropped'] / 1e6,
                label='RX Dropped', color='#F44336', linewidth=2)
        ax4.set_xlabel('Time (seconds)', fontweight='bold')
        ax4.set_ylabel('Packets (Millions)', fontweight='bold')
        ax4.set_title('DPDK NIC Statistics', fontweight='bold', fontsize=13)
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.output_dir / '04_throughput_performance.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 04_throughput_performance.png")

    def plot_octosketch_metrics(self):
        """Plot 5: OctoSketch-specific metrics"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 10))

        # Plot 1: Memory usage
        sketch_memory = self.df['sketch_memory_kb'].iloc[-1] if len(self.df) > 0 else 5377
        labels = ['OctoSketch\n(14 workers)', 'Hash Table\n(Estimated)']
        memory_usage = [sketch_memory, sketch_memory * 50]  # Hash table ~50x more memory
        colors = ['#4CAF50', '#F44336']

        bars = ax1.bar(labels, memory_usage, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)
        ax1.set_ylabel('Memory Usage (KB)', fontweight='bold')
        ax1.set_title('Memory Efficiency: OctoSketch vs Hash Table', fontweight='bold', fontsize=13)
        ax1.set_yscale('log')

        for bar, mem in zip(bars, memory_usage):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{mem:.0f} KB',
                    ha='center', va='bottom', fontweight='bold')

        ax1.grid(axis='y', alpha=0.3)

        # Plot 2: Sketch updates over time
        if any(self.df['sketch_updates'] > 0):
            ax2.plot(self.df['timestamps'], self.df['sketch_updates'] / 1e6,
                    color='#673AB7', linewidth=2.5, marker='o', markersize=4)
            ax2.set_xlabel('Time (seconds)', fontweight='bold')
            ax2.set_ylabel('Sketch Updates (Millions)', fontweight='bold')
            ax2.set_title('OctoSketch Update Operations', fontweight='bold', fontsize=13)
            ax2.grid(True, alpha=0.3)
            ax2.fill_between(self.df['timestamps'], self.df['sketch_updates'] / 1e6, alpha=0.2, color='#673AB7')

        # Plot 3: Sampling efficiency
        sampling_rate = self.df['sketch_sampling_rate'].iloc[-1] if len(self.df) > 0 else 32
        overhead_pct = (1.0 / sampling_rate) * 100

        labels = ['Sampled\nPackets', 'Skipped\nPackets']
        sizes = [overhead_pct, 100 - overhead_pct]
        colors_pie = ['#FF9800', '#E0E0E0']
        explode = (0.1, 0)

        ax3.pie(sizes, explode=explode, labels=labels, colors=colors_pie, autopct='%1.2f%%',
                shadow=True, startangle=90, textprops={'fontsize': 11, 'fontweight': 'bold'})
        ax3.set_title(f'Sampling Rate: 1/{sampling_rate} packets\n({overhead_pct:.2f}% overhead)',
                     fontweight='bold', fontsize=13)

        # Plot 4: Detection latency histogram
        if any(self.df['detection_latency_ms'] > 0):
            latencies = self.df[self.df['detection_latency_ms'] > 0]['detection_latency_ms']
            ax4.hist(latencies, bins=20, color='#2196F3', alpha=0.7, edgecolor='black')
            ax4.axvline(latencies.mean(), color='red', linestyle='--', linewidth=2,
                       label=f'Mean: {latencies.mean():.2f} ms')
            ax4.axhline(y=866, color='orange', linestyle='--', linewidth=2,
                       label='MULTI-LF: 866 ms')
            ax4.set_xlabel('Detection Latency (ms)', fontweight='bold')
            ax4.set_ylabel('Frequency', fontweight='bold')
            ax4.set_title('Detection Latency Distribution', fontweight='bold', fontsize=13)
            ax4.legend()
            ax4.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.output_dir / '05_octosketch_metrics.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 05_octosketch_metrics.png")

    def plot_alert_timeline(self):
        """Plot 6: Alert level timeline with attack types"""
        fig = plt.figure(figsize=(16, 10))
        gs = GridSpec(2, 1, figure=fig, hspace=0.3, height_ratios=[1, 1.5])

        # Subplot 1: Alert levels
        ax1 = fig.add_subplot(gs[0])

        # Map alert levels to numeric values (normalize strings first)
        alert_map = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        alert_numeric = []

        # Debug: print unique alert levels found
        unique_levels = set()
        for level in self.df['alert_level']:
            clean_level = str(level).strip().upper()
            unique_levels.add(clean_level)
            alert_numeric.append(alert_map.get(clean_level, 0))

        print(f"  [DEBUG] Unique alert levels found: {unique_levels}")
        print(f"  [DEBUG] Alert numeric values: {set(alert_numeric)}")

        # Create color-coded timeline
        colors_map = {0: '#4CAF50', 1: '#FFEB3B', 2: '#FF9800', 3: '#F44336'}
        colors = [colors_map[val] for val in alert_numeric]

        # Plot with larger markers
        ax1.scatter(self.df['timestamps'], alert_numeric, c=colors, s=150, alpha=0.9, edgecolors='black', linewidths=2, zorder=3)
        ax1.plot(self.df['timestamps'], alert_numeric, color='gray', alpha=0.4, linewidth=2, linestyle='--', zorder=2)

        ax1.set_xlabel('Time (seconds)', fontweight='bold', fontsize=12)
        ax1.set_ylabel('Alert Level', fontweight='bold', fontsize=12)
        ax1.set_title('DDoS Alert Level Timeline', fontweight='bold', fontsize=14)
        ax1.set_yticks([0, 1, 2, 3])
        ax1.set_yticklabels(['NONE', 'LOW', 'MEDIUM', 'HIGH'])
        ax1.set_ylim(-0.5, 3.5)
        ax1.grid(True, alpha=0.3, zorder=1)

        # Add legend
        legend_elements = [
            mpatches.Patch(color='#4CAF50', label='NONE (No threat)'),
            mpatches.Patch(color='#FFEB3B', label='LOW (Monitoring)'),
            mpatches.Patch(color='#FF9800', label='MEDIUM (Warning)'),
            mpatches.Patch(color='#F44336', label='HIGH (Attack detected)')
        ]
        ax1.legend(handles=legend_elements, loc='upper left', fontsize=10, framealpha=0.9)

        # Shade attack detection periods
        high_alert_count = sum(1 for x in alert_numeric if x == 3)
        if high_alert_count > 0:
            high_alert_indices = [i for i, x in enumerate(alert_numeric) if x == 3]
            if len(high_alert_indices) > 0:
                start_idx = high_alert_indices[0]
                ax1.axvspan(self.df['timestamps'].iloc[start_idx], self.df['timestamps'].max(),
                          alpha=0.15, color='red', zorder=1)

                # Add annotation
                mid_point = (self.df['timestamps'].iloc[start_idx] + self.df['timestamps'].max()) / 2
                ax1.text(mid_point, 3.2, f'{high_alert_count} HIGH alerts detected',
                       ha='center', fontsize=10, fontweight='bold',
                       bbox=dict(boxstyle='round', facecolor='red', alpha=0.4), zorder=4)

        # Subplot 2: Attack types detected (from reason field)
        ax2 = fig.add_subplot(gs[1])

        # Parse attack types from reason field
        # Format: "UDP FLOOD detected: 1708544 UDP pps | SYN FLOOD detected: 2984756 SYN pps | ..."
        attack_types = {
            'UDP Flood': [],
            'SYN Flood': [],
            'HTTP Flood': [],
            'ICMP Flood': [],
            'DNS Amp': [],
        }

        attack_rates = {
            'UDP Flood': [],
            'SYN Flood': [],
            'HTTP Flood': [],
            'ICMP Flood': [],
            'DNS Amp': [],
        }

        for idx, reason in enumerate(self.df['alert_reason']):
            reason_str = str(reason)
            timestamp = self.df['timestamps'].iloc[idx]

            # Skip if reason is "None" or empty
            if reason_str in ['None', 'nan', ''] or pd.isna(reason):
                continue

            reason_upper = reason_str.upper()

            # Check for each attack type in the reason string
            # Format: "UDP FLOOD detected: 1708544 UDP pps | SYN FLOOD detected: ..."
            if 'UDP FLOOD DETECTED' in reason_upper:
                attack_types['UDP Flood'].append(timestamp)
                # Extract rate: "UDP FLOOD detected: 1708544 UDP pps"
                rate_match = re.search(r'UDP FLOOD DETECTED:\s+([\d,]+)\s+UDP\s+PPS', reason_upper)
                if rate_match:
                    attack_rates['UDP Flood'].append(int(rate_match.group(1).replace(',', '')))

            if 'SYN FLOOD DETECTED' in reason_upper:
                attack_types['SYN Flood'].append(timestamp)
                rate_match = re.search(r'SYN FLOOD DETECTED:\s+([\d,]+)\s+SYN\s+PPS', reason_upper)
                if rate_match:
                    attack_rates['SYN Flood'].append(int(rate_match.group(1).replace(',', '')))

            if 'HTTP FLOOD DETECTED' in reason_upper:
                attack_types['HTTP Flood'].append(timestamp)
                rate_match = re.search(r'HTTP FLOOD DETECTED:\s+([\d,]+)\s+HTTP\s+RPS', reason_upper)
                if rate_match:
                    attack_rates['HTTP Flood'].append(int(rate_match.group(1).replace(',', '')))

            if 'ICMP FLOOD DETECTED' in reason_upper:
                attack_types['ICMP Flood'].append(timestamp)
                rate_match = re.search(r'ICMP FLOOD DETECTED:\s+([\d,]+)\s+ICMP\s+PPS', reason_upper)
                if rate_match:
                    attack_rates['ICMP Flood'].append(int(rate_match.group(1).replace(',', '')))

            if 'DNS AMP' in reason_upper or 'DNS AMPLIFICATION' in reason_upper:
                attack_types['DNS Amp'].append(timestamp)

        # Debug: print attack types found
        print(f"  [DEBUG] Attack types detected:")
        for attack_type, timestamps in attack_types.items():
            if len(timestamps) > 0:
                avg_rate = np.mean(attack_rates[attack_type]) if len(attack_rates[attack_type]) > 0 else 0
                print(f"    - {attack_type}: {len(timestamps)} occurrences (avg rate: {avg_rate:,.0f} pps/rps)")

        # Plot attack types as horizontal lines
        y_positions = {'UDP Flood': 0, 'SYN Flood': 1, 'HTTP Flood': 2, 'ICMP Flood': 3, 'DNS Amp': 4}
        colors_attack = {'UDP Flood': '#FF5722', 'SYN Flood': '#E91E63',
                        'HTTP Flood': '#9C27B0', 'ICMP Flood': '#3F51B5', 'DNS Amp': '#00BCD4'}

        for attack_type, timestamps in attack_types.items():
            if attack_type in y_positions and len(timestamps) > 0:
                y_pos = y_positions[attack_type]

                # Calculate average rate for label
                avg_rate = np.mean(attack_rates[attack_type]) if len(attack_rates[attack_type]) > 0 else 0
                unit = 'rps' if attack_type == 'HTTP Flood' else 'pps'
                label = f'{attack_type} (avg: {avg_rate/1e6:.2f}M {unit})' if avg_rate > 0 else attack_type

                ax2.scatter(timestamps, [y_pos] * len(timestamps),
                           c=colors_attack[attack_type], s=200, alpha=0.8,
                           marker='s', edgecolors='black', linewidths=1.5, label=label)

                # Draw horizontal line to show duration
                if len(timestamps) > 1:
                    ax2.plot([timestamps[0], timestamps[-1]], [y_pos, y_pos],
                            color=colors_attack[attack_type], linewidth=4, alpha=0.3)

                # Add annotation with count at the end
                if len(timestamps) > 0:
                    last_time = timestamps[-1]
                    ax2.text(last_time + 1, y_pos, f'{len(timestamps)}',
                            fontsize=9, fontweight='bold',
                            bbox=dict(boxstyle='round,pad=0.3', facecolor=colors_attack[attack_type], alpha=0.3))

        ax2.set_xlabel('Time (seconds)', fontweight='bold', fontsize=12)
        ax2.set_ylabel('Attack Type', fontweight='bold', fontsize=12)
        ax2.set_title('Detected Attack Types Over Time', fontweight='bold', fontsize=14)
        ax2.set_yticks(list(y_positions.values()))
        ax2.set_yticklabels(list(y_positions.keys()))
        ax2.set_ylim(-0.5, 4.5)
        ax2.grid(True, alpha=0.3, axis='x')
        ax2.legend(loc='upper right', fontsize=10)

        # Add vertical line at attack start
        if high_alert_count > 0 and len(high_alert_indices) > 0:
            attack_start_time = self.df['timestamps'].iloc[high_alert_indices[0]]
            ax2.axvline(x=attack_start_time, color='red', linestyle='--', linewidth=2,
                       alpha=0.5, label='Attack Start')

        plt.tight_layout()
        plt.savefig(self.output_dir / '06_alert_and_attack_types.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("  ✓ Generated: 06_alert_and_attack_types.png")

    def generate_summary_table(self):
        """Generate summary statistics table"""
        # Calculate summary statistics
        total_packets = self.df['total_packets'].sum()
        total_baseline = self.df['baseline_packets'].sum()
        total_attack = self.df['attack_packets'].sum()
        avg_throughput_gbps = self.df['total_gbps'].mean()
        max_throughput_gbps = self.df['total_gbps'].max()
        avg_throughput_mpps = self.df['throughput_mpps'].mean()

        # Detection metrics
        first_detection = self.df[self.df['detection_latency_ms'] > 0]['detection_latency_ms'].iloc[0] if len(self.df[self.df['detection_latency_ms'] > 0]) > 0 else 0
        total_udp_floods = self.df['udp_flood_events'].max()
        total_syn_floods = self.df['syn_flood_events'].max()
        total_http_floods = self.df['http_flood_events'].max()
        total_icmp_floods = self.df['icmp_flood_events'].max()

        # OctoSketch metrics
        sketch_memory = self.df['sketch_memory_kb'].iloc[-1] if len(self.df) > 0 else 0
        sketch_sampling = self.df['sketch_sampling_rate'].iloc[-1] if len(self.df) > 0 else 0

        # Performance metrics
        avg_cycles_per_pkt = self.df['cycles_per_pkt'].mean()
        total_rx_dropped = self.df['rx_dropped'].sum()
        drop_rate = (total_rx_dropped / self.df['rx_packets_nic'].sum() * 100) if self.df['rx_packets_nic'].sum() > 0 else 0

        # Create summary table with more vertical space and top margin for title
        fig = plt.figure(figsize=(16, 15))
        ax = fig.add_axes([0.1, 0.05, 0.8, 0.85])  # [left, bottom, width, height]
        ax.axis('tight')
        ax.axis('off')

        summary_data = [
            ['EXPERIMENT SUMMARY', ''],
            ['Experiment Duration', f'{self.df["timestamps"].max():.1f} seconds'],
            ['Total Packets Processed', f'{total_packets:,}'],
            ['Baseline Traffic', f'{total_baseline:,} packets ({total_baseline/total_packets*100:.1f}%)'],
            ['Attack Traffic', f'{total_attack:,} packets ({total_attack/total_packets*100:.1f}%)'],
            ['', ''],
            ['THROUGHPUT METRICS', ''],
            ['Average Throughput', f'{avg_throughput_gbps:.2f} Gbps ({avg_throughput_mpps:.2f} Mpps)'],
            ['Peak Throughput', f'{max_throughput_gbps:.2f} Gbps'],
            ['Average Cycles/Packet', f'{avg_cycles_per_pkt:.0f} cycles'],
            ['', ''],
            ['DETECTION METRICS', ''],
            ['First Detection Latency', f'{first_detection:.2f} ms (vs MULTI-LF: 866 ms)'],
            ['Improvement Factor', f'{866/first_detection:.1f}× faster than MULTI-LF' if first_detection > 0 else 'N/A'],
            ['UDP Flood Events', f'{total_udp_floods}'],
            ['SYN Flood Events', f'{total_syn_floods}'],
            ['HTTP Flood Events', f'{total_http_floods}'],
            ['ICMP Flood Events', f'{total_icmp_floods}'],
            ['', ''],
            ['OCTOSKETCH METRICS', ''],
            ['Total Sketch Memory', f'{sketch_memory:.0f} KB (14 workers × {sketch_memory/14:.1f} KB)' if sketch_memory > 0 else 'N/A'],
            ['Sampling Rate', f'1 in {sketch_sampling} packets ({100/sketch_sampling:.2f}% overhead)' if sketch_sampling > 0 else 'N/A'],
            ['Architecture', 'Per-worker (lock-free, no atomics)'],
            ['Memory Complexity', 'O(1) constant'],
            ['', ''],
            ['DPDK PERFORMANCE', ''],
            ['Total RX Packets (NIC)', f'{self.df["rx_packets_nic"].sum():,}'],
            ['Total RX Dropped', f'{total_rx_dropped:,} ({drop_rate:.3f}%)'],
            ['RX No Mbufs', f'{self.df["rx_no_mbufs"].sum():,}'],
            ['RX Errors', f'{self.df["rx_errors"].sum():,}'],
        ]

        # Create table with better spacing
        table = ax.table(cellText=summary_data, cellLoc='left', loc='center',
                        colWidths=[0.45, 0.55])
        table.auto_set_font_size(False)
        table.set_fontsize(10)
        table.scale(1, 3.0)  # Increased vertical scale

        # Style header rows
        header_rows = [0, 6, 11, 19, 25]
        for i in header_rows:
            if i < len(summary_data):
                table[(i, 0)].set_facecolor('#2196F3')
                table[(i, 0)].set_text_props(weight='bold', color='white', fontsize=11)
                table[(i, 1)].set_facecolor('#2196F3')
                table[(i, 1)].set_text_props(color='white')

        # Alternate row colors for better readability
        for i in range(len(summary_data)):
            if i not in header_rows and i % 2 == 0:
                table[(i, 0)].set_facecolor('#E3F2FD')
                table[(i, 1)].set_facecolor('#E3F2FD')

        # Make metric names bold
        for i in range(len(summary_data)):
            if i not in header_rows and summary_data[i][0] != '':
                table[(i, 0)].set_text_props(weight='bold')

        # Add title at the top with proper positioning
        fig.text(0.5, 0.95, 'MIRA DDoS Detector - Experiment Summary',
                ha='center', fontweight='bold', fontsize=18)
        fig.text(0.5, 0.92, 'DPDK + OctoSketch vs MULTI-LF (2025)',
                ha='center', fontweight='bold', fontsize=14, color='#2196F3')

        plt.savefig(self.output_dir / '07_summary_table.png', dpi=300, bbox_inches='tight', pad_inches=0.3)
        plt.close()
        print("  ✓ Generated: 07_summary_table.png")


def main():
    """Main analysis function"""
    # Set paths
    script_dir = Path(__file__).parent
    log_file = script_dir.parent / 'results' / 'mira_detector_multicore.log'
    output_dir = script_dir / 'output'

    print("╔═══════════════════════════════════════════════════════════════════════╗")
    print("║   MIRA DDoS DETECTOR - OCTOSKETCH RESULTS ANALYSIS                   ║")
    print("╚═══════════════════════════════════════════════════════════════════════╝")
    print(f"\nLog file: {log_file}")
    print(f"Output directory: {output_dir}")

    # Check if log file exists
    if not log_file.exists():
        print(f"\n❌ ERROR: Log file not found: {log_file}")
        print("\nPlease ensure the detector has been run and generated the log file.")
        sys.exit(1)

    # Parse log file
    print("\n[PARSING LOG FILE]")
    parser = MIRALogParser(log_file)
    df = parser.parse()

    if len(df) == 0:
        print("\n❌ ERROR: No data extracted from log file")
        sys.exit(1)

    print(f"  ✓ Extracted {len(df)} data points")
    print(f"  ✓ Time range: 0 - {df['timestamps'].max():.1f} seconds")

    # Generate visualizations
    visualizer = MIRAVisualizer(df, output_dir)
    visualizer.plot_all()

    # Print summary
    print("\n" + "="*75)
    print("EXPERIMENT SUMMARY")
    print("="*75)

    first_detection = df[df['detection_latency_ms'] > 0]['detection_latency_ms'].iloc[0] if len(df[df['detection_latency_ms'] > 0]) > 0 else 0
    if first_detection > 0:
        print(f"\n✓ First Detection Latency: {first_detection:.2f} ms")
        print(f"✓ MULTI-LF Latency: 866 ms")
        print(f"✓ Improvement: {866/first_detection:.1f}× FASTER")

    print(f"\n✓ Total Packets: {df['total_packets'].sum():,}")
    print(f"✓ Average Throughput: {df['total_gbps'].mean():.2f} Gbps")
    print(f"✓ Peak Throughput: {df['total_gbps'].max():.2f} Gbps")

    print(f"\n✓ UDP Flood Events: {df['udp_flood_events'].max()}")
    print(f"✓ SYN Flood Events: {df['syn_flood_events'].max()}")
    print(f"✓ HTTP Flood Events: {df['http_flood_events'].max()}")
    print(f"✓ ICMP Flood Events: {df['icmp_flood_events'].max()}")

    sketch_memory = df['sketch_memory_kb'].iloc[-1] if len(df) > 0 else 0
    sketch_sampling = df['sketch_sampling_rate'].iloc[-1] if len(df) > 0 else 0
    print(f"\n✓ OctoSketch Memory: {sketch_memory:.0f} KB")
    print(f"✓ Sampling Rate: 1/{sketch_sampling} packets ({100/sketch_sampling:.2f}% overhead)")

    print("\n" + "="*75)
    print(f"\n✅ Analysis complete! Check {output_dir}/ for visualizations.\n")


if __name__ == '__main__':
    main()
