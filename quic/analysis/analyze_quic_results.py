#!/usr/bin/env python3
"""
QUIC Optimistic ACK Attack Analysis

Analisis avanzado de resultados del detector QUIC Optimistic ACK con
metricas de baseline, ataque, eficacia de deteccion y utilizacion del enlace.

Uso:
    python3 analyze_quic_results.py

Genera:
    - 01_traffic_overview.png
    - 02_detection_efficacy.png
    - 03_baseline_vs_attack.png
    - 04_link_utilization.png
    - 05_ack_analysis.png
"""

import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import numpy as np
import os


class QUICOptimisticACKAnalyzer:
    def __init__(self, log_file, output_dir, avg_packet_size=700, link_capacity_gbps=25, attack_start_time=130):
        self.log_file = log_file
        self.output_dir = output_dir
        self.snapshots = []
        self.avg_packet_size = avg_packet_size
        self.link_capacity_gbps = link_capacity_gbps
        self.attack_start_time = attack_start_time  # When attack traffic starts

        os.makedirs(output_dir, exist_ok=True)
        self.parse_log()

    def pps_to_gbps(self, pps):
        """Convert packets per second to Gbps"""
        return (pps * self.avg_packet_size * 8) / 1e9

    def calculate_link_utilization(self, gbps):
        """Calculate link utilization percentage"""
        return (gbps / self.link_capacity_gbps) * 100

    def parse_log(self):
        """Parse log file and extract statistics"""
        with open(self.log_file, 'r', encoding='utf-8') as f:
            content = f.read()

        stats_sections = re.split(r'╔═+╗\n║\s+QUIC OPTIMISTIC ACK DETECTOR - STATISTICS\s+║', content)[1:]

        for i, section in enumerate(stats_sections):
            snapshot = self.parse_snapshot(section, i)
            if snapshot:
                self.snapshots.append(snapshot)

        # Post-process to calculate throughput
        self.calculate_throughput()

    def parse_snapshot(self, section, index):
        """Parse individual snapshot of statistics"""
        snapshot = {'index': index, 'interval': (index + 1) * 5}

        # Total packets
        match = re.search(r'Total packets:\s+(\d+)', section)
        if match:
            snapshot['total_packets'] = int(match.group(1))

        # QUIC packets
        match = re.search(r'QUIC packets:\s+(\d+)', section)
        if match:
            snapshot['quic_packets'] = int(match.group(1))

        # Baseline packets
        match = re.search(r'Baseline \(192\.168\):\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['baseline_packets'] = int(match.group(1))
            snapshot['baseline_percent'] = float(match.group(2))

        # Attack packets
        match = re.search(r'Attack \(203\.0\.113\):\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['attack_packets'] = int(match.group(1))
            snapshot['attack_percent'] = float(match.group(2))

        # Long/Short headers
        match = re.search(r'Long headers:\s+(\d+)', section)
        if match:
            snapshot['long_headers'] = int(match.group(1))

        match = re.search(r'Short headers:\s+(\d+)', section)
        if match:
            snapshot['short_headers'] = int(match.group(1))

        # Total ACKs
        match = re.search(r'Total ACKs:\s+(\d+)', section)
        if match:
            snapshot['total_acks'] = int(match.group(1))

        # Bytes analysis
        match = re.search(r'Bytes IN \(client\):\s+(\d+)', section)
        if match:
            snapshot['bytes_in'] = int(match.group(1))

        match = re.search(r'Bytes OUT \(server\):\s+(\d+)', section)
        if match:
            snapshot['bytes_out'] = int(match.group(1))

        match = re.search(r'Ratio OUT/IN:\s+([\d.]+)', section)
        if match:
            snapshot['bytes_ratio'] = float(match.group(1))

        # IP analysis
        match = re.search(r'Unique IPs:\s+(\d+)', section)
        if match:
            snapshot['unique_ips'] = int(match.group(1))

        match = re.search(r'Heavy ACKers:\s+(\d+)', section)
        if match:
            snapshot['heavy_ackers'] = int(match.group(1))

        match = re.search(r'Suspicious IPs:\s+(\d+)', section)
        if match:
            snapshot['suspicious_ips'] = int(match.group(1))

        # Attack indicators
        match = re.search(r'High ACK rate:\s+(\d+)', section)
        if match:
            snapshot['high_ack_rate_detections'] = int(match.group(1))

        match = re.search(r'Bytes anomalies:\s+(\d+)', section)
        if match:
            snapshot['bytes_anomalies'] = int(match.group(1))

        match = re.search(r'Max bytes ratio:\s+([\d.]+)', section)
        if match:
            snapshot['max_bytes_ratio'] = float(match.group(1))

        match = re.search(r'Max ACK rate/IP:\s+(\d+)', section)
        if match:
            snapshot['max_ack_rate'] = int(match.group(1))

        # Alert level
        match = re.search(r'Alert level:\s+(\w+)', section)
        if match:
            snapshot['alert_level'] = match.group(1)

        # Alert reason
        match = re.search(r'Reason:\s+(.+?)(?:\n|$)', section)
        if match:
            snapshot['alert_reason'] = match.group(1).strip()
        else:
            snapshot['alert_reason'] = 'None'

        return snapshot if snapshot.get('total_packets') else None

    def calculate_throughput(self):
        """Calculate throughput for each snapshot based on packet deltas"""
        for i, snapshot in enumerate(self.snapshots):
            # Set timestamp
            snapshot['timestamp'] = snapshot['interval']

            if i == 0:
                # First snapshot - calculate from 0
                baseline_pps = snapshot.get('baseline_packets', 0) / 5.0
                attack_pps = snapshot.get('attack_packets', 0) / 5.0
                total_pps = snapshot.get('quic_packets', 0) / 5.0
            else:
                # Calculate delta from previous snapshot
                prev = self.snapshots[i - 1]
                baseline_delta = snapshot.get('baseline_packets', 0) - prev.get('baseline_packets', 0)
                attack_delta = snapshot.get('attack_packets', 0) - prev.get('attack_packets', 0)
                total_delta = snapshot.get('quic_packets', 0) - prev.get('quic_packets', 0)

                # Convert to pps (interval is 5 seconds)
                baseline_pps = max(0, baseline_delta / 5.0)
                attack_pps = max(0, attack_delta / 5.0)
                total_pps = max(0, total_delta / 5.0)

            # Convert to Gbps
            snapshot['baseline_throughput_gbps'] = self.pps_to_gbps(baseline_pps)
            snapshot['attack_throughput_gbps'] = self.pps_to_gbps(attack_pps)
            snapshot['total_throughput_gbps'] = self.pps_to_gbps(total_pps)

    def calculate_metrics(self):
        """Calculate comprehensive experiment metrics"""
        if not self.snapshots:
            return {}

        # Use actual attack start time instead of attack_percent
        baseline_phase = [s for s in self.snapshots if s['interval'] < self.attack_start_time]
        attack_phase = [s for s in self.snapshots if s['interval'] >= self.attack_start_time]

        metrics = {
            'total_snapshots': len(self.snapshots),
            'baseline_snapshots': len(baseline_phase),
            'attack_snapshots': len(attack_phase),
            'total_duration': self.snapshots[-1]['interval'],
        }

        if baseline_phase:
            last_baseline = baseline_phase[-1]
            metrics['baseline_duration'] = last_baseline['interval']
            metrics['baseline_total_packets'] = last_baseline.get('quic_packets', 0)
            metrics['baseline_avg_pps'] = last_baseline.get('quic_packets', 0) / last_baseline['interval']
            metrics['baseline_unique_ips'] = last_baseline.get('unique_ips', 0)
            metrics['baseline_total_acks'] = last_baseline.get('total_acks', 0)

            metrics['baseline_gbps'] = self.pps_to_gbps(metrics['baseline_avg_pps'])
            metrics['baseline_link_utilization'] = self.calculate_link_utilization(metrics['baseline_gbps'])

        if attack_phase:
            first_attack = attack_phase[0]
            last_attack = attack_phase[-1]

            total_attack_packets = last_attack.get('attack_packets', 0)
            attack_duration = last_attack['interval'] - first_attack['interval'] + 5

            metrics['attack_start_time'] = first_attack['interval']
            metrics['attack_duration'] = attack_duration
            metrics['total_attack_packets'] = total_attack_packets
            metrics['attack_avg_pps'] = total_attack_packets / attack_duration if attack_duration > 0 else 0

            metrics['attack_gbps'] = self.pps_to_gbps(metrics['attack_avg_pps'])
            metrics['attack_link_utilization'] = self.calculate_link_utilization(metrics['attack_gbps'])

            # Total during attack
            total_pps_during_attack = []
            for i, s in enumerate(attack_phase):
                if i == 0:
                    prev_total = baseline_phase[-1].get('quic_packets', 0) if baseline_phase else 0
                else:
                    prev_total = attack_phase[i-1].get('quic_packets', 0)
                pps = (s.get('quic_packets', 0) - prev_total) / 5
                total_pps_during_attack.append(pps)

            metrics['total_avg_pps_during_attack'] = np.mean(total_pps_during_attack) if total_pps_during_attack else 0
            metrics['total_gbps_during_attack'] = self.pps_to_gbps(metrics['total_avg_pps_during_attack'])
            metrics['total_link_utilization_during_attack'] = self.calculate_link_utilization(metrics['total_gbps_during_attack'])

            # Attack percentages
            metrics['max_attack_percent'] = max(s.get('attack_percent', 0) for s in attack_phase)
            metrics['avg_attack_percent'] = np.mean([s.get('attack_percent', 0) for s in attack_phase])

            # ACK statistics
            metrics['max_bytes_ratio'] = max(s.get('max_bytes_ratio', 0) for s in attack_phase)
            metrics['max_ack_rate'] = max(s.get('max_ack_rate', 0) for s in attack_phase)

            # Detection performance
            first_detection = next((s for s in self.snapshots if s.get('alert_level') not in ['NONE', None]), None)
            if first_detection:
                metrics['time_to_detection'] = first_detection['interval']
                metrics['detection_alert_level'] = first_detection['alert_level']
                if first_detection['interval'] >= metrics['attack_start_time']:
                    metrics['detection_delay'] = first_detection['interval'] - metrics['attack_start_time']
                else:
                    metrics['detection_delay'] = 0

            # Alert counts
            alert_counts = {'NONE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
            for s in self.snapshots:
                level = s.get('alert_level', 'NONE')
                alert_counts[level] = alert_counts.get(level, 0) + 1

            metrics['alert_counts'] = alert_counts

            # Detection accuracy
            attack_detected = sum(1 for s in attack_phase if s.get('alert_level') not in ['NONE', None])
            metrics['detection_rate'] = (attack_detected / len(attack_phase) * 100) if attack_phase else 0

            # False positives
            baseline_alerts = sum(1 for s in baseline_phase if s.get('alert_level') not in ['NONE', None])
            metrics['false_positives'] = baseline_alerts
            metrics['false_positive_rate'] = (baseline_alerts / len(baseline_phase) * 100) if baseline_phase else 0

            # True positives
            high_alerts_attack = sum(1 for s in attack_phase if s.get('alert_level') == 'HIGH')
            metrics['true_positives'] = high_alerts_attack
            metrics['true_positive_rate'] = (high_alerts_attack / len(attack_phase) * 100) if attack_phase else 0

        return metrics

    def print_metrics(self):
        """Print comprehensive metrics"""
        metrics = self.calculate_metrics()

        print("\n" + "="*80)
        print("QUIC OPTIMISTIC ACK ATTACK ANALYSIS - COMPREHENSIVE METRICS")
        print("="*80)

        print("\n[EXPERIMENT OVERVIEW]")
        print(f"  Total snapshots:              {metrics.get('total_snapshots', 0)}")
        print(f"  Total duration:               {metrics.get('total_duration', 0)} seconds")
        print(f"  Baseline snapshots:           {metrics.get('baseline_snapshots', 0)}")
        print(f"  Attack snapshots:             {metrics.get('attack_snapshots', 0)}")

        print("\n[BASELINE TRAFFIC]")
        print(f"  Duration:                     {metrics.get('baseline_duration', 0)} seconds")
        print(f"  Total QUIC packets:           {metrics.get('baseline_total_packets', 0):,}")
        print(f"  Average pps:                  {metrics.get('baseline_avg_pps', 0):,.0f}")
        print(f"  Unique IPs:                   {metrics.get('baseline_unique_ips', 0):,}")
        print(f"  Total ACKs:                   {metrics.get('baseline_total_acks', 0):,}")

        print("\n[LINK UTILIZATION - BASELINE]")
        print(f"  Throughput:                   {metrics.get('baseline_gbps', 0):.2f} Gbps")
        print(f"  Link utilization:             {metrics.get('baseline_link_utilization', 0):.1f}% of {self.link_capacity_gbps}G")

        print("\n[ATTACK TRAFFIC]")
        print(f"  Start time:                   {metrics.get('attack_start_time', 0)} seconds")
        print(f"  Duration:                     {metrics.get('attack_duration', 0)} seconds")
        print(f"  Total attack packets:         {metrics.get('total_attack_packets', 0):,}")
        print(f"  Average attack pps:           {metrics.get('attack_avg_pps', 0):,.0f}")
        print(f"  Maximum attack %:             {metrics.get('max_attack_percent', 0):.1f}%")
        print(f"  Average attack %:             {metrics.get('avg_attack_percent', 0):.1f}%")

        print("\n[OPTIMISTIC ACK INDICATORS]")
        print(f"  Max bytes ratio (OUT/IN):     {metrics.get('max_bytes_ratio', 0):.2f}")
        print(f"  Max ACK rate per IP:          {metrics.get('max_ack_rate', 0):,}")

        print("\n[LINK UTILIZATION - DURING ATTACK]")
        print(f"  Attack traffic only:          {metrics.get('attack_gbps', 0):.2f} Gbps ({metrics.get('attack_link_utilization', 0):.1f}%)")
        print(f"  Total traffic (base+attack):  {metrics.get('total_gbps_during_attack', 0):.2f} Gbps ({metrics.get('total_link_utilization_during_attack', 0):.1f}%)")
        print(f"  Link capacity:                {self.link_capacity_gbps} Gbps")

        print("\n[DETECTION PERFORMANCE]")
        if metrics.get('time_to_detection'):
            print(f"  Time to first detection:      {metrics.get('time_to_detection', 0)} seconds")
            print(f"  Detection delay:              {metrics.get('detection_delay', 0)} seconds")
            print(f"  Initial alert level:          {metrics.get('detection_alert_level', 'N/A')}")
        else:
            print(f"  No attack detected")

        print(f"  Detection rate:               {metrics.get('detection_rate', 0):.1f}%")
        print(f"  True positive rate (HIGH):    {metrics.get('true_positive_rate', 0):.1f}%")

        print("\n[ALERT DISTRIBUTION]")
        alert_counts = metrics.get('alert_counts', {})
        for level in ['NONE', 'LOW', 'MEDIUM', 'HIGH']:
            count = alert_counts.get(level, 0)
            percentage = (count / metrics.get('total_snapshots', 1) * 100)
            print(f"  {level:8s}: {count:3d} snapshots ({percentage:5.1f}%)")

        print("\n[FALSE POSITIVES]")
        print(f"  False positives (baseline):   {metrics.get('false_positives', 0)}")
        print(f"  False positive rate:          {metrics.get('false_positive_rate', 0):.1f}%")

        print("\n[OVERALL EFFICACY]")
        if metrics.get('attack_snapshots', 0) > 0:
            tp = metrics.get('true_positives', 0)
            fp = metrics.get('false_positives', 0)
            precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
            print(f"  Precision:                    {precision:.1f}%")

            recall = metrics.get('true_positive_rate', 0)
            print(f"  Recall (Sensitivity):         {recall:.1f}%")

            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
            print(f"  F1 Score:                     {f1:.1f}%")

        print("="*80 + "\n")

        return metrics

    def plot_traffic_overview(self):
        """Generate comprehensive traffic overview"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('QUIC Optimistic ACK Attack - Traffic Analysis', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]
        total_packets = [s.get('quic_packets', 0) for s in self.snapshots]
        baseline_packets = [s.get('baseline_packets', 0) for s in self.snapshots]
        attack_packets = [s.get('attack_packets', 0) for s in self.snapshots]
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]

        # 1. Cumulative packets
        ax1 = axes[0, 0]
        ax1.plot(intervals, total_packets, 'k-', linewidth=2, label='Total', zorder=3)
        ax1.fill_between(intervals, baseline_packets, alpha=0.4, color='green', label='Baseline', zorder=1)
        ax1.fill_between(intervals, baseline_packets, total_packets, alpha=0.4, color='red', label='Attack', zorder=2)
        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Cumulative Packets', fontsize=12)
        ax1.set_title('Traffic Distribution: Baseline vs Attack', fontsize=14, fontweight='bold')
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)

        # 2. Attack percentage
        ax2 = axes[0, 1]
        colors = ['green' if p == 0 else 'orange' if p < 30 else 'red' for p in attack_percent]
        ax2.bar(intervals, attack_percent, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax2.axhline(y=30, color='red', linestyle='--', linewidth=2, label='Critical threshold (30%)')
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Attack Traffic (%)', fontsize=12)
        ax2.set_title('Attack Intensity Over Time', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. PPS
        ax3 = axes[1, 0]
        pps_total = []
        pps_baseline = []
        pps_attack = []

        for i in range(len(self.snapshots)):
            if i == 0:
                pps_baseline.append(baseline_packets[i] / 5)
                pps_attack.append(attack_packets[i] / 5)
                pps_total.append(total_packets[i] / 5)
            else:
                pps_baseline.append((baseline_packets[i] - baseline_packets[i-1]) / 5)
                pps_attack.append((attack_packets[i] - attack_packets[i-1]) / 5)
                pps_total.append((total_packets[i] - total_packets[i-1]) / 5)

        ax3.plot(intervals, pps_total, 'k-', linewidth=2, marker='o', markersize=3, label='Total PPS', alpha=0.7)
        ax3.plot(intervals, pps_baseline, 'g-', linewidth=2, marker='o', markersize=3, label='Baseline PPS', alpha=0.7)
        ax3.plot(intervals, pps_attack, 'r-', linewidth=2, marker='s', markersize=3, label='Attack PPS', alpha=0.7)
        ax3.set_xlabel('Time (seconds)', fontsize=12)
        ax3.set_ylabel('Packets per Second (PPS)', fontsize=12)
        ax3.set_title('Traffic Rate Analysis', fontsize=14, fontweight='bold')
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. Alert levels
        ax4 = axes[1, 1]
        alert_levels = [s.get('alert_level', 'NONE') for s in self.snapshots]
        alert_numeric = []
        for level in alert_levels:
            if level == 'NONE':
                alert_numeric.append(0)
            elif level == 'LOW':
                alert_numeric.append(1)
            elif level == 'MEDIUM':
                alert_numeric.append(2)
            elif level == 'HIGH':
                alert_numeric.append(3)
            else:
                alert_numeric.append(0)

        colors_alert = ['green' if a == 0 else 'yellow' if a == 1 else 'orange' if a == 2 else 'red' for a in alert_numeric]
        ax4.bar(intervals, alert_numeric, width=4, color=colors_alert, alpha=0.7, edgecolor='black')
        ax4.set_xlabel('Time (seconds)', fontsize=12)
        ax4.set_ylabel('Alert Level', fontsize=12)
        ax4.set_title('Detection System Alert Status', fontsize=14, fontweight='bold')
        ax4.set_yticks([0, 1, 2, 3])
        ax4.set_yticklabels(['NONE', 'LOW', 'MEDIUM', 'HIGH'])
        ax4.grid(True, alpha=0.3, axis='x')

        plt.tight_layout()
        output_path = os.path.join(self.output_dir, '01_traffic_overview.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\n[FIGURE 1: Traffic Overview] - Saved to {output_path}")

    def plot_ack_analysis(self):
        """Generate ACK-specific analysis for Optimistic ACK attack"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('QUIC Optimistic ACK Attack - ACK Analysis', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]

        # 1. Total ACKs over time
        ax1 = axes[0, 0]
        total_acks = [s.get('total_acks', 0) for s in self.snapshots]
        ax1.plot(intervals, total_acks, 'b-', linewidth=2, marker='o', markersize=4)
        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Cumulative ACKs', fontsize=12)
        ax1.set_title('Total ACK Frames Over Time', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)

        # 2. Bytes ratio (key indicator)
        ax2 = axes[0, 1]
        bytes_ratio = [s.get('bytes_ratio', 0) for s in self.snapshots]
        colors = ['green' if r < 5 else 'orange' if r < 10 else 'red' for r in bytes_ratio]
        ax2.bar(intervals, bytes_ratio, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax2.axhline(y=10, color='red', linestyle='--', linewidth=2, label='Amplification threshold (10x)')
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Bytes OUT/IN Ratio', fontsize=12)
        ax2.set_title('Amplification Ratio (Key Attack Indicator)', fontsize=14, fontweight='bold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Heavy ACKers and suspicious IPs
        ax3 = axes[1, 0]
        heavy_ackers = [s.get('heavy_ackers', 0) for s in self.snapshots]
        suspicious_ips = [s.get('suspicious_ips', 0) for s in self.snapshots]

        ax3.plot(intervals, heavy_ackers, 'r-', linewidth=2, marker='s', markersize=4, label='Heavy ACKers')
        ax3.plot(intervals, suspicious_ips, 'purple', linewidth=2, marker='^', markersize=4, label='Suspicious IPs')
        ax3.set_xlabel('Time (seconds)', fontsize=12)
        ax3.set_ylabel('Count', fontsize=12)
        ax3.set_title('Anomalous IP Detection', fontsize=14, fontweight='bold')
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. ACK rate per snapshot
        ax4 = axes[1, 1]
        ack_rates = []
        for i in range(len(self.snapshots)):
            if i == 0:
                rate = total_acks[i] / 5
            else:
                rate = (total_acks[i] - total_acks[i-1]) / 5
            ack_rates.append(rate)

        colors = ['green' if r < 5000 else 'orange' if r < 10000 else 'red' for r in ack_rates]
        ax4.bar(intervals, ack_rates, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax4.axhline(y=5000, color='orange', linestyle='--', linewidth=1, alpha=0.7, label='Warning (5K ACKs/s)')
        ax4.axhline(y=10000, color='red', linestyle='--', linewidth=2, label='Critical (10K ACKs/s)')
        ax4.set_xlabel('Time (seconds)', fontsize=12)
        ax4.set_ylabel('ACKs per Second', fontsize=12)
        ax4.set_title('ACK Rate Analysis', fontsize=14, fontweight='bold')
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()
        output_path = os.path.join(self.output_dir, '05_ack_analysis.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\n[FIGURE 5: ACK Analysis] - Saved to {output_path}")

    def plot_detection_efficacy(self):
        """Generate detection efficacy analysis"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Detection System Efficacy Analysis', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]
        metrics = self.calculate_metrics()
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]

        # 1. Detection timeline
        ax1 = axes[0, 0]
        alert_levels = [s.get('alert_level', 'NONE') for s in self.snapshots]

        # Plot attack intensity as background
        ax1_twin = ax1.twinx()
        line1 = ax1.plot(intervals, attack_percent, 'r-', linewidth=3, label='Attack Intensity (%)', alpha=0.7)

        # Plot detection events
        detection_times = []
        detection_levels = []
        for i, s in enumerate(self.snapshots):
            if s.get('alert_level') == 'HIGH':
                detection_times.append(s['interval'])
                detection_levels.append(s.get('attack_percent', 0))

        if detection_times:
            line2 = ax1.scatter(detection_times, detection_levels, color='darkred', s=100, marker='X',
                               label='HIGH Alert', zorder=5, edgecolors='black', linewidths=1)

        # Mark attack start
        if metrics.get('attack_start_time'):
            ax1.axvline(x=metrics['attack_start_time'], color='orange', linestyle='--',
                       linewidth=2, label=f"Attack Start ({metrics['attack_start_time']}s)")

        # Mark first detection
        if metrics.get('time_to_detection'):
            ax1.axvline(x=metrics['time_to_detection'], color='blue', linestyle='--',
                       linewidth=2, label=f"First Detection ({metrics['time_to_detection']}s)")

        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Attack Traffic (%)', fontsize=12, color='r')
        ax1.set_title('Detection Timeline', fontsize=14, fontweight='bold')
        ax1.tick_params(axis='y', labelcolor='r')
        ax1.set_ylim(0, 100)
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)

        # 2. ACK rate over time
        ax2 = axes[0, 1]
        total_acks = [s.get('total_acks', 0) for s in self.snapshots]
        ack_rates = []
        for i in range(len(self.snapshots)):
            if i == 0:
                rate = total_acks[i] / 5 if total_acks[i] > 0 else 0
            else:
                rate = (total_acks[i] - total_acks[i-1]) / 5
            ack_rates.append(rate)

        ax2.plot(intervals, ack_rates, 'b-', linewidth=2, marker='o', markersize=3, label='ACK Rate', alpha=0.7)
        ax2.axhline(y=5000, color='orange', linestyle='--', linewidth=2, label='Warning threshold')
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('ACKs per Second', fontsize=12)
        ax2.set_title('ACK Rate Over Time', fontsize=14, fontweight='bold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Detection confusion matrix
        ax3 = axes[1, 0]

        baseline_phase = [s for s in self.snapshots if s.get('attack_percent', 0) == 0]
        attack_phase = [s for s in self.snapshots if s.get('attack_percent', 0) > 0]

        # True Negatives: Baseline with no alert
        tn = sum(1 for s in baseline_phase if s.get('alert_level') in ['NONE', None])
        # False Positives: Baseline with alert
        fp = sum(1 for s in baseline_phase if s.get('alert_level') not in ['NONE', None])
        # True Positives: Attack with HIGH alert
        tp = sum(1 for s in attack_phase if s.get('alert_level') == 'HIGH')
        # False Negatives: Attack with no HIGH alert
        fn = sum(1 for s in attack_phase if s.get('alert_level') != 'HIGH')

        confusion_matrix = np.array([[tn, fp], [fn, tp]])

        im = ax3.imshow(confusion_matrix, cmap='RdYlGn', alpha=0.8)
        ax3.set_xticks([0, 1])
        ax3.set_yticks([0, 1])
        ax3.set_xticklabels(['No Attack\n(Predicted)', 'Attack\n(Predicted)'])
        ax3.set_yticklabels(['No Attack\n(Actual)', 'Attack\n(Actual)'])
        ax3.set_title('Detection Confusion Matrix', fontsize=14, fontweight='bold')

        # Add text annotations
        for i in range(2):
            for j in range(2):
                total = confusion_matrix.sum()
                if total > 0:
                    text = ax3.text(j, i, f'{confusion_matrix[i, j]}\n({confusion_matrix[i, j]/total*100:.1f}%)',
                                   ha="center", va="center", color="black", fontsize=14, fontweight='bold')

        plt.colorbar(im, ax=ax3)

        # 4. Efficacy metrics summary
        ax4 = axes[1, 1]
        ax4.axis('off')

        # Calculate metrics
        precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
        accuracy = ((tp + tn) / (tp + tn + fp + fn) * 100) if (tp + tn + fp + fn) > 0 else 0

        summary_text = f"""
DETECTION EFFICACY SUMMARY

Performance Metrics:
  • Accuracy:        {accuracy:.1f}%
  • Precision:       {precision:.1f}%
  • Recall:          {recall:.1f}%
  • F1 Score:        {f1_score:.1f}%

Detection Stats:
  • True Positives:  {tp} snapshots
  • True Negatives:  {tn} snapshots
  • False Positives: {fp} snapshots
  • False Negatives: {fn} snapshots

Timing:
  • Attack Start:    {metrics.get('attack_start_time', 0)}s
  • First Detection: {metrics.get('time_to_detection', 0)}s
  • Detection Delay: {metrics.get('detection_delay', 0)}s

Attack Indicators:
  • Max Bytes Ratio: {metrics.get('max_bytes_ratio', 0):.2f}
  • Max ACK Rate:    {metrics.get('max_ack_rate', 0):,}
        """

        ax4.text(0.1, 0.95, summary_text, transform=ax4.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.tight_layout()
        output_path = os.path.join(self.output_dir, '02_detection_efficacy.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\n[FIGURE 2: Detection Efficacy] - Saved to {output_path}")

    def plot_baseline_vs_attack(self):
        """Generate baseline vs attack comparison"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Baseline vs Attack Traffic Comparison', fontsize=16, fontweight='bold')

        metrics = self.calculate_metrics()
        intervals = [s['interval'] for s in self.snapshots]

        # 1. Packet distribution comparison
        ax1 = axes[0, 0]
        categories = ['Total Packets', 'Average PPS', 'Total ACKs']
        baseline_values = [
            metrics.get('baseline_total_packets', 0),
            metrics.get('baseline_avg_pps', 0),
            metrics.get('baseline_total_acks', 0)
        ]
        attack_values = [
            metrics.get('total_attack_packets', 0),
            metrics.get('attack_avg_pps', 0),
            0  # Attack ACKs not separately tracked
        ]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax1.bar(x - width/2, baseline_values, width, label='Baseline', color='green', alpha=0.7)
        bars2 = ax1.bar(x + width/2, attack_values, width, label='Attack', color='red', alpha=0.7)

        ax1.set_ylabel('Values', fontsize=12)
        ax1.set_title('Traffic Comparison: Baseline vs Attack', fontsize=14, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(categories)
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')

        # Add value labels on bars
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                if height > 0:
                    ax1.annotate(f'{height:,.0f}',
                                xy=(bar.get_x() + bar.get_width() / 2, height),
                                xytext=(0, 3),
                                textcoords="offset points",
                                ha='center', va='bottom', fontsize=8)

        # 2. QUIC packet types
        ax2 = axes[0, 1]
        long_headers = [s.get('long_headers', 0) for s in self.snapshots]
        short_headers = [s.get('short_headers', 0) for s in self.snapshots]

        ax2.plot(intervals, long_headers, 'b-', linewidth=2, marker='o', markersize=3, label='Long Headers', alpha=0.7)
        ax2.plot(intervals, short_headers, 'g-', linewidth=2, marker='s', markersize=3, label='Short Headers', alpha=0.7)
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Cumulative Count', fontsize=12)
        ax2.set_title('QUIC Header Types Over Time', fontsize=14, fontweight='bold')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Attack percentage distribution
        ax3 = axes[1, 0]
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]

        # Count snapshots by attack percentage ranges
        ranges = [(0, 0, 'No Attack'), (0.1, 20, 'Low'), (20, 40, 'Medium'), (40, 100, 'High')]
        range_counts = []
        range_labels = []
        range_colors = ['green', 'yellow', 'orange', 'red']

        for min_val, max_val, label in ranges:
            count = sum(1 for p in attack_percent if min_val <= p < max_val or (min_val == 0 and p == 0))
            range_counts.append(count)
            range_labels.append(label)

        if sum(range_counts) > 0:
            wedges, texts, autotexts = ax3.pie(range_counts, labels=range_labels, colors=range_colors,
                                                autopct='%1.1f%%', shadow=True, startangle=90)
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(10)

        ax3.set_title('Attack Intensity Distribution', fontsize=14, fontweight='bold')

        # 4. Phase breakdown
        ax4 = axes[1, 1]

        # Phase durations
        baseline_duration = metrics.get('baseline_duration', 0)
        attack_duration = metrics.get('attack_duration', 0)

        phase_labels = ['Baseline\nPhase', 'Attack\nPhase']
        phase_durations = [baseline_duration, attack_duration]
        phase_colors = ['green', 'red']

        if max(phase_durations) > 0:
            bars = ax4.barh(phase_labels, phase_durations, color=phase_colors, alpha=0.7, edgecolor='black', linewidth=2)

            ax4.set_xlabel('Duration (seconds)', fontsize=12)
            ax4.set_title('Experiment Phase Breakdown', fontsize=14, fontweight='bold')
            ax4.grid(True, alpha=0.3, axis='x')

            # Add value labels
            for i, (bar, duration) in enumerate(zip(bars, phase_durations)):
                if duration > 0:
                    width = bar.get_width()
                    total_duration = metrics.get('total_duration', 1)
                    ax4.text(width + 5, bar.get_y() + bar.get_height()/2,
                            f'{duration}s\n({duration/total_duration*100:.1f}%)',
                            ha='left', va='center', fontsize=11, fontweight='bold')

        plt.tight_layout()
        output_path = os.path.join(self.output_dir, '03_baseline_vs_attack.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\n[FIGURE 3: Baseline vs Attack] - Saved to {output_path}")

    def plot_link_utilization(self):
        """Generate link utilization analysis"""
        if not self.snapshots:
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Link Utilization Analysis ({self.link_capacity_gbps}G Link)', fontsize=16, fontweight='bold')

        # Extract data
        times = [s['timestamp'] for s in self.snapshots]
        baseline_throughput = [s['baseline_throughput_gbps'] for s in self.snapshots]
        attack_throughput = [s['attack_throughput_gbps'] for s in self.snapshots]
        total_throughput = [s['total_throughput_gbps'] for s in self.snapshots]
        link_utilization = [(t / self.link_capacity_gbps) * 100 for t in total_throughput]

        # Calculate phase statistics
        baseline_phase = [s for s in self.snapshots if s['timestamp'] < self.attack_start_time]
        attack_phase = [s for s in self.snapshots if s['timestamp'] >= self.attack_start_time]

        # 1. Throughput over time
        ax1 = axes[0, 0]
        ax1.fill_between(times, 0, baseline_throughput, alpha=0.6, color='green', label='Baseline Traffic')
        ax1.fill_between(times, baseline_throughput, total_throughput, alpha=0.6, color='red', label='Attack Traffic')
        ax1.plot(times, total_throughput, 'b-', linewidth=2, label='Total Throughput')
        ax1.axhline(y=self.link_capacity_gbps, color='gray', linestyle='--', linewidth=2, label=f'{self.link_capacity_gbps}G Link Capacity')
        ax1.axvline(x=self.attack_start_time, color='orange', linestyle=':', linewidth=2, label='Attack Start')
        ax1.set_xlabel('Time (seconds)', fontweight='bold')
        ax1.set_ylabel('Throughput (Gbps)', fontweight='bold')
        ax1.set_title('Throughput Over Time (Stacked)', fontweight='bold', fontsize=12)
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)

        # 2. Link utilization percentage
        ax2 = axes[0, 1]

        # Calculate average utilization for each phase
        baseline_util = sum([s['total_throughput_gbps'] for s in baseline_phase]) / len(baseline_phase) / self.link_capacity_gbps * 100 if baseline_phase else 0
        attack_util = sum([s['total_throughput_gbps'] for s in attack_phase]) / len(attack_phase) / self.link_capacity_gbps * 100 if attack_phase else 0

        phases = [f'Baseline Only\n(0-{self.attack_start_time}s)', f'Baseline + Attack\n({self.attack_start_time}-500s)']
        utilizations = [baseline_util, attack_util]
        colors = ['green', 'red']

        bars = ax2.bar(phases, utilizations, color=colors, alpha=0.7, edgecolor='black', linewidth=2)
        ax2.axhline(y=100, color='gray', linestyle='--', linewidth=2, label='100% Capacity')
        ax2.set_ylabel('Link Utilization (%)', fontweight='bold')
        ax2.set_title('Average Link Utilization by Phase', fontweight='bold', fontsize=12)
        ax2.set_ylim(0, 110)
        ax2.legend()
        ax2.grid(True, alpha=0.3, axis='y')

        # Add percentage labels on bars
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.1f}%',
                    ha='center', va='bottom', fontweight='bold', fontsize=11)

        # 3. Throughput breakdown comparison
        ax3 = axes[1, 0]

        # Calculate averages for each phase
        baseline_avg_baseline = sum([s['baseline_throughput_gbps'] for s in baseline_phase]) / len(baseline_phase) if baseline_phase else 0
        baseline_avg_attack = 0  # No attack during baseline phase
        attack_avg_baseline = sum([s['baseline_throughput_gbps'] for s in attack_phase]) / len(attack_phase) if attack_phase else 0
        attack_avg_attack = sum([s['attack_throughput_gbps'] for s in attack_phase]) / len(attack_phase) if attack_phase else 0

        x_pos = np.arange(len(phases))
        width = 0.35

        baseline_bars = ax3.bar(x_pos - width/2, [baseline_avg_baseline, attack_avg_baseline],
                               width, label='Baseline Traffic', color='green', alpha=0.7, edgecolor='black')
        attack_bars = ax3.bar(x_pos + width/2, [baseline_avg_attack, attack_avg_attack],
                             width, label='Attack Traffic', color='red', alpha=0.7, edgecolor='black')

        ax3.set_ylabel('Throughput (Gbps)', fontweight='bold')
        ax3.set_title('Throughput Breakdown by Phase', fontweight='bold', fontsize=12)
        ax3.set_xticks(x_pos)
        ax3.set_xticklabels(phases)
        ax3.legend()
        ax3.grid(True, alpha=0.3, axis='y')

        # Add value labels
        for bars_group in [baseline_bars, attack_bars]:
            for bar in bars_group:
                height = bar.get_height()
                if height > 0:
                    ax3.text(bar.get_x() + bar.get_width()/2., height,
                            f'{height:.2f}',
                            ha='center', va='bottom', fontsize=9)

        # 4. Summary statistics
        ax4 = axes[1, 1]
        ax4.axis('off')

        # Calculate detailed statistics
        baseline_total_avg = baseline_avg_baseline + baseline_avg_attack
        attack_total_avg = attack_avg_baseline + attack_avg_attack

        peak_throughput = max(total_throughput)
        peak_utilization = max(link_utilization)
        avg_throughput = sum(total_throughput) / len(total_throughput)
        avg_utilization = (avg_throughput / self.link_capacity_gbps) * 100

        # Calculate traffic increase
        traffic_increase = ((attack_total_avg - baseline_total_avg) / baseline_total_avg * 100) if baseline_total_avg > 0 else 0

        summary_text = f"""
LINK UTILIZATION SUMMARY
{'='*50}

Link Capacity: {self.link_capacity_gbps} Gbps

BASELINE PHASE (0-{self.attack_start_time}s):
  • Baseline Traffic:     {baseline_avg_baseline:>8.2f} Gbps
  • Total Throughput:     {baseline_total_avg:>8.2f} Gbps
  • Link Utilization:     {baseline_util:>8.1f}%

ATTACK PHASE ({self.attack_start_time}-500s):
  • Baseline Traffic:     {attack_avg_baseline:>8.2f} Gbps
  • Attack Traffic:       {attack_avg_attack:>8.2f} Gbps
  • Total Throughput:     {attack_total_avg:>8.2f} Gbps
  • Link Utilization:     {attack_util:>8.1f}%

OVERALL STATISTICS:
  • Average Throughput:   {avg_throughput:>8.2f} Gbps
  • Average Utilization:  {avg_utilization:>8.1f}%
  • Peak Throughput:      {peak_throughput:>8.2f} Gbps
  • Peak Utilization:     {peak_utilization:>8.1f}%

TRAFFIC IMPACT:
  • Traffic Increase:     {traffic_increase:>8.1f}%
  • Attack/Total Ratio:   {(attack_avg_attack/attack_total_avg*100) if attack_total_avg > 0 else 0:>8.1f}%
"""

        ax4.text(0.05, 0.95, summary_text, transform=ax4.transAxes,
                fontfamily='monospace', fontsize=10, verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))

        plt.tight_layout()
        output_path = os.path.join(self.output_dir, '04_link_utilization.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"\n[FIGURE 4: Link Utilization] - Saved to {output_path}")


def main():
    log_file = r'C:\Users\claud\Comi_archi\MD\codigo\dpdk_100g\quic\results\results_quic_optimistic_ack.log'
    output_dir = os.path.dirname(__file__)

    print("\n" + "="*80)
    print("QUIC OPTIMISTIC ACK ATTACK ANALYZER")
    print("="*80)
    print(f"\nLog file: {log_file}")
    print(f"Output directory: {output_dir}")

    analyzer = QUICOptimisticACKAnalyzer(log_file, output_dir, avg_packet_size=700, link_capacity_gbps=25)

    metrics = analyzer.print_metrics()

    print("\nGenerating analysis figures...\n")
    analyzer.plot_traffic_overview()
    analyzer.plot_ack_analysis()
    analyzer.plot_detection_efficacy()
    analyzer.plot_baseline_vs_attack()
    analyzer.plot_link_utilization()

    print("\n" + "="*80)
    print("ANALYSIS COMPLETED")
    print("="*80)
    print(f"\nAll figures saved to: {output_dir}")
    print("Generated files:")
    print("  - 01_traffic_overview.png")
    print("  - 02_detection_efficacy.png")
    print("  - 03_baseline_vs_attack.png")
    print("  - 04_link_utilization.png")
    print("  - 05_ack_analysis.png\n")


if __name__ == "__main__":
    main()
