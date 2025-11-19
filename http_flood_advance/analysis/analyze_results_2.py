#!/usr/bin/env python3
"""
HTTP Flood Attack Analysis v2
Advanced analysis of HTTP Flood detector results with baseline, attack, and detection efficacy metrics
"""

import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import numpy as np
import os


class HTTPFloodAnalyzer:
    def __init__(self, log_file, output_dir, avg_packet_size=700, link_capacity_gbps=100):
        self.log_file = log_file
        self.output_dir = output_dir
        self.snapshots = []
        self.avg_packet_size = avg_packet_size  # bytes
        self.link_capacity_gbps = link_capacity_gbps  # Gbps

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        self.parse_log()

    def pps_to_gbps(self, pps):
        """Convert packets per second to Gbps"""
        # Gbps = (pps * packet_size_bytes * 8) / 1e9
        return (pps * self.avg_packet_size * 8) / 1e9

    def calculate_link_utilization(self, gbps):
        """Calculate link utilization percentage"""
        return (gbps / self.link_capacity_gbps) * 100

    def parse_log(self):
        """Parse log file and extract statistics"""
        with open(self.log_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find all statistics sections
        stats_sections = re.split(r'╔═+╗\n║\s+HTTP FLOOD DETECTOR - STATISTICS\s+║', content)[1:]

        for i, section in enumerate(stats_sections):
            snapshot = self.parse_snapshot(section, i)
            if snapshot:
                self.snapshots.append(snapshot)

    def parse_snapshot(self, section, index):
        """Parse individual snapshot of statistics"""
        snapshot = {'index': index, 'interval': (index + 1) * 5}  # 5 seconds per interval

        # Total packets
        match = re.search(r'Total packets:\s+(\d+)', section)
        if match:
            snapshot['total_packets'] = int(match.group(1))

        # HTTP packets
        match = re.search(r'HTTP packets:\s+(\d+)', section)
        if match:
            snapshot['http_packets'] = int(match.group(1))

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

        # Unique IPs
        match = re.search(r'Unique IPs:\s+(\d+)', section)
        if match:
            snapshot['unique_ips'] = int(match.group(1))

        # Heavy hitters
        match = re.search(r'Heavy hitters:\s+(\d+)', section)
        if match:
            snapshot['heavy_hitters'] = int(match.group(1))

        # HTTP Methods
        match = re.search(r'GET:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['get_count'] = int(match.group(1))
            snapshot['get_percent'] = float(match.group(2))

        match = re.search(r'POST:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['post_count'] = int(match.group(1))
            snapshot['post_percent'] = float(match.group(2))

        # URL Concentration
        match = re.search(r'Top URL count:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['top_url_count'] = int(match.group(1))
            snapshot['top_url_percent'] = float(match.group(2))

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

    def calculate_metrics(self):
        """Calculate comprehensive experiment metrics"""
        if not self.snapshots:
            return {}

        # Baseline phase (before attack)
        baseline_phase = [s for s in self.snapshots if s.get('attack_percent', 0) == 0]

        # Attack phase
        attack_phase = [s for s in self.snapshots if s.get('attack_percent', 0) > 0]

        metrics = {
            'total_snapshots': len(self.snapshots),
            'baseline_snapshots': len(baseline_phase),
            'attack_snapshots': len(attack_phase),
            'total_duration': self.snapshots[-1]['interval'],
        }

        if baseline_phase:
            last_baseline = baseline_phase[-1]
            metrics['baseline_duration'] = last_baseline['interval']
            metrics['baseline_total_packets'] = last_baseline['total_packets']
            metrics['baseline_avg_pps'] = last_baseline['total_packets'] / last_baseline['interval']
            metrics['baseline_unique_ips'] = last_baseline['unique_ips']

            # Calculate Gbps and link utilization for baseline
            metrics['baseline_gbps'] = self.pps_to_gbps(metrics['baseline_avg_pps'])
            metrics['baseline_link_utilization'] = self.calculate_link_utilization(metrics['baseline_gbps'])

        if attack_phase:
            first_attack = attack_phase[0]
            last_attack = attack_phase[-1]

            # Attack packets
            total_attack_packets = last_attack.get('attack_packets', 0)
            attack_duration = last_attack['interval'] - first_attack['interval'] + 5

            metrics['attack_start_time'] = first_attack['interval']
            metrics['attack_duration'] = attack_duration
            metrics['total_attack_packets'] = total_attack_packets
            metrics['attack_avg_pps'] = total_attack_packets / attack_duration if attack_duration > 0 else 0

            # Calculate Gbps and link utilization for attack traffic only
            metrics['attack_gbps'] = self.pps_to_gbps(metrics['attack_avg_pps'])
            metrics['attack_link_utilization'] = self.calculate_link_utilization(metrics['attack_gbps'])

            # Calculate total traffic during attack phase (baseline + attack)
            total_pps_during_attack = []
            for i, s in enumerate(attack_phase):
                if i == 0:
                    prev_total = baseline_phase[-1]['total_packets'] if baseline_phase else 0
                else:
                    prev_total = attack_phase[i-1]['total_packets']
                pps = (s['total_packets'] - prev_total) / 5
                total_pps_during_attack.append(pps)

            metrics['total_avg_pps_during_attack'] = np.mean(total_pps_during_attack) if total_pps_during_attack else 0
            metrics['total_gbps_during_attack'] = self.pps_to_gbps(metrics['total_avg_pps_during_attack'])
            metrics['total_link_utilization_during_attack'] = self.calculate_link_utilization(metrics['total_gbps_during_attack'])

            # Maximum attack percentage
            metrics['max_attack_percent'] = max(s.get('attack_percent', 0) for s in attack_phase)
            metrics['avg_attack_percent'] = np.mean([s.get('attack_percent', 0) for s in attack_phase])

            # Time to first detection
            first_detection = next((s for s in self.snapshots if s.get('alert_level') not in ['NONE', None]), None)
            if first_detection:
                metrics['time_to_detection'] = first_detection['interval']
                metrics['detection_alert_level'] = first_detection['alert_level']

                # Detection delay (time between attack start and detection)
                if first_detection['interval'] >= metrics['attack_start_time']:
                    metrics['detection_delay'] = first_detection['interval'] - metrics['attack_start_time']
                else:
                    metrics['detection_delay'] = 0

            # Alerts generated
            alert_counts = {'NONE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
            for s in self.snapshots:
                level = s.get('alert_level', 'NONE')
                alert_counts[level] = alert_counts.get(level, 0) + 1

            metrics['alert_counts'] = alert_counts

            # Maximum heavy hitters
            metrics['max_heavy_hitters'] = max(s.get('heavy_hitters', 0) for s in self.snapshots)

            # Detection accuracy during attack
            attack_detected = sum(1 for s in attack_phase if s.get('alert_level') not in ['NONE', None])
            metrics['detection_rate'] = (attack_detected / len(attack_phase) * 100) if attack_phase else 0

            # False positives (alerts during baseline)
            baseline_alerts = sum(1 for s in baseline_phase if s.get('alert_level') not in ['NONE', None])
            metrics['false_positives'] = baseline_alerts
            metrics['false_positive_rate'] = (baseline_alerts / len(baseline_phase) * 100) if baseline_phase else 0

            # True positives (HIGH alerts during attack)
            high_alerts_attack = sum(1 for s in attack_phase if s.get('alert_level') == 'HIGH')
            metrics['true_positives'] = high_alerts_attack
            metrics['true_positive_rate'] = (high_alerts_attack / len(attack_phase) * 100) if attack_phase else 0

        return metrics

    def print_metrics(self):
        """Print comprehensive metrics"""
        metrics = self.calculate_metrics()

        print("\n" + "="*80)
        print("HTTP FLOOD ATTACK ANALYSIS - COMPREHENSIVE METRICS")
        print("="*80)

        print("\n[EXPERIMENT OVERVIEW]")
        print(f"  Total snapshots:              {metrics.get('total_snapshots', 0)}")
        print(f"  Total duration:               {metrics.get('total_duration', 0)} seconds")
        print(f"  Baseline snapshots:           {metrics.get('baseline_snapshots', 0)}")
        print(f"  Attack snapshots:             {metrics.get('attack_snapshots', 0)}")

        print("\n[BASELINE TRAFFIC]")
        print(f"  Duration:                     {metrics.get('baseline_duration', 0)} seconds")
        print(f"  Total packets:                {metrics.get('baseline_total_packets', 0):,}")
        print(f"  Average pps:                  {metrics.get('baseline_avg_pps', 0):,.0f}")
        print(f"  Unique IPs:                   {metrics.get('baseline_unique_ips', 0):,}")

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

        print(f"  Maximum heavy hitters:        {metrics.get('max_heavy_hitters', 0):,}")
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
            # Precision: True positives / (True positives + False positives)
            tp = metrics.get('true_positives', 0)
            fp = metrics.get('false_positives', 0)
            precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0
            print(f"  Precision:                    {precision:.1f}%")

            # Recall: True positives / Total attack snapshots
            recall = metrics.get('true_positive_rate', 0)
            print(f"  Recall (Sensitivity):         {recall:.1f}%")

            # F1 Score
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
        fig.suptitle('HTTP Flood Attack - Traffic Analysis', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]
        total_packets = [s['total_packets'] for s in self.snapshots]
        baseline_packets = [s.get('baseline_packets', 0) for s in self.snapshots]
        attack_packets = [s.get('attack_packets', 0) for s in self.snapshots]
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]

        # 1. Cumulative packets (baseline vs attack)
        ax1 = axes[0, 0]
        ax1.plot(intervals, total_packets, 'k-', linewidth=2, label='Total', zorder=3)
        ax1.fill_between(intervals, baseline_packets, alpha=0.4, color='green', label='Baseline', zorder=1)
        ax1.fill_between(intervals, baseline_packets, total_packets, alpha=0.4, color='red', label='Attack', zorder=2)
        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Cumulative Packets', fontsize=12)
        ax1.set_title('Traffic Distribution: Baseline vs Attack', fontsize=14, fontweight='bold')
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)
        ax1.ticklabel_format(style='plain', axis='y')

        # 2. Attack percentage over time
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

        # 3. Packet rate (PPS) - incremental
        ax3 = axes[1, 0]
        pps_baseline = []
        pps_attack = []
        pps_total = []

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
        ax3.ticklabel_format(style='plain', axis='y')

        # 4. Alert levels over time
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

        # Custom legend
        none_patch = mpatches.Patch(color='green', alpha=0.7, label='NONE')
        low_patch = mpatches.Patch(color='yellow', alpha=0.7, label='LOW')
        medium_patch = mpatches.Patch(color='orange', alpha=0.7, label='MEDIUM')
        high_patch = mpatches.Patch(color='red', alpha=0.7, label='HIGH')
        ax4.legend(handles=[none_patch, low_patch, medium_patch, high_patch], loc='upper left')

        plt.tight_layout()

        # Save figure
        output_path = os.path.join(self.output_dir, '01_traffic_overview.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[FIGURE 1: Traffic Overview] - Saved to {output_path}")

    def plot_detection_efficacy(self):
        """Generate detection efficacy analysis"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Detection System Efficacy Analysis', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]
        metrics = self.calculate_metrics()

        # 1. Detection timeline
        ax1 = axes[0, 0]
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]
        alert_levels = [s.get('alert_level', 'NONE') for s in self.snapshots]

        # Plot attack intensity
        ax1_twin = ax1.twinx()
        line1 = ax1.plot(intervals, attack_percent, 'r-', linewidth=3, label='Attack Intensity (%)', alpha=0.7)

        # Plot detection events
        detection_times = []
        detection_levels = []
        for i, s in enumerate(self.snapshots):
            if s.get('alert_level') == 'HIGH':
                detection_times.append(s['interval'])
                detection_levels.append(s.get('attack_percent', 0))

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

        # 2. Heavy hitters detection
        ax2 = axes[0, 1]
        unique_ips = [s.get('unique_ips', 0) for s in self.snapshots]
        heavy_hitters = [s.get('heavy_hitters', 0) for s in self.snapshots]

        ax2_twin = ax2.twinx()
        line1 = ax2.plot(intervals, unique_ips, 'b-', linewidth=2, marker='o', markersize=3, label='Unique IPs', alpha=0.7)
        line2 = ax2_twin.plot(intervals, heavy_hitters, 'r-', linewidth=2, marker='s', markersize=3, label='Heavy Hitters', alpha=0.7)

        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Unique IPs', fontsize=12, color='b')
        ax2_twin.set_ylabel('Heavy Hitters', fontsize=12, color='r')
        ax2.set_title('Heavy Hitter Detection', fontsize=14, fontweight='bold')
        ax2.tick_params(axis='y', labelcolor='b')
        ax2_twin.tick_params(axis='y', labelcolor='r')
        ax2.grid(True, alpha=0.3)

        # Combine legends
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax2.legend(lines, labels, loc='upper left')

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
                text = ax3.text(j, i, f'{confusion_matrix[i, j]}\n({confusion_matrix[i, j]/(confusion_matrix.sum())*100:.1f}%)',
                               ha="center", va="center", color="black", fontsize=14, fontweight='bold')

        # Add labels
        ax3.text(-0.5, 0, 'TN', ha="center", va="center", fontsize=10, fontweight='bold', color='green')
        ax3.text(1.5, 0, 'FP', ha="center", va="center", fontsize=10, fontweight='bold', color='orange')
        ax3.text(-0.5, 1, 'FN', ha="center", va="center", fontsize=10, fontweight='bold', color='orange')
        ax3.text(1.5, 1, 'TP', ha="center", va="center", fontsize=10, fontweight='bold', color='green')

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

Attack Profile:
  • Total Packets:   {metrics.get('total_attack_packets', 0):,}
  • Avg Attack PPS:  {metrics.get('attack_avg_pps', 0):,.0f}
  • Max Attack %:    {metrics.get('max_attack_percent', 0):.1f}%
        """

        ax4.text(0.1, 0.95, summary_text, transform=ax4.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.tight_layout()

        # Save figure
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
        categories = ['Total Packets', 'Average PPS']
        baseline_values = [
            metrics.get('baseline_total_packets', 0),
            metrics.get('baseline_avg_pps', 0)
        ]
        attack_values = [
            metrics.get('total_attack_packets', 0),
            metrics.get('attack_avg_pps', 0)
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
                ax1.annotate(f'{height:,.0f}',
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=9)

        # 2. HTTP methods distribution
        ax2 = axes[0, 1]
        get_percent = [s.get('get_percent', 0) for s in self.snapshots]
        post_percent = [s.get('post_percent', 0) for s in self.snapshots]

        ax2.plot(intervals, get_percent, 'g-', linewidth=2, marker='o', markersize=3, label='GET %', alpha=0.7)
        ax2.plot(intervals, post_percent, 'b-', linewidth=2, marker='s', markersize=3, label='POST %', alpha=0.7)
        ax2.axhline(y=92, color='green', linestyle='--', linewidth=1, alpha=0.5, label='Baseline GET (~92%)')
        ax2.axhline(y=98, color='red', linestyle='--', linewidth=2, label='Anomaly threshold (98%)')
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Percentage (%)', fontsize=12)
        ax2.set_title('HTTP Method Distribution Over Time', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Alert distribution pie chart
        ax3 = axes[1, 0]
        alert_counts = metrics.get('alert_counts', {})
        labels = []
        sizes = []
        colors_pie = []
        explode_vals = []

        for level, color, exp in [('NONE', '#90ee90', 0), ('LOW', '#ffeb3b', 0.05),
                                   ('MEDIUM', '#ff9800', 0.1), ('HIGH', '#f44336', 0.15)]:
            if alert_counts.get(level, 0) > 0:
                labels.append(level)
                sizes.append(alert_counts[level])
                colors_pie.append(color)
                explode_vals.append(exp)

        if sizes:
            wedges, texts, autotexts = ax3.pie(sizes, explode=explode_vals, labels=labels, colors=colors_pie,
                                                autopct='%1.1f%%', shadow=True, startangle=90)

            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(10)

        ax3.set_title('Alert Level Distribution', fontsize=14, fontweight='bold')

        # 4. Phase breakdown
        ax4 = axes[1, 1]

        # Phase durations
        baseline_duration = metrics.get('baseline_duration', 0)
        attack_duration = metrics.get('attack_duration', 0)

        phase_labels = ['Baseline\nPhase', 'Attack\nPhase']
        phase_durations = [baseline_duration, attack_duration]
        phase_colors = ['green', 'red']

        bars = ax4.barh(phase_labels, phase_durations, color=phase_colors, alpha=0.7, edgecolor='black', linewidth=2)

        ax4.set_xlabel('Duration (seconds)', fontsize=12)
        ax4.set_title('Experiment Phase Breakdown', fontsize=14, fontweight='bold')
        ax4.grid(True, alpha=0.3, axis='x')

        # Add value labels
        for i, (bar, duration) in enumerate(zip(bars, phase_durations)):
            width = bar.get_width()
            ax4.text(width + 5, bar.get_y() + bar.get_height()/2,
                    f'{duration}s\n({duration/metrics.get("total_duration", 1)*100:.1f}%)',
                    ha='left', va='center', fontsize=11, fontweight='bold')

        plt.tight_layout()

        # Save figure
        output_path = os.path.join(self.output_dir, '03_baseline_vs_attack.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[FIGURE 3: Baseline vs Attack] - Saved to {output_path}")

    def plot_link_utilization(self):
        """Generate link utilization analysis"""
        if not self.snapshots:
            print("No data to plot")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Link Utilization Analysis ({self.link_capacity_gbps}G Link)', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]
        total_packets = [s['total_packets'] for s in self.snapshots]
        baseline_packets = [s.get('baseline_packets', 0) for s in self.snapshots]
        attack_packets = [s.get('attack_packets', 0) for s in self.snapshots]

        # Calculate PPS and Gbps for each interval
        pps_total = []
        pps_baseline = []
        pps_attack = []
        gbps_total = []
        gbps_baseline = []
        gbps_attack = []
        utilization_total = []

        for i in range(len(self.snapshots)):
            if i == 0:
                pps_t = total_packets[i] / 5
                pps_b = baseline_packets[i] / 5
                pps_a = attack_packets[i] / 5
            else:
                pps_t = (total_packets[i] - total_packets[i-1]) / 5
                pps_b = (baseline_packets[i] - baseline_packets[i-1]) / 5
                pps_a = (attack_packets[i] - attack_packets[i-1]) / 5

            pps_total.append(pps_t)
            pps_baseline.append(pps_b)
            pps_attack.append(pps_a)

            gbps_t = self.pps_to_gbps(pps_t)
            gbps_b = self.pps_to_gbps(pps_b)
            gbps_a = self.pps_to_gbps(pps_a)

            gbps_total.append(gbps_t)
            gbps_baseline.append(gbps_b)
            gbps_attack.append(gbps_a)
            utilization_total.append(self.calculate_link_utilization(gbps_t))

        # 1. Throughput over time (Gbps)
        ax1 = axes[0, 0]
        ax1.fill_between(intervals, 0, gbps_baseline, alpha=0.5, color='green', label='Baseline')
        ax1.fill_between(intervals, gbps_baseline, [b + a for b, a in zip(gbps_baseline, gbps_attack)],
                        alpha=0.5, color='red', label='Attack')
        ax1.plot(intervals, gbps_total, 'k-', linewidth=2, label='Total', zorder=3)
        ax1.axhline(y=self.link_capacity_gbps, color='purple', linestyle='--', linewidth=2,
                   label=f'Link Capacity ({self.link_capacity_gbps}G)')
        ax1.set_xlabel('Time (seconds)', fontsize=12)
        ax1.set_ylabel('Throughput (Gbps)', fontsize=12)
        ax1.set_title('Network Throughput Over Time', fontsize=14, fontweight='bold')
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(0, max(max(gbps_total) * 1.2, self.link_capacity_gbps * 0.5))

        # 2. Link utilization percentage
        ax2 = axes[0, 1]
        colors = ['green' if u < 50 else 'orange' if u < 80 else 'red' for u in utilization_total]
        ax2.bar(intervals, utilization_total, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax2.axhline(y=50, color='orange', linestyle='--', linewidth=1, alpha=0.7, label='50% threshold')
        ax2.axhline(y=80, color='red', linestyle='--', linewidth=2, label='80% threshold')
        ax2.set_xlabel('Time (seconds)', fontsize=12)
        ax2.set_ylabel('Link Utilization (%)', fontsize=12)
        ax2.set_title('Link Utilization Over Time', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Throughput breakdown comparison
        ax3 = axes[1, 0]
        metrics = self.calculate_metrics()

        categories = ['Baseline\nPhase', 'Attack Traffic\nOnly', 'Total During\nAttack']
        gbps_values = [
            metrics.get('baseline_gbps', 0),
            metrics.get('attack_gbps', 0),
            metrics.get('total_gbps_during_attack', 0)
        ]
        utilization_values = [
            metrics.get('baseline_link_utilization', 0),
            metrics.get('attack_link_utilization', 0),
            metrics.get('total_link_utilization_during_attack', 0)
        ]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax3.bar(x - width/2, gbps_values, width, label='Gbps', color='steelblue', alpha=0.8)

        ax3_twin = ax3.twinx()
        bars2 = ax3_twin.bar(x + width/2, utilization_values, width, label='Utilization %', color='coral', alpha=0.8)

        ax3.set_xlabel('Traffic Phase', fontsize=12)
        ax3.set_ylabel('Throughput (Gbps)', fontsize=12, color='steelblue')
        ax3_twin.set_ylabel('Link Utilization (%)', fontsize=12, color='coral')
        ax3.set_title('Throughput Summary by Phase', fontsize=14, fontweight='bold')
        ax3.set_xticks(x)
        ax3.set_xticklabels(categories)
        ax3.tick_params(axis='y', labelcolor='steelblue')
        ax3_twin.tick_params(axis='y', labelcolor='coral')
        ax3_twin.set_ylim(0, 100)

        # Add value labels
        for bar in bars1:
            height = bar.get_height()
            ax3.annotate(f'{height:.1f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom', fontsize=9, fontweight='bold')

        for bar in bars2:
            height = bar.get_height()
            ax3_twin.annotate(f'{height:.1f}%',
                             xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3),
                             textcoords="offset points",
                             ha='center', va='bottom', fontsize=9, fontweight='bold')

        # Combine legends
        lines1, labels1 = ax3.get_legend_handles_labels()
        lines2, labels2 = ax3_twin.get_legend_handles_labels()
        ax3.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

        # 4. Summary box
        ax4 = axes[1, 1]
        ax4.axis('off')

        avg_utilization = np.mean(utilization_total)
        max_utilization = max(utilization_total)
        min_utilization = min(utilization_total)

        summary_text = f"""
LINK UTILIZATION SUMMARY

Configuration:
  • Link Capacity:      {self.link_capacity_gbps} Gbps
  • Avg Packet Size:    {self.avg_packet_size} bytes

Baseline Phase:
  • Throughput:         {metrics.get('baseline_gbps', 0):.2f} Gbps
  • Utilization:        {metrics.get('baseline_link_utilization', 0):.1f}%

During Attack:
  • Attack Only:        {metrics.get('attack_gbps', 0):.2f} Gbps ({metrics.get('attack_link_utilization', 0):.1f}%)
  • Total (Base+Atk):   {metrics.get('total_gbps_during_attack', 0):.2f} Gbps ({metrics.get('total_link_utilization_during_attack', 0):.1f}%)

Overall Statistics:
  • Average Utilization: {avg_utilization:.1f}%
  • Maximum Utilization: {max_utilization:.1f}%
  • Minimum Utilization: {min_utilization:.1f}%

Capacity Status:
  • Available Capacity:  {self.link_capacity_gbps - metrics.get('total_gbps_during_attack', 0):.1f} Gbps
  • Headroom:            {100 - metrics.get('total_link_utilization_during_attack', 0):.1f}%
        """

        ax4.text(0.05, 0.95, summary_text, transform=ax4.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightcyan', alpha=0.8))

        plt.tight_layout()

        # Save figure
        output_path = os.path.join(self.output_dir, '04_link_utilization.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[FIGURE 4: Link Utilization] - Saved to {output_path}")


def main():
    # File paths
    log_file = r'C:\Users\claud\Comi_archi\MD\codigo\dpdk_100g\results\results_http_flood_500s_2.log'
    output_dir = os.path.join(os.path.dirname(__file__))

    print("\n" + "="*80)
    print("HTTP FLOOD ATTACK ANALYZER v2 - ADVANCED ANALYSIS")
    print("="*80)
    print(f"\nLog file: {log_file}")
    print(f"Output directory: {output_dir}")

    # Create analyzer
    analyzer = HTTPFloodAnalyzer(log_file, output_dir)

    # Calculate and print metrics
    metrics = analyzer.print_metrics()

    # Generate figures
    print("\nGenerating analysis figures...\n")
    analyzer.plot_traffic_overview()
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
    print("  - 04_link_utilization.png\n")


if __name__ == "__main__":
    main()
