#!/usr/bin/env python3
"""
DDoS Attack Visual Analyzer
----------------------------
Analyzes detection.log and generates attack metrics visualizations.

Usage:
    python3 analyze_attack.py [detection_log.txt]
"""

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import Rectangle
import seaborn as sns
import numpy as np
from pathlib import Path
import sys

# Visual configuration
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (18, 10)
plt.rcParams['font.size'] = 11
plt.rcParams['font.weight'] = 'normal'

class AttackAnalyzer:
    def __init__(self, log_file):
        self.log_file = Path(log_file)
        self.df = None
        self.df_filtered = None
        self.attack_type = "Unknown"
        self.attack_severity = "LOW"
        self.attack_color = "#95a5a6"

    def load_data(self):
        """Load and prepare log data"""
        print(f"[*] Loading data from: {self.log_file}")

        try:
            self.df = pd.read_csv(self.log_file)

            # Validate required columns
            required_cols = ['timestamp', 'pps', 'gbps', 'tcp', 'udp', 'icmp',
                           'syn', 'ack', 'rst', 'fin', 'frag']
            missing = set(required_cols) - set(self.df.columns)
            if missing:
                raise ValueError(f"Missing columns: {missing}")

            # Convert timestamp to relative time in seconds
            self.df['time_sec'] = (self.df['timestamp'] - self.df['timestamp'].min())

            # Filter out rows with zero traffic for cleaner visualization
            self.df_filtered = self.df[self.df['pps'] > 0].copy()

            print(f"[✓] Data loaded: {len(self.df)} samples ({len(self.df_filtered)} with traffic)")
            return True

        except FileNotFoundError:
            print(f"[✗] Error: File not found: {self.log_file}")
            return False
        except Exception as e:
            print(f"[✗] Error loading data: {e}")
            return False

    def detect_attack_type(self):
        """Detect attack type based on traffic characteristics"""
        if self.df_filtered is None or len(self.df_filtered) == 0:
            self.attack_type = "No Traffic"
            self.attack_severity = "NONE"
            self.attack_color = "#95a5a6"
            return self.attack_type

        # Calculate average ratios (only on traffic periods)
        total_pkts = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()
        if total_pkts == 0:
            self.attack_type = "No Traffic"
            self.attack_severity = "NONE"
            self.attack_color = "#95a5a6"
            return self.attack_type

        tcp_ratio = self.df_filtered['tcp'].sum() / total_pkts
        udp_ratio = self.df_filtered['udp'].sum() / total_pkts
        icmp_ratio = self.df_filtered['icmp'].sum() / total_pkts

        # TCP flag ratios
        tcp_total = self.df_filtered['tcp'].sum()
        if tcp_total > 0:
            syn_ratio = self.df_filtered['syn'].sum() / tcp_total
            ack_ratio = self.df_filtered['ack'].sum() / tcp_total
            rst_ratio = self.df_filtered['rst'].sum() / tcp_total
        else:
            syn_ratio = ack_ratio = rst_ratio = 0

        # Get average PPS during attack
        avg_pps = self.df_filtered['pps'].mean()

        # Attack detection logic with severity
        if tcp_ratio > 0.6 and syn_ratio > 0.7:
            self.attack_type = "SYN FLOOD"
            self.attack_severity = "CRITICAL" if avg_pps > 100000 else "HIGH"
            self.attack_color = "#e74c3c"
        elif udp_ratio > 0.6:
            if avg_pps > 100000:
                self.attack_type = "UDP FLOOD (HIGH RATE)"
                self.attack_severity = "CRITICAL"
            else:
                self.attack_type = "UDP FLOOD"
                self.attack_severity = "HIGH"
            self.attack_color = "#3498db"
        elif icmp_ratio > 0.5:
            self.attack_type = "ICMP FLOOD"
            self.attack_severity = "HIGH"
            self.attack_color = "#2ecc71"
        elif tcp_ratio > 0.6 and rst_ratio > 0.3:
            self.attack_type = "TCP RST ATTACK"
            self.attack_severity = "MEDIUM"
            self.attack_color = "#f39c12"
        elif tcp_total > 0 and syn_ratio < 0.3 and ack_ratio > 0.5:
            self.attack_type = "HTTP FLOOD"
            self.attack_severity = "HIGH"
            self.attack_color = "#9b59b6"
        elif tcp_ratio > 0.2 or udp_ratio > 0.2 or icmp_ratio > 0.2:
            self.attack_type = "MIXED ATTACK"
            self.attack_severity = "MEDIUM"
            self.attack_color = "#e67e22"
        else:
            self.attack_type = "BENIGN TRAFFIC"
            self.attack_severity = "LOW"
            self.attack_color = "#27ae60"

        print(f"[✓] Attack detected: {self.attack_type} (Severity: {self.attack_severity})")
        return self.attack_type

    def print_summary_table(self):
        """Print summary table with key statistics"""
        print("\n" + "="*80)
        print(f"{'DDOS ATTACK ANALYSIS SUMMARY':^80}")
        print("="*80)

        if self.df_filtered is None or len(self.df_filtered) == 0:
            print("No traffic data to analyze.")
            return

        # General statistics
        duration = self.df['time_sec'].max()
        active_duration = len(self.df_filtered)
        total_packets = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()

        print(f"\n{'Metric':<35} {'Value':>20} {'Unit':<15}")
        print("-" * 80)
        print(f"{'Attack Type':<35} {self.attack_type:>20}")
        print(f"{'Severity Level':<35} {self.attack_severity:>20}")
        print(f"{'Total Duration':<35} {duration:>20.1f} {'seconds':<15}")
        print(f"{'Active Attack Duration':<35} {active_duration:>20} {'seconds':<15}")
        print(f"{'Total Packets':<35} {total_packets:>20,.0f} {'packets':<15}")

        # Throughput metrics
        print(f"\n{'THROUGHPUT METRICS':^80}")
        print("-" * 80)
        avg_pps = self.df_filtered['pps'].mean()
        max_pps = self.df_filtered['pps'].max()
        avg_gbps = self.df_filtered['gbps'].mean()
        max_gbps = self.df_filtered['gbps'].max()

        print(f"{'Average PPS':<35} {avg_pps:>20,.0f} {'pps':<15}")
        print(f"{'Peak PPS':<35} {max_pps:>20,.0f} {'pps':<15}")
        print(f"{'Average Throughput':<35} {avg_gbps:>20.2f} {'Gbps':<15}")
        print(f"{'Peak Throughput':<35} {max_gbps:>20.2f} {'Gbps':<15}")

        # Protocol distribution
        print(f"\n{'PROTOCOL DISTRIBUTION':^80}")
        print("-" * 80)
        tcp_total = self.df_filtered['tcp'].sum()
        udp_total = self.df_filtered['udp'].sum()
        icmp_total = self.df_filtered['icmp'].sum()

        print(f"{'TCP Packets':<35} {tcp_total:>20,.0f} {f'({tcp_total/total_packets*100:.1f}%)':<15}")
        print(f"{'UDP Packets':<35} {udp_total:>20,.0f} {f'({udp_total/total_packets*100:.1f}%)':<15}")
        print(f"{'ICMP Packets':<35} {icmp_total:>20,.0f} {f'({icmp_total/total_packets*100:.1f}%)':<15}")

        # TCP flags (if TCP traffic exists)
        if tcp_total > 0:
            print(f"\n{'TCP FLAGS ANALYSIS':^80}")
            print("-" * 80)
            syn_total = self.df_filtered['syn'].sum()
            ack_total = self.df_filtered['ack'].sum()
            rst_total = self.df_filtered['rst'].sum()
            fin_total = self.df_filtered['fin'].sum()

            print(f"{'SYN Packets':<35} {syn_total:>20,.0f} {f'({syn_total/tcp_total*100:.1f}%)':<15}")
            print(f"{'ACK Packets':<35} {ack_total:>20,.0f} {f'({ack_total/tcp_total*100:.1f}%)':<15}")
            print(f"{'RST Packets':<35} {rst_total:>20,.0f} {f'({rst_total/tcp_total*100:.1f}%)':<15}")
            print(f"{'FIN Packets':<35} {fin_total:>20,.0f} {f'({fin_total/tcp_total*100:.1f}%)':<15}")

            # SYN/ACK ratio (important for SYN flood detection)
            if ack_total > 0:
                syn_ack_ratio = syn_total / ack_total
                print(f"{'SYN/ACK Ratio':<35} {syn_ack_ratio:>20.2f} {'(Normal: ~1.0)':<15}")

        print("\n" + "="*80 + "\n")

    def create_main_analysis(self, output_file="attack_main_analysis.png"):
        """Generate main analysis visualization with 4 key plots"""
        if self.df_filtered is None or len(self.df_filtered) == 0:
            print("[✗] No traffic data to visualize")
            return

        fig = plt.figure(figsize=(18, 10))
        fig.patch.set_facecolor('white')

        # Main title
        fig.suptitle('DDoS Attack Detection - Main Analysis',
                     fontsize=20, fontweight='bold', y=0.97)

        # ===== PLOT 1: Attack Identification Panel =====
        ax1 = plt.subplot(2, 2, 1)
        ax1.axis('off')

        # Get metrics
        total_packets = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()
        avg_pps = self.df_filtered['pps'].mean()
        max_pps = self.df_filtered['pps'].max()
        avg_gbps = self.df_filtered['gbps'].mean()

        # Attack type box (large and prominent)
        attack_box = Rectangle((0.1, 0.65), 0.8, 0.25,
                               facecolor=self.attack_color,
                               edgecolor='black', linewidth=3)
        ax1.add_patch(attack_box)
        ax1.text(0.5, 0.775, self.attack_type,
                ha='center', va='center', fontsize=24,
                fontweight='bold', color='white',
                transform=ax1.transAxes)

        # Severity indicator
        severity_colors = {
            'CRITICAL': '#c0392b',
            'HIGH': '#e74c3c',
            'MEDIUM': '#f39c12',
            'LOW': '#27ae60',
            'NONE': '#95a5a6'
        }
        sev_box = Rectangle((0.1, 0.50), 0.8, 0.10,
                           facecolor=severity_colors.get(self.attack_severity, '#95a5a6'),
                           edgecolor='black', linewidth=2)
        ax1.add_patch(sev_box)
        ax1.text(0.5, 0.55, f'SEVERITY: {self.attack_severity}',
                ha='center', va='center', fontsize=16,
                fontweight='bold', color='white',
                transform=ax1.transAxes)

        # Key metrics
        metrics_text = f"""
        Average PPS: {avg_pps:,.0f}
        Peak PPS: {max_pps:,.0f}
        Average Throughput: {avg_gbps:.2f} Gbps
        Total Packets: {total_packets:,.0f}
        Duration: {len(self.df_filtered)}s
        """
        ax1.text(0.5, 0.25, metrics_text,
                ha='center', va='center', fontsize=12,
                family='monospace',
                bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8),
                transform=ax1.transAxes)

        ax1.set_title('Attack Identification', fontsize=14, fontweight='bold', pad=10)

        # ===== PLOT 2: Throughput Over Time =====
        ax2 = plt.subplot(2, 2, 2)
        ax2_twin = ax2.twinx()

        # Plot PPS
        line1 = ax2.plot(self.df['time_sec'], self.df['pps']/1000,
                        'b-', linewidth=2.5, label='PPS', alpha=0.8)
        ax2.fill_between(self.df['time_sec'], 0, self.df['pps']/1000,
                        color='b', alpha=0.1)
        ax2.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax2.set_ylabel('PPS (thousands)', color='b', fontsize=12, fontweight='bold')
        ax2.tick_params(axis='y', labelcolor='b')
        ax2.grid(True, alpha=0.3, linestyle='--')

        # Plot Gbps
        line2 = ax2_twin.plot(self.df['time_sec'], self.df['gbps'],
                             'r-', linewidth=2.5, label='Gbps', alpha=0.8)
        ax2_twin.set_ylabel('Throughput (Gbps)', color='r', fontsize=12, fontweight='bold')
        ax2_twin.tick_params(axis='y', labelcolor='r')

        # Combined legend
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax2.legend(lines, labels, loc='upper left', fontsize=10, framealpha=0.9)
        ax2.set_title('Traffic Throughput Over Time', fontsize=14, fontweight='bold', pad=10)

        # ===== PLOT 3: Protocol Distribution Over Time =====
        ax3 = plt.subplot(2, 2, 3)

        # Stacked area chart
        ax3.fill_between(self.df_filtered['time_sec'], 0,
                        self.df_filtered['tcp'],
                        label='TCP', color='#e74c3c', alpha=0.7)
        ax3.fill_between(self.df_filtered['time_sec'],
                        self.df_filtered['tcp'],
                        self.df_filtered['tcp'] + self.df_filtered['udp'],
                        label='UDP', color='#3498db', alpha=0.7)
        ax3.fill_between(self.df_filtered['time_sec'],
                        self.df_filtered['tcp'] + self.df_filtered['udp'],
                        self.df_filtered['tcp'] + self.df_filtered['udp'] + self.df_filtered['icmp'],
                        label='ICMP', color='#2ecc71', alpha=0.7)

        ax3.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
        ax3.set_ylabel('Packets per Second', fontsize=12, fontweight='bold')
        ax3.set_title('Protocol Distribution Over Time', fontsize=14, fontweight='bold', pad=10)
        ax3.legend(loc='upper left', fontsize=10, framealpha=0.9)
        ax3.grid(True, alpha=0.3, linestyle='--')

        # ===== PLOT 4: SYN/ACK Ratio Analysis =====
        ax4 = plt.subplot(2, 2, 4)

        tcp_total = self.df_filtered['tcp'].sum()
        if tcp_total > 0:
            # Calculate SYN/ACK ratio with protection against division by zero
            syn_ack_ratio = np.where(self.df_filtered['ack'] > 10,
                                    self.df_filtered['syn'] / (self.df_filtered['ack'] + 1),
                                    0)

            # Plot ratio
            ax4.plot(self.df_filtered['time_sec'], syn_ack_ratio,
                    linewidth=2.5, color='#e74c3c', label='SYN/ACK Ratio', alpha=0.9)
            ax4.fill_between(self.df_filtered['time_sec'], syn_ack_ratio,
                            color='#e74c3c', alpha=0.2)

            # Reference lines
            ax4.axhline(y=1, color='#27ae60', linestyle='--',
                       label='Normal (1:1)', linewidth=2.5, alpha=0.8)
            ax4.axhline(y=3, color='#f39c12', linestyle='--',
                       label='Suspicious (>3:1)', linewidth=2.5, alpha=0.8)
            ax4.axhline(y=5, color='#c0392b', linestyle='--',
                       label='Attack (>5:1)', linewidth=2.5, alpha=0.8)

            # Highlight dangerous zones
            ax4.axhspan(3, 10, facecolor='#f39c12', alpha=0.1)
            ax4.axhspan(5, 10, facecolor='#e74c3c', alpha=0.1)

            ax4.set_xlabel('Time (seconds)', fontsize=12, fontweight='bold')
            ax4.set_ylabel('SYN/ACK Ratio', fontsize=12, fontweight='bold')
            ax4.set_title('SYN/ACK Ratio (SYN Flood Indicator)',
                         fontsize=14, fontweight='bold', pad=10)
            ax4.legend(loc='upper left', fontsize=9, framealpha=0.9)
            ax4.grid(True, alpha=0.3, linestyle='--')
            ax4.set_ylim(bottom=0, top=min(10, syn_ack_ratio.max() * 1.1))
        else:
            ax4.text(0.5, 0.5, 'No TCP Traffic Detected',
                    ha='center', va='center', fontsize=16,
                    transform=ax4.transAxes,
                    bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8))
            ax4.set_title('SYN/ACK Ratio Analysis', fontsize=14, fontweight='bold', pad=10)

        plt.tight_layout(rect=[0, 0, 1, 0.96])

        # Save figure
        output_path = Path(output_file)
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"[✓] Main analysis saved: {output_path}")

        plt.show()

    def create_detailed_metrics(self, output_file="attack_detailed_metrics.png"):
        """Generate detailed metrics visualization with 4 additional plots"""
        if self.df_filtered is None or len(self.df_filtered) == 0:
            print("[✗] No traffic data to visualize")
            return

        fig = plt.figure(figsize=(18, 10))
        fig.patch.set_facecolor('white')

        fig.suptitle('DDoS Attack Detection - Detailed Metrics',
                     fontsize=20, fontweight='bold', y=0.97)

        # ===== PLOT 1: Protocol Distribution (Pie Chart) =====
        ax1 = plt.subplot(2, 2, 1)

        tcp_total = self.df_filtered['tcp'].sum()
        udp_total = self.df_filtered['udp'].sum()
        icmp_total = self.df_filtered['icmp'].sum()
        total = tcp_total + udp_total + icmp_total

        protocol_counts = [tcp_total, udp_total, icmp_total]
        colors = ['#e74c3c', '#3498db', '#2ecc71']
        explode = (0.05, 0.05, 0.05)

        wedges, texts, autotexts = ax1.pie(protocol_counts,
                                           labels=['TCP', 'UDP', 'ICMP'],
                                           autopct=lambda pct: f'{pct:.1f}%\n({int(pct*total/100):,})',
                                           colors=colors,
                                           startangle=90,
                                           explode=explode,
                                           shadow=True,
                                           textprops={'fontsize': 11, 'weight': 'bold'})

        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')

        ax1.set_title('Protocol Distribution', fontsize=14, fontweight='bold', pad=10)

        # ===== PLOT 2: TCP Flags Bar Chart =====
        ax2 = plt.subplot(2, 2, 2)

        if tcp_total > 0:
            flag_data = {
                'SYN': self.df_filtered['syn'].sum(),
                'ACK': self.df_filtered['ack'].sum(),
                'RST': self.df_filtered['rst'].sum(),
                'FIN': self.df_filtered['fin'].sum()
            }

            bars = ax2.bar(flag_data.keys(), flag_data.values(),
                          color=['#e74c3c', '#3498db', '#f39c12', '#9b59b6'],
                          edgecolor='black', linewidth=1.5, alpha=0.8)

            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height):,}\n({height/tcp_total*100:.1f}%)',
                        ha='center', va='bottom', fontsize=10, fontweight='bold')

            ax2.set_ylabel('Packet Count', fontsize=12, fontweight='bold')
            ax2.set_title('TCP Flags Distribution', fontsize=14, fontweight='bold', pad=10)
            ax2.grid(axis='y', alpha=0.3, linestyle='--')
            ax2.ticklabel_format(style='plain', axis='y')
        else:
            ax2.text(0.5, 0.5, 'No TCP Traffic',
                    ha='center', va='center', fontsize=16,
                    transform=ax2.transAxes,
                    bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8))
            ax2.set_title('TCP Flags Distribution', fontsize=14, fontweight='bold', pad=10)

        # ===== PLOT 3: Traffic Intensity Heatmap =====
        ax3 = plt.subplot(2, 2, 3)

        # Create time bins for heatmap
        n_bins = min(30, len(self.df_filtered))
        if n_bins > 1:
            df_temp = self.df_filtered.copy()
            time_bins = np.linspace(df_temp['time_sec'].min(),
                                   df_temp['time_sec'].max(), n_bins)
            df_temp['time_bin'] = pd.cut(df_temp['time_sec'], bins=time_bins)

            heatmap_data = df_temp.groupby('time_bin')[['tcp', 'udp', 'icmp']].sum().T

            sns.heatmap(heatmap_data, cmap='YlOrRd', ax=ax3,
                       cbar_kws={'label': 'Packets per Interval'},
                       linewidths=0.5, linecolor='white',
                       annot=False, fmt=',.0f')

            ax3.set_xlabel('Time Interval', fontsize=12, fontweight='bold')
            ax3.set_ylabel('Protocol', fontsize=12, fontweight='bold')
            ax3.set_xticklabels([])
            ax3.set_yticklabels(['TCP', 'UDP', 'ICMP'], rotation=0)

        ax3.set_title('Traffic Intensity Heatmap', fontsize=14, fontweight='bold', pad=10)

        # ===== PLOT 4: Summary Metrics Table =====
        ax4 = plt.subplot(2, 2, 4)
        ax4.axis('off')

        # Calculate all metrics
        duration = self.df['time_sec'].max()
        active_duration = len(self.df_filtered)
        total_packets = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()
        avg_pps = self.df_filtered['pps'].mean()
        max_pps = self.df_filtered['pps'].max()
        avg_gbps = self.df_filtered['gbps'].mean()
        max_gbps = self.df_filtered['gbps'].max()

        # Create summary table
        summary_data = [
            ['Attack Type', self.attack_type],
            ['Severity', self.attack_severity],
            ['Total Duration', f'{duration:.1f} s'],
            ['Active Duration', f'{active_duration} s'],
            ['Total Packets', f'{total_packets:,.0f}'],
            ['Avg PPS', f'{avg_pps:,.0f}'],
            ['Peak PPS', f'{max_pps:,.0f}'],
            ['Avg Throughput', f'{avg_gbps:.2f} Gbps'],
            ['Peak Throughput', f'{max_gbps:.2f} Gbps']
        ]

        # TCP-specific metrics
        if tcp_total > 0:
            syn_total = self.df_filtered['syn'].sum()
            ack_total = self.df_filtered['ack'].sum()
            if ack_total > 0:
                syn_ack_ratio = syn_total / ack_total
                summary_data.append(['SYN/ACK Ratio', f'{syn_ack_ratio:.2f}'])

        # Protocol percentages
        summary_data.extend([
            ['TCP %', f'{tcp_total/total_packets*100:.1f}%'],
            ['UDP %', f'{udp_total/total_packets*100:.1f}%'],
            ['ICMP %', f'{icmp_total/total_packets*100:.1f}%']
        ])

        table = ax4.table(cellText=summary_data,
                         colLabels=['Metric', 'Value'],
                         cellLoc='left',
                         loc='center',
                         colWidths=[0.55, 0.45])

        table.auto_set_font_size(False)
        table.set_fontsize(11)
        table.scale(1, 2.5)

        # Style table
        for i in range(len(summary_data) + 1):
            if i == 0:
                # Header
                table[(i, 0)].set_facecolor('#34495e')
                table[(i, 1)].set_facecolor('#34495e')
                table[(i, 0)].set_text_props(weight='bold', color='white', fontsize=12)
                table[(i, 1)].set_text_props(weight='bold', color='white', fontsize=12)
            else:
                # Alternate row colors
                color = '#ecf0f1' if i % 2 == 0 else 'white'
                table[(i, 0)].set_facecolor(color)
                table[(i, 1)].set_facecolor(color)
                table[(i, 0)].set_text_props(weight='bold')

                # Highlight attack type and severity
                if i == 1 or i == 2:
                    table[(i, 1)].set_facecolor(self.attack_color)
                    table[(i, 1)].set_text_props(weight='bold', color='white')

        ax4.set_title('Summary Metrics', fontsize=14, fontweight='bold', pad=20)

        plt.tight_layout(rect=[0, 0, 1, 0.96])

        # Save figure
        output_path = Path(output_file)
        plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
        print(f"[✓] Detailed metrics saved: {output_path}")

        plt.show()

    def run_analysis(self, show_plot=True):
        """Execute complete analysis"""
        if not self.load_data():
            return False

        self.detect_attack_type()
        self.print_summary_table()

        if show_plot:
            self.create_main_analysis()
            self.create_detailed_metrics()

        return True


def main():
    print("="*80)
    print(f"{'DDoS Attack Visual Analyzer':^80}")
    print("="*80)

    # Determine input file
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = "detection_log.txt"

    # Verify file exists
    if not Path(log_file).exists():
        print(f"\n[✗] Error: File not found '{log_file}'")
        print("\nUsage:")
        print(f"    python3 {sys.argv[0]} [detection_log.txt]")
        print("\nMake sure to:")
        print("  1. Copy the content from /local/logs/detection.log")
        print("  2. Paste it into detection_log.txt (in this directory)")
        print("  3. Run this script")
        sys.exit(1)

    # Run analysis
    analyzer = AttackAnalyzer(log_file)
    success = analyzer.run_analysis(show_plot=True)

    if success:
        print("\n[✓] Analysis completed successfully!")
        print(f"[✓] Main analysis saved: attack_main_analysis.png")
        print(f"[✓] Detailed metrics saved: attack_detailed_metrics.png")
    else:
        print("\n[✗] Analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
