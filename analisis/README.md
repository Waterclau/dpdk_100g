# DDoS Attack Analysis Tool

Professional Python-based tool for analyzing and visualizing DDoS attack detection results. Generates publication-quality visualizations with automatic attack classification.

## Files

- `analyze_attack.py` - Main analysis script (all-in-one)
- `detection_log.txt` - Input file template (paste detector logs here)
- `CODE_ANALYSIS.md` - Detailed code explanation

## Key Features

- **Automatic Attack Detection** - Intelligently identifies SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, DNS Amplification, and mixed attacks
- **Severity Classification** - Four-level severity (CRITICAL, HIGH, MEDIUM, LOW) based on traffic intensity
- **Dual High-Resolution Visualization** - Two separate 300-DPI images with 4 plots each for comprehensive analysis
- **Statistical Analysis** - Complete metrics including PPS, Gbps, protocol distribution, TCP flag analysis, and SYN/ACK ratios
- **Professional English Interface** - All metrics, plots, and outputs in English for publication and research use
- **Zero Configuration** - Works out-of-the-box with detector logs, no training required

## Usage

### 1. Copy logs from CloudLab

From the **Detector** machine, copy the log content:

```bash
# View log content
cat /local/logs/detection.log

# Or copy to your local machine
scp user@detector.cloudlab.us:/local/logs/detection.log ./detection_log.txt
```

### 2. Paste the log

Open `detection_log.txt` and paste the complete content from `detection.log`.

Format must be CSV with these columns:
```
timestamp,pps,gbps,tcp,udp,icmp,syn,ack,rst,fin,frag
1731234567,45000,2.5,40000,5000,0,35000,8000,200,100,0
...
```

### 3. Install dependencies

```bash
pip3 install pandas matplotlib seaborn numpy
```

### 4. Run analysis

```bash
cd analisis
python3 analyze_attack.py
```

Or specify a different file:

```bash
python3 analyze_attack.py my_detection_log.txt
```

## Outputs

### 1. Terminal Output (Statistical Summary)

Displays a comprehensive formatted table with:
- **Attack Classification**: Detected type and severity level
- **Duration Metrics**: Total duration and active traffic period
- **Throughput Statistics**: Average and peak PPS (packets per second), Gbps (gigabits per second)
- **Protocol Distribution**: TCP/UDP/ICMP packet counts and percentages
- **TCP Flags Analysis**: SYN, ACK, RST, FIN counts and their significance
- **Attack Indicators**: SYN/ACK ratio (critical for SYN flood detection, normal ~1.0, attack >5.0)

**Example**: See sample output in the "Example Output" section below.

### Visualization 1: Main Analysis (attack_main_analysis.png)

4 key visualizations:

1. **Attack Identification Panel** - Large colored display showing:
   - Attack type (SYN FLOOD, UDP FLOOD, etc.)
   - Severity level (CRITICAL, HIGH, MEDIUM, LOW)
   - Key metrics summary

2. **Traffic Throughput Over Time** - Dual-axis plot:
   - PPS (blue line with area fill)
   - Gbps (red line)

3. **Protocol Distribution Over Time** - Stacked area chart:
   - TCP (red)
   - UDP (blue)
   - ICMP (green)

4. **SYN/ACK Ratio Analysis** - SYN flood indicator:
   - Ratio over time
   - Reference lines (Normal 1:1, Suspicious >3:1, Attack >5:1)
   - Color-coded danger zones

### Visualization 2: Detailed Metrics (attack_detailed_metrics.png)

4 additional visualizations:

1. **Protocol Distribution** - Pie chart with percentages and packet counts
2. **TCP Flags Distribution** - Bar chart (SYN/ACK/RST/FIN) with labels
3. **Traffic Intensity Heatmap** - Time-based protocol intensity
4. **Summary Metrics Table** - Complete statistics with color-coded attack info

## Detected Attack Types

The script automatically identifies:

- **SYN FLOOD** - High ratio of SYN packets without ACK (Severity: HIGH/CRITICAL)
- **UDP FLOOD** - UDP traffic predominance (Severity: HIGH/CRITICAL)
- **ICMP FLOOD** - High volume of ICMP packets (Severity: HIGH)
- **HTTP FLOOD** - TCP traffic with low SYN ratio (Severity: HIGH)
- **TCP RST ATTACK** - High number of RST packets (Severity: MEDIUM)
- **MIXED ATTACK** - Combination of patterns (Severity: MEDIUM)
- **BENIGN TRAFFIC** - Normal traffic patterns (Severity: LOW)

## Example Output

```
================================================================================
                      DDOS ATTACK ANALYSIS SUMMARY
================================================================================

Metric                              Value                Unit
--------------------------------------------------------------------------------
Attack Type                          SYN FLOOD
Severity Level                            HIGH
Total Duration                           142.0 seconds
Active Attack Duration                     117 seconds
Total Packets                       61,836,912 packets

                              THROUGHPUT METRICS
--------------------------------------------------------------------------------
Average PPS                            528,358 pps
Peak PPS                               574,488 pps
Average Throughput                        0.62 Gbps
Peak Throughput                           0.67 Gbps

                            PROTOCOL DISTRIBUTION
--------------------------------------------------------------------------------
TCP Packets                         56,134,866 (90.8%)
UDP Packets                          4,771,772 (7.7%)
ICMP Packets                           930,274 (1.5%)

                            TCP FLAGS ANALYSIS
--------------------------------------------------------------------------------
SYN Packets                         12,163,490 (21.7%)
ACK Packets                         49,596,094 (88.4%)
RST Packets                                  0 (0.0%)
FIN Packets                         11,237,972 (20.0%)
SYN/ACK Ratio                             0.25 (Normal: ~1.0)
```

## Troubleshooting

### Error: File not found

```bash
# Verify file exists
ls -l detection_log.txt

# Verify it has content
wc -l detection_log.txt
```

### Error: Incorrect columns

Make sure the file has the correct header:
```
timestamp,pps,gbps,tcp,udp,icmp,syn,ack,rst,fin,frag
```

### Error: No data to visualize

The file must have at least 2 lines (header + data):
```bash
# Check content
head detection_log.txt
```

### Plots not showing

If you're on a server without GUI:
```python
# In analyze_attack.py, comment out plt.show() calls
# plt.show()  # Comment this line (appears twice)
```

Plots will still be saved as PNG files.

### Module import errors

```bash
# Install all dependencies
pip3 install pandas matplotlib seaborn numpy

# Or with specific versions
pip3 install pandas==1.5.3 matplotlib==3.7.1 seaborn==0.12.2 numpy==1.24.3
```

## Key Features

- **Automatic Detection**: Identifies attack type and severity automatically
- **Dual-Axis Plots**: Compare PPS and Gbps simultaneously
- **SYN Flood Detection**: Dedicated SYN/ACK ratio analysis with visual indicators
- **Professional Output**: High-resolution (300 DPI) publication-ready figures
- **Color-Coded Severity**: Visual indication of attack severity levels
- **Comprehensive Metrics**: Complete statistical analysis in tables
- **Filtered Analysis**: Automatically filters out zero-traffic periods for cleaner visuals

## Notes

- Analysis is more accurate with logs of at least 30 seconds
- Plots are automatically generated in high resolution (300 DPI)
- Script automatically detects attack type and severity
- Compatible with mixed experiment logs (benign + attack traffic)
- Creates 2 separate images for better readability (4 plots each)
