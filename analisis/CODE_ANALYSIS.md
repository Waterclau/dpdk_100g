# Analysis Tool - Code Analysis

## Important Code Explanation

This document explains the key code sections in the Analysis Tool (`analyze_attack.py`).

## File: `analyze_attack.py`

### Overview

The analysis tool is a single Python script that:
1. Loads detection logs (CSV format)
2. Automatically detects attack type and severity
3. Generates statistical summaries
4. Creates professional visualizations

---

## Core Class: AttackAnalyzer

### 1. Initialization and Data Loading

#### Method: `__init__()`

```python
def __init__(self, log_file):
    self.log_file = Path(log_file)
    self.df = None                    # Full dataframe
    self.df_filtered = None           # Traffic-only dataframe
    self.attack_type = "Unknown"
    self.attack_severity = "LOW"
    self.attack_color = "#95a5a6"     # Color for visualizations
```

**What it does**:
- Initializes file path and data structures
- Sets up default attack classification
- Prepares color coding for severity levels

#### Method: `load_data()`

```python
def load_data(self):
    # Load CSV
    self.df = pd.read_csv(self.log_file)

    # Validate columns
    required_cols = ['timestamp', 'pps', 'gbps', 'tcp', 'udp', 'icmp',
                   'syn', 'ack', 'rst', 'fin', 'frag']
    missing = set(required_cols) - set(self.df.columns)
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    # Convert to relative time
    self.df['time_sec'] = (self.df['timestamp'] - self.df['timestamp'].min())

    # Filter out zero-traffic periods
    self.df_filtered = self.df[self.df['pps'] > 0].copy()
```

**What it does**:
1. Loads CSV with pandas
2. Validates all required columns exist
3. Converts absolute timestamps to relative seconds (starting at 0)
4. Creates filtered dataframe excluding periods with zero traffic

**Why filtering matters**:
- Detector logs have many zero-traffic samples (no packets received)
- Filtering gives cleaner visualizations and accurate statistics
- Preserves full dataframe for timeline context

---

### 2. Attack Detection Logic

#### Method: `detect_attack_type()`

```python
def detect_attack_type(self):
    # Calculate protocol ratios (only on active traffic)
    total_pkts = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()

    tcp_ratio = self.df_filtered['tcp'].sum() / total_pkts
    udp_ratio = self.df_filtered['udp'].sum() / total_pkts
    icmp_ratio = self.df_filtered['icmp'].sum() / total_pkts

    # TCP flag ratios
    tcp_total = self.df_filtered['tcp'].sum()
    if tcp_total > 0:
        syn_ratio = self.df_filtered['syn'].sum() / tcp_total
        ack_ratio = self.df_filtered['ack'].sum() / tcp_total
        rst_ratio = self.df_filtered['rst'].sum() / tcp_total

    # Get average PPS during attack
    avg_pps = self.df_filtered['pps'].mean()

    # Detection logic
    if tcp_ratio > 0.6 and syn_ratio > 0.7:
        self.attack_type = "SYN FLOOD"
        self.attack_severity = "CRITICAL" if avg_pps > 100000 else "HIGH"
        self.attack_color = "#e74c3c"  # Red
```

**Detection Heuristics**:

| Attack Type | Detection Criteria | Severity |
|-------------|-------------------|----------|
| **SYN FLOOD** | TCP > 60% AND SYN > 70% of TCP | HIGH/CRITICAL |
| **UDP FLOOD** | UDP > 60% | HIGH/CRITICAL |
| **ICMP FLOOD** | ICMP > 50% | HIGH |
| **HTTP FLOOD** | TCP > 60% AND SYN < 30% AND ACK > 50% | HIGH |
| **TCP RST** | TCP > 60% AND RST > 30% | MEDIUM |
| **MIXED** | No single protocol dominates | MEDIUM |
| **BENIGN** | None of above | LOW |

**Why these heuristics**:
- **SYN Flood**: High SYN ratio indicates connection attempts without completion
- **UDP Flood**: UDP doesn't need connection setup, pure volume
- **HTTP Flood**: Application-layer attacks have normal TCP handshakes (low SYN ratio)
- **Severity**: Based on PPS rate (>100K = CRITICAL)

---

### 3. Statistical Summary

#### Method: `print_summary_table()`

```python
def print_summary_table(self):
    # Calculate metrics
    duration = self.df['time_sec'].max()
    active_duration = len(self.df_filtered)
    total_packets = self.df_filtered[['tcp', 'udp', 'icmp']].sum().sum()

    avg_pps = self.df_filtered['pps'].mean()
    max_pps = self.df_filtered['pps'].max()
    avg_gbps = self.df_filtered['gbps'].mean()
    max_gbps = self.df_filtered['gbps'].max()

    # Print formatted table
    print(f"{'Metric':<35} {'Value':>20} {'Unit':<15}")
    print("-" * 80)
    print(f"{'Attack Type':<35} {self.attack_type:>20}")
    print(f"{'Severity Level':<35} {self.attack_severity:>20}")
    print(f"{'Average PPS':<35} {avg_pps:>20,.0f} {'pps':<15}")
    # ... more metrics
```

**Key Metrics Calculated**:

1. **Duration Metrics**:
   - `duration`: Total experiment time (including zero traffic)
   - `active_duration`: Seconds with actual traffic

2. **Throughput Metrics**:
   - `avg_pps`: Mean packets per second during attack
   - `max_pps`: Peak PPS reached
   - `avg_gbps`: Average throughput
   - `max_gbps`: Peak throughput

3. **Protocol Distribution**:
   - Absolute counts and percentages for TCP/UDP/ICMP

4. **TCP Analysis** (if applicable):
   - SYN, ACK, RST, FIN counts and percentages
   - **SYN/ACK Ratio**: Critical for SYN flood detection

**Why SYN/ACK ratio matters**:
- Normal traffic: ~1.0 (one SYN, one SYN-ACK)
- SYN flood: >3.0 (many SYNs, few responses)
- Threshold: >5.0 is highly suspicious

---

### 4. Visualization Generation

#### Method: `create_main_analysis()`

Creates first image with 4 key plots:

##### Plot 1: Attack Identification Panel

```python
# Attack type box (large, colored)
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
    'CRITICAL': '#c0392b',  # Dark red
    'HIGH': '#e74c3c',      # Red
    'MEDIUM': '#f39c12',    # Orange
    'LOW': '#27ae60',       # Green
    'NONE': '#95a5a6'       # Gray
}
```

**What it does**:
- Creates large colored box showing attack type
- Color-codes severity level
- Displays key metrics in summary box
- Provides at-a-glance attack identification

##### Plot 2: Throughput Over Time (Dual-Axis)

```python
# Plot PPS on left axis
line1 = ax2.plot(self.df['time_sec'], self.df['pps']/1000,
                'b-', linewidth=2.5, label='PPS', alpha=0.8)
ax2.fill_between(self.df['time_sec'], 0, self.df['pps']/1000,
                color='b', alpha=0.1)  # Shaded area
ax2.set_ylabel('PPS (thousands)', color='b')

# Plot Gbps on right axis
ax2_twin = ax2.twinx()
line2 = ax2_twin.plot(self.df['time_sec'], self.df['gbps'],
                     'r-', linewidth=2.5, label='Gbps', alpha=0.8)
ax2_twin.set_ylabel('Throughput (Gbps)', color='r')

# Combined legend
lines = line1 + line2
labels = [l.get_label() for l in lines]
ax2.legend(lines, labels, loc='upper left')
```

**Why dual-axis**:
- PPS and Gbps have different scales
- Both metrics important (volume vs bandwidth)
- Shows correlation between packet rate and throughput

**Why shaded area**:
- Visual emphasis of attack intensity
- Easier to see traffic periods vs idle

##### Plot 3: Protocol Distribution (Stacked Area)

```python
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
                self.df_filtered['tcp'] + self.df_filtered['udp'] +
                self.df_filtered['icmp'],
                label='ICMP', color='#2ecc71', alpha=0.7)
```

**What it shows**:
- Protocol composition over time
- Stacked = shows total traffic and breakdown simultaneously
- Color-coded for easy identification

**Why stacked area**:
- Better than line plot (shows totals)
- Better than separate plots (shows proportions)
- Reveals protocol shifts during attack

##### Plot 4: SYN/ACK Ratio Analysis

```python
# Calculate ratio (with zero-division protection)
syn_ack_ratio = np.where(self.df_filtered['ack'] > 10,
                        self.df_filtered['syn'] / (self.df_filtered['ack'] + 1),
                        0)

# Plot ratio
ax4.plot(self.df_filtered['time_sec'], syn_ack_ratio,
        linewidth=2.5, color='#e74c3c')
ax4.fill_between(self.df_filtered['time_sec'], syn_ack_ratio,
                color='#e74c3c', alpha=0.2)

# Reference lines
ax4.axhline(y=1, color='#27ae60', linestyle='--',
           label='Normal (1:1)', linewidth=2.5)
ax4.axhline(y=3, color='#f39c12', linestyle='--',
           label='Suspicious (>3:1)', linewidth=2.5)
ax4.axhline(y=5, color='#c0392b', linestyle='--',
           label='Attack (>5:1)', linewidth=2.5)

# Highlight danger zones
ax4.axhspan(3, 10, facecolor='#f39c12', alpha=0.1)  # Yellow zone
ax4.axhspan(5, 10, facecolor='#e74c3c', alpha=0.1)  # Red zone
```

**Why this plot is critical**:
- **Primary SYN flood indicator**
- Normal traffic: ratio ≈ 1.0
- SYN flood: ratio >> 1.0 (many SYNs, few ACKs)
- Visual thresholds make interpretation immediate

**Zero-division protection**:
- Only calculate ratio when ACK > 10 (avoid noise)
- Add 1 to denominator (safety)

---

#### Method: `create_detailed_metrics()`

Creates second image with 4 additional plots:

##### Plot 1: Protocol Distribution (Pie Chart)

```python
tcp_total = self.df_filtered['tcp'].sum()
udp_total = self.df_filtered['udp'].sum()
icmp_total = self.df_filtered['icmp'].sum()
total = tcp_total + udp_total + icmp_total

wedges, texts, autotexts = ax1.pie(
    protocol_counts,
    labels=['TCP', 'UDP', 'ICMP'],
    autopct=lambda pct: f'{pct:.1f}%\n({int(pct*total/100):,})',
    colors=['#e74c3c', '#3498db', '#2ecc71'],
    explode=(0.05, 0.05, 0.05),  # Slight separation
    shadow=True
)
```

**Custom autopct function**:
- Shows percentage
- Shows absolute count
- Both metrics in one label

##### Plot 2: TCP Flags Bar Chart

```python
flag_data = {
    'SYN': self.df_filtered['syn'].sum(),
    'ACK': self.df_filtered['ack'].sum(),
    'RST': self.df_filtered['rst'].sum(),
    'FIN': self.df_filtered['fin'].sum()
}

bars = ax2.bar(flag_data.keys(), flag_data.values(),
              color=['#e74c3c', '#3498db', '#f39c12', '#9b59b6'])

# Add value labels on bars
for bar in bars:
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height,
            f'{int(height):,}\n({height/tcp_total*100:.1f}%)',
            ha='center', va='bottom', fontsize=10, fontweight='bold')
```

**Why show counts on bars**:
- Immediate readability
- No need to estimate from axis
- Shows both absolute and percentage

##### Plot 3: Traffic Intensity Heatmap

```python
# Create time bins
n_bins = min(30, len(self.df_filtered))
time_bins = np.linspace(df_temp['time_sec'].min(),
                       df_temp['time_sec'].max(), n_bins)
df_temp['time_bin'] = pd.cut(df_temp['time_sec'], bins=time_bins)

# Aggregate by time bin
heatmap_data = df_temp.groupby('time_bin')[['tcp', 'udp', 'icmp']].sum().T

# Plot heatmap
sns.heatmap(heatmap_data, cmap='YlOrRd', ax=ax3,
           cbar_kws={'label': 'Packets per Interval'},
           linewidths=0.5, linecolor='white')
```

**What it shows**:
- Traffic intensity evolution
- Protocol-specific hot spots
- Temporal patterns (bursts, pauses)

**Why 30 bins**: Balance between detail and readability

##### Plot 4: Summary Metrics Table

```python
summary_data = [
    ['Attack Type', self.attack_type],
    ['Severity', self.attack_severity],
    ['Total Duration', f'{duration:.1f} s'],
    ['Avg PPS', f'{avg_pps:,.0f}'],
    # ... more rows
]

table = ax4.table(cellText=summary_data,
                 colLabels=['Metric', 'Value'],
                 cellLoc='left',
                 loc='center',
                 colWidths=[0.55, 0.45])

# Style table
for i in range(len(summary_data) + 1):
    if i == 0:
        # Header row
        table[(i, 0)].set_facecolor('#34495e')
        table[(i, 0)].set_text_props(weight='bold', color='white')
    else:
        # Alternate row colors
        color = '#ecf0f1' if i % 2 == 0 else 'white'
        table[(i, 0)].set_facecolor(color)

    # Highlight attack type/severity rows
    if i == 1 or i == 2:
        table[(i, 1)].set_facecolor(self.attack_color)
        table[(i, 1)].set_text_props(weight='bold', color='white')
```

**Styling details**:
- Alternating row colors (readability)
- Dark header
- Attack type/severity highlighted with attack color
- Professional appearance

---

## Data Processing Techniques

### 1. Filtering Strategy

```python
# Keep full dataframe for context
self.df = pd.read_csv(log_file)

# Create filtered view for analysis
self.df_filtered = self.df[self.df['pps'] > 0].copy()
```

**Why both**:
- `df`: Needed for complete timeline (includes idle periods)
- `df_filtered`: Used for statistics (excludes zeros)
- Prevents skewing of means/percentages

### 2. Safe Division

```python
# Bad: Division by zero crashes
syn_ack_ratio = self.df['syn'] / self.df['ack']

# Good: Protected with np.where
syn_ack_ratio = np.where(self.df['ack'] > 10,
                        self.df['syn'] / (self.df['ack'] + 1),
                        0)
```

### 3. Timestamp Normalization

```python
# Convert absolute to relative timestamps
self.df['time_sec'] = (self.df['timestamp'] - self.df['timestamp'].min())
```

**Why**: Makes plots start at 0 seconds instead of Unix timestamp

---

## Visualization Best Practices

### 1. Color Consistency

```python
# Define color palette once
PROTOCOL_COLORS = {
    'tcp': '#e74c3c',   # Red
    'udp': '#3498db',   # Blue
    'icmp': '#2ecc71'   # Green
}

# Use consistently across all plots
```

### 2. High-Resolution Output

```python
plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white')
```

**Parameters**:
- `dpi=300`: Publication quality
- `bbox_inches='tight'`: No wasted whitespace
- `facecolor='white'`: Clean background

### 3. Font Sizes

```python
plt.rcParams['font.size'] = 11          # Base size
fig.suptitle(..., fontsize=20)          # Title
ax.set_title(..., fontsize=14)          # Subplot titles
ax.set_xlabel(..., fontsize=12)         # Axis labels
table.set_fontsize(11)                  # Table text
```

**Hierarchy**: Helps guide reader's attention

---

## Performance Considerations

### Memory Usage

- **Small logs** (<1MB): Load entirely into memory
- **Large logs** (>100MB): Could use chunked reading
- Current implementation: Suitable for typical experiments (1M rows ≈ 50MB)

### Processing Time

- **Typical**: 10-30 seconds for complete analysis
- **Bottleneck**: Matplotlib rendering, not pandas processing
- **Optimization**: Could cache plots if running repeatedly

---

## Extension Points

### Adding New Attack Types

```python
# In detect_attack_type():
elif some_new_condition:
    self.attack_type = "NEW ATTACK"
    self.attack_severity = "HIGH"
    self.attack_color = "#hexcolor"
```

### Additional Metrics

```python
# In print_summary_table():
new_metric = self.df_filtered['new_column'].sum()
print(f"{'New Metric':<35} {new_metric:>20,.0f}")
```

### Custom Visualizations

```python
def create_custom_plot(self):
    fig, ax = plt.subplots()
    ax.plot(self.df_filtered['time_sec'], self.df_filtered['custom_metric'])
    plt.savefig('custom_plot.png')
```

---

## Summary

The analysis tool uses:
1. **Pandas** for efficient data manipulation
2. **Matplotlib + Seaborn** for professional visualizations
3. **Heuristic detection** for attack classification
4. **Dual dataframes** (full + filtered) for accurate analysis
5. **Color coding** for severity indication
6. **High-resolution output** for publication quality

Key strengths:
- Automatic attack detection (no manual labeling)
- Comprehensive visualizations (8 plots)
- Statistical rigor (proper filtering, safe division)
- Professional appearance (suitable for papers/presentations)
