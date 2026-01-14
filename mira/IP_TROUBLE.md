# Network Traffic Routing Issue - MIRA DDoS Detector

## Experiment Overview

We are running a DPDK-based DDoS detector (MIRA) on CloudLab with the following architecture:

**Physical Nodes:**
- **node-monitor** (10.10.1.2, 10.10.1.3): Runs the DDoS detector, captures all traffic
- **node-controller** (10.10.1.5): Sends benign traffic using PCAP replay
- **node-tg** (10.10.1.1): Sends attack traffic using PCAP replay

**Traffic Flow:**
- Controller/TG send pre-generated PCAP files containing simulated traffic
- Simulated benign clients: 10.10.2.x (500 IPs)
- Simulated attack sources: 10.10.3.x (200 IPs)
- All traffic is destined to 10.10.1.2 (monitor's detector IP)

## Network Configuration

### node-monitor Interfaces:

```
eno33 (Control/Management):
  MAC: 1c:34:da:72:fa:96
  IP: 128.110.219.76/21 (public internet access, SSH)
  Purpose: CloudLab shared control network

ens1f0 (Experimental - DPDK capture):
  MAC: 0c:42:a1:dd:57:90
  IP: None (raw packet capture)
  Purpose: DPDK captures all packets here

ens1f1 (Experimental - Kernel):
  MAC: 0c:42:a1:dd:57:91
  IPs: 10.10.1.3/24, 10.10.1.2/24
  Purpose: Experimental network with IPs assigned
```

### PCAP Traffic Characteristics:

**Benign PCAP (benign_20M.pcap):**
```
Source MAC: 00:00:00:00:00:01 (simulated)
Dest MAC: 0c:42:a1:dd:57:90 (ens1f0 on monitor)
Source IPs: 10.10.2.x (simulated benign clients)
Dest IP: 10.10.1.2 (monitor)
Protocols: HTTP, DNS, SSH, ICMP
```

**Attack PCAPs:**
```
Source MAC: 00:00:00:00:00:01 (simulated)
Dest MAC: 0c:42:a1:dd:57:90 (ens1f0 on monitor)
Source IPs: 10.10.3.x (simulated attackers)
Dest IP: 10.10.1.2 (monitor)
Protocols: Various DDoS attack vectors
```

## Expected Behavior

1. PCAP sender on controller/tg reads packets from file
2. Packets are sent via DPDK through ens1f0 interface (0000:41:00.0)
3. Ethernet switch routes packets based on destination MAC (0c:42:a1:dd:57:90)
4. Packets arrive at ens1f0 on node-monitor
5. DPDK detector captures and analyzes packets
6. All physical traffic remains on experimental network (ens1f0/ens1f1)
7. Control network (eno33) only carries SSH/management traffic (<100 pps)

## Actual Problem

CloudLab is detecting massive traffic on the **shared control network (eno33)** instead of the experimental network:

```
Alert from CloudLab:
Node: amd165 (node-monitor)
Interface: eth0 (eno33 - control network)
Traffic: 730,931 packets/sec, 381 Mbits/sec
Duration: 1333 seconds
```

### Measurements Confirming the Issue:

**Test duration: 60 seconds**

Before test:
```
eno33 TX packets: 1,410,856,714
```

After test:
```
eno33 TX packets: 1,421,287,725
```

**Calculation:**
- Packets sent: 10,431,011 packets
- Rate: 173,850 packets/sec via control network
- This violates CloudLab policy (threshold: 100,000 pps)

### Traffic Analysis (tcpdump on eno33):

While experiment is running, eno33 shows:
```
IP 10.10.1.2.80 > 10.10.2.26.53939: HTTP/1.1 200 OK
IP 10.10.1.2.22 > 10.10.2.135.59874: SSH SYN-ACK
IP 10.10.1.2.53 > 10.10.2.7.61491: DNS response
```

**Analysis:** The Linux kernel is generating responses to the simulated traffic (10.10.2.x clients) and sending those responses via eno33 instead of ens1f1.

## Root Cause Analysis

### Why the kernel is responding:

1. PCAP traffic arrives at ens1f0 with destination IP 10.10.1.2
2. DPDK captures the packets correctly
3. Mellanox ConnectX-5 NICs allow the kernel to also see the traffic
4. Kernel sees packets destined for 10.10.1.2 (which is in /etc/hosts as this node)
5. Kernel generates automatic responses (TCP ACK, DNS replies, etc.)
6. Despite 10.10.1.2 being configured on ens1f1, responses are routed via eno33

### Routing Table:
```
default via 128.110.216.1 dev eno33
10.10.1.0/24 dev ens1f1 proto kernel scope link src 10.10.1.3
```

### ARP Table Issue:
```
10.10.1.2 dev ens1f1  FAILED
```

The ARP entry for 10.10.1.2 on ens1f1 is failing, which may cause the kernel to use the default route (eno33) for responses.

## Attempted Solutions

1. **Used whitelist (-w 0000:41:00.0):** DPDK correctly uses only ens1f0 for capture
2. **Added 10.10.1.2 as secondary IP on ens1f1:** Configured but ARP resolution fails
3. **Disabled hardware offloads on eno33:** `ethtool -K eno33 rx off tx off`
4. **Verified PCAP contains correct MACs:** Destination MAC is correct (0c:42:a1:dd:57:90)

## Root Cause Diagnosis

### Critical Discovery:

Running the following command revealed the exact problem:

```bash
ip route get 10.10.2.10 from 10.10.1.2
```

**Result:**
```
10.10.2.10 from 10.10.1.2 via 128.110.216.1 dev eno33 uid 20014
```

**Analysis:** The kernel has no routing entries for the simulated networks 10.10.2.0/24 and 10.10.3.0/24. When the kernel needs to send responses to these IPs, it treats them as "external" and uses the default gateway (128.110.216.1) via eno33 (control network).

### Complete Routing Table Analysis:

```bash
default via 128.110.216.1 dev eno33
10.10.1.0/24 dev ens1f1 proto kernel scope link src 10.10.1.3
```

**Missing routes:**
- No route for 10.10.2.0/24 (benign simulated clients)
- No route for 10.10.3.0/24 (attack simulated sources)

Without these routes, the kernel defaults to eno33 for all traffic destined to these networks.

## Solution

### Add Static Routes for Simulated Networks

Add explicit routes telling the kernel to send traffic for simulated networks via ens1f1:

```bash
# On node-monitor
sudo ip route add 10.10.2.0/24 dev ens1f1 src 10.10.1.2
sudo ip route add 10.10.3.0/24 dev ens1f1 src 10.10.1.2
```

### Verification:

```bash
# Verify routing table
ip route show
```

**Expected output:**
```
default via 128.110.216.1 dev eno33 proto dhcp src 128.110.219.76 metric 1024
10.10.1.0/24 dev ens1f1 proto kernel scope link src 10.10.1.3
10.10.2.0/24 dev ens1f1 scope link src 10.10.1.2  <-- NEW
10.10.3.0/24 dev ens1f1 scope link src 10.10.1.2  <-- NEW
128.110.216.0/21 dev eno33 proto kernel scope link src 128.110.219.76
```

```bash
# Test routing decision
ip route get 10.10.2.10 from 10.10.1.2
```

**Expected output:**
```
10.10.2.10 from 10.10.1.2 dev ens1f1 uid 20014  <-- Uses ens1f1 now
```

### Results After Solution:

**60-second test:**

Before test:
```
eno33 TX packets: 1,421,289,566
```

After test:
```
eno33 TX packets: 1,421,289,768
```

**Calculation:**
- Packets sent: 202 packets
- Rate: 3.37 packets/sec via control network
- Status: RESOLVED (below 100,000 pps threshold by 99.99%)

**Traffic is now correctly routed through ens1f1 (experimental network) instead of eno33 (control network).**

## Making the Solution Permanent

### IMPORTANT: Only node-monitor Requires Route Configuration

**Only node-monitor needs the routing configuration.** Here's why:

| Node | Role | DPDK Interface | Kernel Involvement | Needs Routes? |
|------|------|----------------|-------------------|---------------|
| **node-monitor** | Receiver/Detector | ens1f0 (0000:41:00.0) captures packets | **YES** - Kernel sees traffic and generates responses | **YES** - Routes prevent responses via eno33 |
| **node-controller** | Sender (benign) | ens1f0 (0000:41:00.0) sends packets | **NO** - Only transmits, doesn't receive | **NO** - ens1f1 can remain DOWN |
| **node-tg** | Sender (attack) | ens1f0 (0000:41:00.0) sends packets | **NO** - Only transmits, doesn't receive | **NO** - ens1f1 can remain DOWN |

**Key Insight:** Mellanox ConnectX-5 NICs allow the kernel to see packets that DPDK captures. On node-monitor, when DPDK captures packets destined to 10.10.1.2, the kernel also sees them and automatically generates responses (TCP ACK, DNS replies, etc.). Without proper routing, these kernel-generated responses use the default route (eno33 - control network). The sender nodes (controller and tg) only transmit via DPDK and never generate kernel responses, so they don't need the routing configuration.

### Configuration Commands:

#### node-monitor (REQUIRED):
```bash
# Ensure ens1f1 has the IP and is UP
sudo ip addr add 10.10.1.2/24 dev ens1f1  # If not already configured
sudo ip link set ens1f1 up

# Add routes for simulated networks
sudo ip route add 10.10.2.0/24 dev ens1f1 src 10.10.1.2
sudo ip route add 10.10.3.0/24 dev ens1f1 src 10.10.1.2

# Verify
ip route show
ip route get 10.10.2.10 from 10.10.1.2  # Should show "dev ens1f1"
```

#### node-controller (NOT REQUIRED):
```bash
# No configuration needed
# ens1f1 can remain DOWN - only ens1f0 is used by DPDK for transmission
# DPDK command: sudo ./dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 -- ...
```

#### node-tg (NOT REQUIRED):
```bash
# No configuration needed
# ens1f1 can remain DOWN - only ens1f0 is used by DPDK for transmission
# DPDK command: sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- ...
```

## Technical Environment

- DPDK version: 19.11+
- NIC: Mellanox ConnectX-5 (mlx5_core driver)
- OS: Ubuntu 20.04
- Detector: Custom DPDK application with 14 worker threads + OctoSketch
- Traffic rate: ~12 Gbps during experiments

## Summary

The issue was caused by missing routing entries for the simulated IP networks (10.10.2.0/24 and 10.10.3.0/24). Without explicit routes, the Linux kernel used the default gateway via eno33 (control network) to send responses, generating massive traffic on CloudLab's shared control network. Adding static routes for these networks via ens1f1 (experimental network) resolved the issue completely.
