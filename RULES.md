# Traffic Generation and Detection Rules

## Overview

This document explains the complete traffic generation and detection methodology I use in my DDoS detection system. It covers:

1. **Benign Traffic Generation**: How I create realistic legitimate network traffic
2. **Attack Traffic Generation**: How I synthesize various DDoS attack types
3. **Detection Rules**: The logic I use to identify attacks in my detector

My system is designed to generate ground-truth labeled traffic for testing and training machine learning models, while my detector applies real-time rules to classify traffic patterns.

---

## System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    Traffic Generation                           │
│                                                                 │
│  ┌─────────────────┐              ┌──────────────────┐        │
│  │ Benign Traffic  │              │ Attack Traffic   │        │
│  │                 │              │                  │        │
│  │ • HTTP Sessions │              │ • SYN Flood      │        │
│  │ • DNS Queries   │              │ • UDP Flood      │        │
│  │ • SSH Sessions  │              │ • HTTP Flood     │        │
│  │ • ICMP Pings    │              │ • DNS Amp        │        │
│  │ • NTP Queries   │              │ • ... 9 types    │        │
│  └────────┬────────┘              └─────────┬────────┘        │
│           │                                 │                  │
│           └─────────────┬───────────────────┘                  │
│                         │                                      │
└─────────────────────────┼──────────────────────────────────────┘
                          │
                          ▼
                    ┌──────────┐
                    │   PCAP   │
                    │   File   │
                    └─────┬────┘
                          │
                          ▼
                 ┌────────────────┐
                 │  tcpreplay to  │
                 │  100G NIC      │
                 └────────┬───────┘
                          │
                          ▼
           ┌──────────────────────────────┐
           │    DPDK Detector             │
           │                              │
           │  ┌────────────────────────┐  │
           │  │ Packet Processing      │  │
           │  └───────┬────────────────┘  │
           │          │                   │
           │  ┌───────▼────────────────┐  │
           │  │ Feature Extraction     │  │
           │  │ • PPS, Gbps           │  │
           │  │ • Protocol ratios     │  │
           │  │ • TCP flag analysis   │  │
           │  │ • Cardinality (HLL)   │  │
           │  └───────┬────────────────┘  │
           │          │                   │
           │  ┌───────▼────────────────┐  │
           │  │ Detection Rules        │  │
           │  │ • Threshold-based     │  │
           │  │ • Ratio-based         │  │
           │  │ • Multi-feature       │  │
           │  └───────┬────────────────┘  │
           │          │                   │
           │          ▼                   │
           │    ┌──────────┐              │
           │    │  Alerts  │              │
           │    └──────────┘              │
           └──────────────────────────────┘
```

---

## 1. Benign Traffic Generation

### 1.1 Traffic Profiles

I define three benign traffic profiles to simulate different network loads:

| Profile | Events/Sec | Target PPS | Use Case |
|---------|------------|------------|----------|
| **Light** | 10 | ~500 | Small office network |
| **Normal** | 50 | ~2,500 | Enterprise network |
| **Heavy** | 200 | ~10,000 | Data center edge |

**Events per second**: Number of complete protocol sessions (HTTP request/response, DNS query/response, etc.)

**Target PPS**: Approximate packets per second generated (each event produces multiple packets)

---

### 1.2 Protocol Mix

I configure each profile with a different protocol distribution:

| Protocol | Light | Normal | Heavy | Description |
|----------|-------|--------|-------|-------------|
| **HTTP** | 40% | 50% | 60% | Web traffic (most common) |
| **DNS** | 30% | 25% | 20% | Domain lookups |
| **SSH** | 10% | 10% | 10% | Remote management |
| **ICMP** | 15% | 10% | 5% | Ping, diagnostics |
| **NTP** | 5% | 5% | 5% | Time synchronization |

**My Rationale**:
- **Heavy profile**: More HTTP (web-heavy data center traffic)
- **Light profile**: More DNS/ICMP (diagnostic-heavy small network)

---

### 1.3 My Protocol Implementations

#### HTTP Session (Complete TCP Lifecycle)

**Packet sequence** (9 packets total):

```
Client                                    Server
  │                                         │
  ├─────────── SYN ───────────────────────>│  1. Connection request
  │<────────── SYN-ACK ─────────────────────┤  2. Connection accept
  ├─────────── ACK ───────────────────────>│  3. ACK handshake
  │                                         │
  ├─────────── PSH-ACK (GET /) ──────────>│  4. HTTP request
  │<────────── PSH-ACK (200 OK) ────────────┤  5. HTTP response
  ├─────────── ACK ───────────────────────>│  6. ACK response
  │                                         │
  ├─────────── FIN-ACK ───────────────────>│  7. Close connection
  │<────────── FIN-ACK ─────────────────────┤  8. Acknowledge close
  ├─────────── ACK ───────────────────────>│  9. Final ACK
  │                                         │
```

**Key characteristics I implement**:
- **Proper 3-way handshake** (SYN, SYN-ACK, ACK)
- **Data transfer with PSH flag** (indicates payload)
- **Graceful teardown** (FIN-ACK sequence)
- **Realistic timing**: 1-5ms between packets, 50-200ms for server processing
- **Variable payload**: HTTP request ~150 bytes, response ~512 bytes

**My Code** (`benign_traffic.py:27-131`):
```python
def generate_http_session(self, writer, client_ip, server_ip, start_time):
    # 1. SYN (Client → Server)
    syn = Ether() / IP(src=client_ip, dst=server_ip) /
          TCP(sport=client_port, dport=80, flags='S', seq=random_seq)

    # 2. SYN-ACK (Server → Client)
    syn_ack = Ether() / IP(src=server_ip, dst=client_ip) /
              TCP(sport=80, dport=client_port, flags='SA', ack=syn.seq+1)

    # 3-9. Continue with full session...
```

---

#### DNS Query/Response (2 packets)

**Packet sequence**:

```
Client                    DNS Server
  │                           │
  ├── Query (A google.com) ──>│  1. Request IP for domain
  │<─ Response (142.250.x.x) ─┤  2. Return IP address
  │                           │
```

**Key characteristics I implement**:
- **UDP-based** (port 53)
- **Query**: ~40 bytes (DNSQR with domain name)
- **Response**: ~60-100 bytes (DNSRR with IP)
- **Realistic domains**: google.com, facebook.com, github.com, etc.
- **Timing**: 10-50ms response time

**My Code** (`benign_traffic.py:133-168`):
```python
def generate_dns_query_response(self, writer, client_ip, dns_server, start_time):
    # Query
    dns_query = DNS(id=random_id, qr=0, rd=1, qd=DNSQR(qname='google.com'))
    query_pkt = IP(src=client_ip, dst=dns_server) / UDP(dport=53) / dns_query

    # Response (10-50ms later)
    dns_response = DNS(id=random_id, qr=1, an=DNSRR(rrname='google.com', rdata=ip))
    response_pkt = IP(src=dns_server, dst=client_ip) / UDP(sport=53) / dns_response
```

---

#### SSH Session (Encrypted Traffic)

**Packet sequence** (7+ packets):

```
Client                    SSH Server
  │                           │
  ├────── SYN ───────────────>│  1. TCP handshake
  │<───── SYN-ACK ─────────────┤
  ├────── ACK ───────────────>│
  │                           │
  ├── PSH-ACK (Key Exchange) ─>│  4. SSH handshake
  │<─ PSH-ACK (Server Key) ────┤  5.
  ├── PSH-ACK (Client Key) ───>│  6.
  │                           │
  ├── PSH-ACK (Encrypted) ────>│  7-10. Data exchange
  │<─ PSH-ACK (Encrypted) ─────┤
  │                           │
```

**Key characteristics I implement**:
- **TCP port 22**
- **Multiple PSH-ACK packets** (bidirectional data)
- **Variable payload sizes**: 64-512 bytes (simulates encrypted commands)
- **Timing**: 50-200ms between exchanges (interactive)

---

#### ICMP Ping (2 packets)

**Packet sequence**:

```
Client                    Target
  │                         │
  ├── Echo Request (type 8) ─>│  1. Ping
  │<─ Echo Reply (type 0) ────┤  2. Pong
  │                         │
```

**Key characteristics I implement**:
- **ICMP types**: 8 (request), 0 (reply)
- **Payload**: 56 bytes (standard ping size)
- **Timing**: 1-50ms RTT (round-trip time)

---

#### NTP Query/Response (2 packets)

**Packet sequence**:

```
Client                    NTP Server
  │                           │
  ├── Request (v4 client) ───>│  1. Time sync request
  │<─ Response (timestamp) ────┤  2. Time data
  │                           │
```

**Key characteristics I implement**:
- **UDP port 123**
- **Fixed payload**: 48 bytes (NTP protocol)
- **Timing**: 10-100ms response

---

### 1.4 My Benign Traffic Characteristics Summary

| Metric | Value | Reasoning |
|--------|-------|-----------|
| **TCP ratio** | 70-80% | Most traffic is HTTP/SSH (TCP) |
| **UDP ratio** | 15-20% | DNS and NTP queries |
| **ICMP ratio** | 5-10% | Occasional diagnostics |
| **SYN ratio** | ~5-10% of TCP | Each session starts with 1 SYN, but has many data packets |
| **ACK ratio** | ~80-90% of TCP | Almost all TCP packets have ACK flag |
| **PSH ratio** | ~30-40% of TCP | Data-carrying packets |
| **FIN ratio** | ~5-10% of TCP | Connection teardowns |
| **Average packet size** | 200-500 bytes | Mix of headers (64B) and data (200-1500B) |
| **Unique source IPs** | 50-250 | Internal network clients |
| **Unique dest ports** | 100-1000 | Various services accessed |
| **Packet rate** | Varies by profile | Light: 500 PPS, Normal: 2.5K PPS, Heavy: 10K PPS |

**Key insight**: My benign traffic is **balanced** and **session-oriented** (complete TCP lifecycles).

---

## 2. Attack Traffic Generation

### 2.1 Attack Types Overview

I implement 9 distinct DDoS attack types:

| Attack Type | Layer | Primary Protocol | Mechanism | Typical PPS |
|-------------|-------|------------------|-----------|-------------|
| **SYN Flood** | L4 | TCP | Connection exhaustion | 10K - 100K |
| **UDP Flood** | L4 | UDP | Bandwidth saturation | 15K - 150K |
| **HTTP Flood** | L7 | TCP (HTTP) | Application exhaustion | 3K - 30K |
| **DNS Amplification** | L4 | UDP | Reflection attack | 8K - 80K |
| **NTP Amplification** | L4 | UDP | Reflection attack | 7K - 70K |
| **ICMP Flood** | L3 | ICMP | Bandwidth saturation | 5K - 50K |
| **Fragmentation** | L3 | IP | Reassembly exhaustion | 5K - 50K |
| **ACK Flood** | L4 | TCP | Firewall bypass | 9K - 90K |
| **Volumetric Mix** | L3/L4 | Mixed | Combined attack | 20K - 200K |

---

### 2.2 Individual Attack Characteristics

#### 2.2.1 SYN Flood

**Objective**: Exhaust server connection table (backlog queue)

**My Implementation**:
- I send **SYN packets only** (never complete handshake)
- I use **spoofed source IPs** (prevents SYN-ACK replies)
- I target **common ports** (80, 443, 8080)

**Packet structure**:
```
Ether / IP(src=random_ip, dst=target) / TCP(flags='S', dport=80)
```

**Key characteristics**:
```
• Protocol: 100% TCP
• SYN ratio: 95-100% (almost all TCP packets are SYN)
• ACK ratio: 0-5% (no completed handshakes)
• Source IPs: 10,000+ unique (spoofed, distributed)
• Destination ports: 3-5 (focused on web services)
• Packet size: 64-70 bytes (minimal SYN packet)
• PPS: 10,000 - 100,000
```

**Detection signature**:
```python
if tcp_ratio > 0.9 and syn_ratio > 0.7:
    alert("SYN_FLOOD")
```

**My Code** (`attacks.py:39-70`):
```python
class SYNFloodGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=10000):
        for i in range(num_packets):
            src_ip = random_public_ip()  # Spoofed
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 8080])

            pkt = IP(src=src_ip, dst=target_ip) /
                  TCP(sport=sport, dport=dport, flags='S', seq=random_seq)
```

**Why it works**:
- Server allocates resources for each SYN (backlog entry)
- SYN-ACK replies go to spoofed IPs (no response)
- Backlog fills up → legitimate connections rejected

---

#### 2.2.2 UDP Flood

**Objective**: Saturate bandwidth and overwhelm processing

**My Implementation**:
- I send **UDP packets** with **large payloads**
- I target **various ports** (harder to filter)
- **No connection state** (can't be filtered by stateful firewalls)

**Packet structure**:
```
Ether / IP(src=random_ip, dst=target) / UDP(dport=random) / Raw(payload)
```

**Key characteristics**:
```
• Protocol: 100% UDP
• Source IPs: 10,000+ unique
• Destination ports: 1-65535 (random, distributed)
• Packet size: 100-1400 bytes (variable payloads)
• PPS: 15,000 - 150,000
• Bandwidth: High (large packets × high PPS)
```

**Detection signature**:
```python
if udp_ratio > 0.8 and pps > 10000:
    alert("UDP_FLOOD")
```

**My Code** (`attacks.py:72-97`):
```python
class UDPFloodGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=15000):
        for i in range(num_packets):
            src_ip = random_public_ip()
            sport = random.randint(1024, 65535)
            dport = random.choice([53, 123, 161, 1900])  # Common UDP ports

            payload_size = random.randint(64, 1400)
            payload = random_bytes(payload_size)

            pkt = IP(src=src_ip, dst=target_ip) /
                  UDP(sport=sport, dport=dport) / Raw(load=payload)
```

---

#### 2.2.3 HTTP Flood (Layer 7)

**Objective**: Exhaust application resources (web server)

**My Implementation**:
- I send **valid HTTP requests** (bypass WAF/firewalls)
- I use **PSH-ACK flags** (data transfer)
- I target **resource-intensive pages** (/search, /login)

**Packet structure**:
```
Ether / IP(src=random_ip, dst=target) /
TCP(flags='PA', dport=80) / Raw(load="GET / HTTP/1.1...")
```

**Key characteristics**:
```
• Protocol: 100% TCP
• TCP flags: PSH+ACK (not just SYN)
• Destination ports: 80, 443, 8080
• Packet size: 200-800 bytes (HTTP headers + payload)
• PPS: 3,000 - 30,000 (lower than volumetric, but CPU-intensive)
• Payload: Valid HTTP syntax (GET, POST requests)
```

**Detection signature**:
```python
if tcp_ratio > 0.9 and psh_ratio > 0.8 and dport in [80, 443]:
    alert("HTTP_FLOOD")
```

**My Code** (`attacks.py:162-193`):
```python
class HTTPFloodGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=3000):
        for i in range(num_packets):
            src_ip = random_public_ip()
            sport = random.randint(10000, 60000)
            dport = random.choice([80, 443, 8080])

            http_payload = "GET / HTTP/1.1\r\nHost: target.com\r\n\r\n"

            pkt = IP(src=src_ip, dst=target_ip) /
                  TCP(sport=sport, dport=dport, flags='PA',  # PSH+ACK
                      seq=random_seq, ack=random_ack) /
                  Raw(load=http_payload)
```

**Why it's dangerous**:
- Passes through firewalls (looks like legitimate HTTP)
- Each request consumes CPU (parsing, database queries)
- Lower PPS but higher per-packet cost

---

#### 2.2.4 DNS Amplification

**Objective**: Amplify attack bandwidth using DNS resolvers

**My Implementation**:
- I query **open DNS resolvers** with spoofed source IP (victim)
- I request large records (e.g., TXT, ANY queries)
- **Amplification factor**: 10-50x (small query → large response)

**Packet structure**:
```
Ether / IP(src=target_ip, dst=dns_resolver) /
UDP(dport=53) / DNS(qd=DNSQR(qname="large-record.com"))

# Response (from resolver to victim):
Ether / IP(src=dns_resolver, dst=target_ip) /
UDP(sport=53) / DNS(an=DNSRR(...large data...))
```

**Key characteristics**:
```
• Protocol: 100% UDP
• Source IPs: Few (DNS resolver IPs)
• Destination ports: 1024-65535 (victim's ephemeral ports)
• Source port: 53 (DNS)
• Packet size: 400-1400 bytes (amplified responses)
• PPS: 8,000 - 80,000
• Amplification: Query 64B → Response 640B (10x)
```

**Detection signature**:
```python
if udp_ratio > 0.9 and avg_pkt_size > 500 and src_port == 53:
    alert("DNS_AMPLIFICATION")
```

**My Code** (`attacks.py:99-131`):
```python
class DNSAmplificationGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=8000):
        dns_servers = ['8.8.8.8', '1.1.1.1', ...]  # Open resolvers

        for i in range(num_packets):
            src_ip = random.choice(dns_servers)  # FROM resolver
            dport = random.randint(1024, 65535)  # TO victim

            # Simulate amplified DNS response
            dns_payload = generate_large_dns_response()  # ~600 bytes

            pkt = IP(src=src_ip, dst=target_ip) /
                  UDP(sport=53, dport=dport) / Raw(load=dns_payload)
```

---

#### 2.2.5 NTP Amplification

**Objective**: Similar to DNS amplification, using NTP

**My Implementation**:
- I exploit **NTP monlist command** (returns 600+ bytes)
- I query open NTP servers with spoofed victim IP
- **Amplification factor**: 20-200x

**Key characteristics I generate**:
```
• Protocol: 100% UDP
• Source port: 123 (NTP)
• Packet size: 400-600 bytes (monlist response)
• Amplification: Query 48B → Response 600B (12x)
```

**My Code** (`attacks.py:133-160`):
```python
class NTPAmplificationGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=7000):
        ntp_servers = ["129.6.15.1", ...]

        for i in range(num_packets):
            src_ip = random.choice(ntp_servers)
            ntp_payload = generate_ntp_monlist()  # ~600 bytes

            pkt = IP(src=src_ip, dst=target_ip) /
                  UDP(sport=123, dport=random_port) / Raw(load=ntp_payload)
```

---

#### 2.2.6 ICMP Flood

**Objective**: Saturate bandwidth with ICMP

**My Implementation**:
- I send **ICMP Echo Requests** (ping)
- Variable payload sizes (small to MTU)
- High packet rate

**Key characteristics I generate**:
```
• Protocol: 100% ICMP
• ICMP types: 8 (Echo Request), 0 (Reply), 3 (Unreachable)
• Packet size: 56-1400 bytes
• PPS: 5,000 - 50,000
```

**Detection signature**:
```python
if icmp_ratio > 0.6 and pps > 5000:
    alert("ICMP_FLOOD")
```

**My Code** (`attacks.py:195-226`):
```python
class ICMPFloodGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=5000):
        for i in range(num_packets):
            src_ip = random_public_ip()
            icmp_type = random.choice([8, 0, 3, 11])
            payload_size = random.randint(56, 1400)

            pkt = IP(src=src_ip, dst=target_ip) /
                  ICMP(type=icmp_type) / Raw(load=random_bytes(payload_size))
```

---

#### 2.2.7 Fragmentation Attack

**Objective**: Exhaust reassembly resources

**My Implementation**:
- I fragment packets into **many small pieces**
- I set **More Fragments (MF)** flag
- I force target to buffer fragments waiting for reassembly

**Packet structure**:
```
# Fragment 1 (MF=1, offset=0)
IP(src=src, dst=target, flags=1, frag=0) / Raw(load=data1)

# Fragment 2 (MF=1, offset=8)
IP(src=src, dst=target, flags=1, frag=8) / Raw(load=data2)

# Fragment 3 (MF=0, offset=16) - last fragment
IP(src=src, dst=target, flags=0, frag=16) / Raw(load=data3)
```

**Key characteristics**:
```
• Protocol: IP-level (any L4 protocol)
• Fragmentation ratio: 80-100% (most packets fragmented)
• Fragment size: 8-64 bytes (tiny fragments)
• Fragments per original packet: 3-6
• PPS: 5,000 - 50,000
```

**Detection signature**:
```python
if frag_ratio > 0.5:
    alert("FRAGMENTATION_ATTACK")
```

**My Code** (`attacks.py:228-260`):
```python
class FragmentationAttackGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=5000):
        for i in range(num_packets // 4):  # Each original → 4 fragments
            src_ip = random_public_ip()
            ip_id = random.randint(0, 65535)  # Same ID for fragments

            for frag_idx in range(4):
                is_last = (frag_idx == 3)
                flags = 0 if is_last else 1  # MF flag
                offset = frag_idx * 8

                pkt = IP(src=src_ip, dst=target_ip,
                        id=ip_id, flags=flags, frag=offset) /
                      Raw(load=random_bytes(64))
```

---

#### 2.2.8 ACK Flood

**Objective**: Bypass stateful firewalls (ACK packets pass through)

**My Implementation**:
- I send **ACK-only packets** (no SYN handshake)
- They appear to be part of existing connection
- Firewalls often allow ACK packets through

**Key characteristics I generate**:
```
• Protocol: 100% TCP
• TCP flags: ACK only (no SYN, PSH, FIN)
• Window size: Often 0 (adds confusion)
• Destination ports: 80, 443, 22
• PPS: 9,000 - 90,000
```

**Detection signature**:
```python
if tcp_ratio > 0.9 and ack_ratio > 0.9 and syn_ratio < 0.1:
    alert("ACK_FLOOD")
```

**My Code** (`attacks.py:262-288`):
```python
class ACKFloodGenerator(AttackGenerator):
    def generate_streaming(self, writer, num_packets, start_time, pps=9000):
        for i in range(num_packets):
            src_ip = random_public_ip()
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 22])

            # ACK-only with window=0
            pkt = IP(src=src_ip, dst=target_ip) /
                  TCP(sport=sport, dport=dport, flags='A',
                      seq=random_seq, ack=random_ack, window=0)
```

---

#### 2.2.9 Volumetric Mix

**Objective**: Combine multiple attack vectors simultaneously

**My Implementation**:
- I mix **SYN, UDP, ICMP, ACK** floods
- Interleaved temporally (not bursted by type)
- Harder to detect with single-metric rules

**My Mix ratios** (default):
```
• SYN Flood: 30%
• UDP Flood: 35%
• ICMP Flood: 15%
• ACK Flood: 20%
```

**Key characteristics**:
```
• Protocol: Mixed (TCP 50%, UDP 35%, ICMP 15%)
• PPS: 20,000 - 200,000 (very high)
• Difficult to classify (no single dominant pattern)
```

**Detection signature**:
```python
if pps > 50000 and no_single_protocol_dominant:
    alert("VOLUMETRIC_MIX")
```

**My Code** (`attacks.py:290-395`):
```python
class VolumetricMixGenerator(AttackGenerator):
    def __init__(self, target_ip, seed=None, mix_ratios=None):
        self.mix_ratios = mix_ratios or {
            'syn': 0.30, 'udp': 0.35, 'icmp': 0.15, 'ack': 0.20
        }

    def generate_streaming(self, writer, num_packets, start_time, pps=20000):
        # Calculate packet counts per type
        packet_counts = {k: int(num_packets * ratio)
                        for k, ratio in self.mix_ratios.items()}

        # Shuffle to interleave
        attack_queue = []
        for attack_type, count in packet_counts.items():
            attack_queue.extend([attack_type] * count)
        random.shuffle(attack_queue)

        # Generate in mixed order
        for attack_type in attack_queue:
            generate_packet_of_type(attack_type)
```

---

### 2.3 Attack Traffic Summary Table

| Attack | TCP% | UDP% | ICMP% | SYN Ratio | ACK Ratio | Avg Size | PPS Range |
|--------|------|------|-------|-----------|-----------|----------|-----------|
| **Benign** | 70-80 | 15-20 | 5-10 | 5-10% | 80-90% | 200-500B | 500-10K |
| **SYN Flood** | 100 | 0 | 0 | 95-100% | 0-5% | 64-70B | 10K-100K |
| **UDP Flood** | 0 | 100 | 0 | N/A | N/A | 100-1400B | 15K-150K |
| **HTTP Flood** | 100 | 0 | 0 | 0-5% | 60-70% | 200-800B | 3K-30K |
| **DNS Amp** | 0 | 100 | 0 | N/A | N/A | 400-1400B | 8K-80K |
| **NTP Amp** | 0 | 100 | 0 | N/A | N/A | 400-600B | 7K-70K |
| **ICMP Flood** | 0 | 0 | 100 | N/A | N/A | 56-1400B | 5K-50K |
| **Fragment** | Mixed | Mixed | Mixed | N/A | N/A | 8-64B | 5K-50K |
| **ACK Flood** | 100 | 0 | 0 | 0-5% | 95-100% | 64-70B | 9K-90K |
| **Volumetric** | 50 | 35 | 15 | 15% | 50% | 100-800B | 20K-200K |

---

## 3. My Detection Rules

### 3.1 My Current Implementation (detector_dpdk.c)

#### Features I Extract (19 Total)

My detector extracts these features every second:

| # | Feature | Description | Use |
|---|---------|-------------|-----|
| 1 | `timestamp` | Unix timestamp | Time series analysis |
| 2 | `gbps` | Gigabits per second | Bandwidth usage |
| 3 | `pps` | Packets per second | Rate detection |
| 4 | `avg_pkt_size` | Average packet size | Size distribution |
| 5 | `std_dev` | Packet size std dev | Variability |
| 6 | `tcp_ratio` | TCP / Total | Protocol distribution |
| 7 | `udp_ratio` | UDP / Total | Protocol distribution |
| 8 | `icmp_ratio` | ICMP / Total | Protocol distribution |
| 9 | `syn_ratio` | SYN / TCP | TCP flag analysis |
| 10 | `ack_ratio` | ACK / TCP | TCP flag analysis |
| 11 | `rst_ratio` | RST / TCP | TCP flag analysis |
| 12 | `fin_ratio` | FIN / TCP | TCP flag analysis |
| 13 | `frag_ratio` | Fragmented / Total | Fragmentation |
| 14 | `small_pkt_ratio` | <100B / Total | Packet size |
| 15 | `entropy_src_ip` | Source IP entropy | Placeholder (5.0) |
| 16 | `entropy_dst_port` | Dest port entropy | Placeholder (5.0) |
| 17 | `unique_src_ips` | HLL cardinality | Source diversity |
| 18 | `unique_dst_ports` | HLL cardinality | Destination diversity |
| 19 | `syn_per_sec` | SYN count | Rate metric |
| 20 | `ack_per_sec` | ACK count | Rate metric |

---

#### My Implemented Detection Rule

**My single rule** in `detector_dpdk.c:334-337`:

```c
if (syn_r > 0.7 && alerts_log) {
    fprintf(alerts_log, "%lu,SYN_FLOOD,CRITICAL,syn_ratio=%.2f\n", now, syn_r);
    fflush(alerts_log);
}
```

**Logic**:
- **Condition**: SYN ratio > 70% of TCP traffic
- **Alert type**: SYN_FLOOD
- **Severity**: CRITICAL

**Why it works**:
- Normal traffic: SYN ~5-10% (many data packets per session)
- SYN Flood: SYN ~95% (only SYN packets, no handshake completion)

**Example**:
```
Normal traffic:
  TCP packets: 135,000
  SYN: 6,750 (5%)
  → syn_ratio = 0.05 (NO ALERT)

SYN Flood:
  TCP packets: 135,000
  SYN: 120,000 (89%)
  → syn_ratio = 0.89 (ALERT TRIGGERED)
```

---

### 3.2 My Proposed Detection Rules

#### Rule 1: UDP Flood

```c
if (udp_ratio > 0.80 && pps > 10000) {
    log_alert("UDP_FLOOD", "HIGH",
              sprintf("udp_ratio=%.2f, pps=%lu", udp_ratio, pps));
}
```

**My Logic**:
- UDP > 80% of traffic (my benign: 15-20%)
- High packet rate (my benign: <10K PPS)

---

#### Rule 2: ICMP Flood

```c
if (icmp_ratio > 0.50 && pps > 5000) {
    log_alert("ICMP_FLOOD", "MEDIUM",
              sprintf("icmp_ratio=%.2f, pps=%lu", icmp_ratio, pps));
}
```

**My Logic**:
- ICMP > 50% of traffic (my benign: 5-10%)
- Moderate packet rate

---

#### Rule 3: HTTP Flood

```c
if (tcp_ratio > 0.90 && psh_ratio > 0.70 &&
    dst_port_80_443 > 0.80 && pps > 3000) {
    log_alert("HTTP_FLOOD", "HIGH",
              sprintf("psh_ratio=%.2f, dport_web=%.2f", psh_ratio, dst_port_ratio));
}
```

**My Logic**:
- High TCP ratio
- High PSH flag (data packets)
- Concentrated on web ports (80, 443)
- Moderate PPS (lower than volumetric, but CPU-heavy)

**Note**: This requires tracking destination port distribution (I haven't implemented this yet)

---

#### Rule 4: DNS/NTP Amplification

```c
if (udp_ratio > 0.90 && avg_pkt_size > 400 &&
    src_port_53_123 > 0.80 && unique_src_ips < 100) {
    log_alert("AMPLIFICATION_ATTACK", "CRITICAL",
              sprintf("avg_size=%.2f, src_port_amp=%.2f",
                      avg_pkt_size, src_port_ratio));
}
```

**My Logic**:
- High UDP ratio
- Large packets (amplified responses)
- Source port 53 (DNS) or 123 (NTP)
- Few source IPs (amplification servers)

**Note**: This requires tracking source port distribution (future work)

---

#### Rule 5: Fragmentation Attack

```c
if (frag_ratio > 0.50 && avg_pkt_size < 100) {
    log_alert("FRAGMENTATION_ATTACK", "HIGH",
              sprintf("frag_ratio=%.2f, avg_size=%.2f", frag_ratio, avg_pkt_size));
}
```

**My Logic**:
- High fragmentation ratio
- Small packet sizes (tiny fragments)

---

#### Rule 6: ACK Flood

```c
if (tcp_ratio > 0.90 && ack_ratio > 0.90 && syn_ratio < 0.10 && pps > 8000) {
    log_alert("ACK_FLOOD", "HIGH",
              sprintf("ack_ratio=%.2f, syn_ratio=%.2f", ack_ratio, syn_ratio));
}
```

**My Logic**:
- High TCP ratio
- High ACK ratio (>90%)
- Low SYN ratio (<10%) - no handshakes
- High packet rate

---

#### Rule 7: Volumetric Mix

```c
if (pps > 50000 &&
    tcp_ratio > 0.30 && tcp_ratio < 0.70 &&
    udp_ratio > 0.20 && udp_ratio < 0.60) {
    log_alert("VOLUMETRIC_MIX", "CRITICAL",
              sprintf("pps=%lu, tcp=%.2f, udp=%.2f", pps, tcp_ratio, udp_ratio));
}
```

**My Logic**:
- Very high PPS (>50K)
- No single protocol dominates (mixed)
- Multiple protocols active simultaneously

---

### 3.3 My Multi-Feature Correlation (Advanced)

Instead of single-rule detection, I plan to combine multiple weak signals:

```c
struct detection_vector {
    bool high_pps;           // PPS > 20K
    bool skewed_tcp_ratio;   // tcp_ratio > 0.9 or < 0.5
    bool high_syn;           // syn_ratio > 0.7
    bool low_ack;            // ack_ratio < 0.3
    bool high_unique_ips;    // unique_src_ips > 5000
    bool low_dst_ports;      // unique_dst_ports < 10
    bool high_fragmentation; // frag_ratio > 0.3
    bool large_packets;      // avg_pkt_size > 500
};

int calculate_threat_score(struct detection_vector *dv) {
    int score = 0;
    if (dv->high_pps) score += 3;
    if (dv->skewed_tcp_ratio) score += 2;
    if (dv->high_syn) score += 3;
    if (dv->low_ack) score += 2;
    if (dv->high_unique_ips) score += 4;  // Strong DDoS indicator
    if (dv->low_dst_ports) score += 3;    // Targeted attack
    if (dv->high_fragmentation) score += 2;
    if (dv->large_packets) score += 1;
    return score;  // Max: 20
}

// Alert thresholds
if (score >= 15) {
    log_alert("HIGH_CONFIDENCE_ATTACK", "CRITICAL");
} else if (score >= 10) {
    log_alert("PROBABLE_ATTACK", "HIGH");
} else if (score >= 7) {
    log_alert("SUSPICIOUS_TRAFFIC", "MEDIUM");
}
```

**Advantages of My Approach**:
- **Reduces false positives**: Requires multiple indicators
- **Detects unknown attacks**: Doesn't rely on exact pattern match
- **Weighted scoring**: Prioritizes strong indicators (high cardinality)

---

## 4. My Attack Detection Mapping

### 4.1 My Detection Decision Tree

```
                         Start
                           │
                           ▼
                   ┌───────────────┐
                   │  PPS > 10K?   │
                   └───────┬───────┘
                           │
                ┌──────────┴──────────┐
                │ YES                 │ NO
                ▼                     ▼
        ┌──────────────┐         Normal Traffic
        │ TCP > 90%?   │         (No Alert)
        └──────┬───────┘
               │
        ┌──────┴──────┐
        │ YES         │ NO
        ▼             ▼
    ┌────────┐   ┌────────────┐
    │SYN>70%?│   │ UDP > 80%? │
    └───┬────┘   └─────┬──────┘
        │              │
    ┌───┴───┐      ┌───┴────┐
    │ YES   │ NO   │ YES    │ NO
    ▼       ▼      ▼        ▼
  SYN    HTTP   UDP      ICMP
  FLOOD  FLOOD  FLOOD    FLOOD
         (PSH?)         (ICMP>50%?)
```

---

### 4.2 My Per-Attack Detection Summary

| Attack Type | Primary Indicators | Secondary Indicators | Threshold |
|-------------|-------------------|---------------------|-----------|
| **SYN Flood** | `syn_ratio > 0.7`<br>`tcp_ratio > 0.9` | `unique_src_ips > 5000`<br>`avg_pkt_size < 100` | PPS > 10K |
| **UDP Flood** | `udp_ratio > 0.8` | `unique_dst_ports > 1000` | PPS > 15K |
| **HTTP Flood** | `psh_ratio > 0.7`<br>`tcp_ratio > 0.9` | `dst_port in [80, 443]`<br>`avg_pkt_size > 200` | PPS > 3K |
| **DNS Amp** | `udp_ratio > 0.9`<br>`avg_pkt_size > 400` | `src_port == 53`<br>`unique_src_ips < 100` | PPS > 8K |
| **NTP Amp** | `udp_ratio > 0.9`<br>`avg_pkt_size > 400` | `src_port == 123`<br>`unique_src_ips < 50` | PPS > 7K |
| **ICMP Flood** | `icmp_ratio > 0.5` | `avg_pkt_size variable` | PPS > 5K |
| **Fragmentation** | `frag_ratio > 0.5` | `avg_pkt_size < 100` | PPS > 5K |
| **ACK Flood** | `ack_ratio > 0.9`<br>`syn_ratio < 0.1` | `tcp_ratio > 0.9`<br>`window size == 0` | PPS > 9K |
| **Volumetric** | `pps > 50K`<br>`mixed protocols` | `no single dominant`<br>`high unique_src_ips` | PPS > 20K |

---

## 5. My Testing and Validation

### 5.1 My Experiment Workflow

```
1. I Generate Traffic
   ├─> Benign PCAP (60-120 seconds, profile: normal)
   └─> Attack PCAP (50K-150K packets per type)

2. I Mix Traffic (Optional)
   ├─> Attack ratio: 10-30%
   └─> Interleave packets by timestamp

3. I Replay to Detector
   ├─> Use tcpreplay at line rate
   └─> Monitor: tail -f /local/logs/detection.log

4. I Analyze Results
   ├─> Run analyze_attack.py
   ├─> Check classification accuracy
   └─> Validate detection timing
```

---

### 5.2 My Expected Detection Results

**Test Case 1: Pure SYN Flood**
```
Input: 100K SYN packets @ 10K PPS
Expected Output:
  - Alert: "SYN_FLOOD, CRITICAL, syn_ratio=0.98"
  - Detection latency: <1 second
  - False positives: 0
```

**Test Case 2: Mixed Traffic (70% benign, 30% SYN flood)**
```
Input: 70K benign + 30K SYN packets
Expected Output:
  - First 7 seconds: No alert (benign)
  - Second 8-10: Alert triggered (SYN flood active)
  - Precision: >95%
```

**Test Case 3: HTTP Flood**
```
Input: 30K HTTP flood packets @ 3K PPS
Expected Output:
  - Alert: "HTTP_FLOOD, HIGH" (if rule implemented)
  - Detection based on: psh_ratio, dport, pps
```

---

## 6. My Future Enhancements

### 6.1 Advanced Attack Types I Plan to Implement

#### Slowloris (HTTP Slow Attack)
```python
# Partial HTTP requests that never complete
"GET / HTTP/1.1\r\nHost: target.com\r\n"  # Missing final \r\n
# Send 1 byte every 10 seconds to keep connection alive
```

**Detection**:
```c
if (active_connections > 10000 && bytes_per_connection < 10) {
    alert("SLOWLORIS");
}
```

---

#### DNS Water Torture
```python
# Random subdomain queries to bypass caching
for i in range(100000):
    random_subdomain = generate_random_string(32)
    query = f"{random_subdomain}.victim.com"
    # Each query hits authoritative DNS server
```

**Detection**:
```c
if (dns_queries > 10000 && unique_subdomains > 5000) {
    alert("DNS_WATER_TORTURE");
}
```

---

### 6.2 My Machine Learning Integration Plan

**My feature matrix** (19 features × N seconds):
```
┌────────┬──────┬──────┬─────┬───────────┬─────────┬─────┐
│  Time  │ PPS  │ Gbps │ TCP%│ SYN Ratio │ Unique  │ ... │
│        │      │      │     │           │ Src IPs │     │
├────────┼──────┼──────┼─────┼───────────┼─────────┼─────┤
│ T=0    │ 1000 │ 0.01 │ 0.75│   0.05    │   150   │ ... │
│ T=1    │ 1200 │ 0.01 │ 0.77│   0.06    │   145   │ ... │
│ T=2    │ 85K  │ 0.85 │ 0.98│   0.92    │  15000  │ ... │ ← Attack!
│ T=3    │ 90K  │ 0.90 │ 0.99│   0.95    │  18000  │ ... │ ← Attack!
└────────┴──────┴──────┴─────┴───────────┴─────────┴─────┘
```

**Model training**:
```python
from sklearn.ensemble import RandomForestClassifier

X = features_df[['pps', 'tcp_ratio', 'syn_ratio', ...]]  # 19 features
y = labels  # 0=benign, 1=attack

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# Feature importance
print(model.feature_importances_)
# Typical result: unique_src_ips (0.25), syn_ratio (0.20), pps (0.15), ...
```

---

## 7. Conclusion

### My Key Takeaways

1. **My benign traffic** is characterized by:
   - Complete TCP sessions (handshake → data → teardown)
   - Balanced protocol mix (70% TCP, 20% UDP, 10% ICMP)
   - Low SYN ratio (5-10% of TCP)
   - Moderate PPS (<10K)

2. **My attack traffic** is characterized by:
   - Incomplete sessions (SYN-only, ACK-only)
   - Skewed protocol distribution (>80% single protocol)
   - Anomalous flag ratios (SYN >70%, ACK >90%)
   - High PPS (>10K)
   - High source IP cardinality (>5K unique)

3. **My detection rules** leverage:
   - Protocol ratios (TCP/UDP/ICMP distribution)
   - TCP flag analysis (SYN, ACK, PSH, FIN ratios)
   - Packet rate thresholds (PPS, Gbps)
   - Cardinality estimates (unique sources, destinations)
   - Packet size distributions

4. **My current implementation** detects:
   - SYN Flood (I have implemented this)
   - 8 other attacks (I have proposed rules, not implemented yet)

5. **My future work**:
   - I will implement remaining detection rules
   - I will add entropy calculations (source IP, dest port)
   - I will integrate machine learning models
   - I will add dynamic baseline learning (adaptive thresholds)

---

### Quick Reference: Detection Cheat Sheet

| If you see... | It's probably... | Confidence |
|---------------|------------------|------------|
| `syn_ratio > 0.7` | SYN Flood | High |
| `udp_ratio > 0.8` | UDP Flood or Amplification | High |
| `icmp_ratio > 0.5` | ICMP Flood | High |
| `psh_ratio > 0.7 && dport=80` | HTTP Flood | Medium |
| `avg_pkt_size > 500 && udp && src_port=53` | DNS Amplification | High |
| `frag_ratio > 0.5` | Fragmentation Attack | High |
| `ack_ratio > 0.9 && syn_ratio < 0.1` | ACK Flood | High |
| `pps > 50K && mixed protocols` | Volumetric Mix | Medium |
| `unique_src_ips > 10K` | Distributed Attack | High |
| `unique_dst_ports < 10` | Targeted Attack | High |

---

*This document provides the complete methodology for generating and detecting DDoS attacks in my system. For implementation details, see `attack_generator/` and `detector_system/` modules.*
