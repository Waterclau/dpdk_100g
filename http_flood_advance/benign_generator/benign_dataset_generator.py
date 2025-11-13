#!/usr/bin/env python3
"""
Benign HTTP Traffic Dataset Generator
Generates large, realistic benign HTTP traffic datasets for baseline testing

Target: Generate diverse, realistic HTTP traffic patterns
Output: PCAP files and flow statistics for analysis
"""

import os
import sys
import time
import random
import argparse
import json
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.http import HTTP, HTTPRequest
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

# Traffic patterns for realistic benign traffic
class BenignTrafficPatterns:
    """Defines realistic benign HTTP traffic patterns"""

    # Common user agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36"
    ]

    # HTTP request paths (realistic web application paths)
    HTTP_PATHS = [
        "/",
        "/index.html",
        "/home",
        "/about",
        "/contact",
        "/products",
        "/services",
        "/api/v1/users",
        "/api/v1/products",
        "/api/v1/orders",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/profile",
        "/api/v1/search?q=test",
        "/api/v1/recommendations",
        "/static/css/main.css",
        "/static/css/style.css",
        "/static/js/app.js",
        "/static/js/jquery.min.js",
        "/static/js/bootstrap.min.js",
        "/static/images/logo.png",
        "/static/images/banner.jpg",
        "/static/fonts/roboto.woff2",
        "/favicon.ico",
        "/robots.txt",
        "/sitemap.xml",
        "/feed/rss",
        "/blog",
        "/blog/post/123",
        "/user/profile",
        "/user/settings",
        "/cart",
        "/checkout",
        "/search?q=dpdk+networking",
        "/category/electronics",
        "/product/laptop-123",
        "/reviews",
        "/help",
        "/faq",
        "/terms",
        "/privacy"
    ]

    # HTTP methods distribution (GET is most common)
    HTTP_METHODS = [
        ("GET", 0.70),      # 70% GET requests
        ("POST", 0.20),     # 20% POST requests
        ("PUT", 0.05),      # 5% PUT requests
        ("DELETE", 0.02),   # 2% DELETE requests
        ("HEAD", 0.02),     # 2% HEAD requests
        ("OPTIONS", 0.01)   # 1% OPTIONS requests
    ]

    # Content types for POST/PUT requests
    CONTENT_TYPES = [
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "application/xml"
    ]

    # Common HTTP headers
    ACCEPT_HEADERS = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "application/json, text/plain, */*",
        "text/css,*/*;q=0.1",
        "application/javascript, */*",
        "image/webp,image/apng,image/*,*/*;q=0.8"
    ]

    # Request sizes (body payload for POST/PUT)
    REQUEST_SIZES = [
        (0, 0.40),          # 40% empty body (GET, HEAD, etc.)
        (100, 0.25),        # 25% small (form data)
        (1000, 0.20),       # 20% medium (JSON API)
        (5000, 0.10),       # 10% large (file upload)
        (50000, 0.05)       # 5% very large (image/video upload)
    ]


class BenignTrafficGenerator:
    """Generates realistic benign HTTP traffic"""

    def __init__(self, config):
        self.config = config
        self.patterns = BenignTrafficPatterns()
        self.stats = defaultdict(int)
        self.packets = []
        self.session_counter = 0

        # Network configuration
        self.src_ip_base = config.get('src_ip_base', '192.168.1.')
        self.dst_ip = config.get('dst_ip', '10.0.0.1')
        self.src_mac = config.get('src_mac', 'aa:aa:aa:aa:aa:aa')
        self.dst_mac = config.get('dst_mac', 'bb:bb:bb:bb:bb:bb')
        self.dst_port = config.get('dst_port', 80)

    def generate_src_ip(self):
        """Generate a source IP from the pool"""
        # Use a pool of /16 (65536 IPs) to simulate many clients
        octet3 = random.randint(0, 255)
        octet4 = random.randint(1, 254)
        return f"{self.src_ip_base}{octet3}.{octet4}"

    def generate_src_port(self):
        """Generate ephemeral source port"""
        return random.randint(32768, 65535)

    def select_http_method(self):
        """Select HTTP method based on realistic distribution"""
        rand = random.random()
        cumulative = 0.0
        for method, prob in self.patterns.HTTP_METHODS:
            cumulative += prob
            if rand <= cumulative:
                return method
        return "GET"

    def select_request_size(self):
        """Select request body size based on distribution"""
        rand = random.random()
        cumulative = 0.0
        for size, prob in self.patterns.REQUEST_SIZES:
            cumulative += prob
            if rand <= cumulative:
                return size
        return 0

    def generate_http_request(self):
        """Generate a realistic HTTP request"""
        method = self.select_http_method()
        path = random.choice(self.patterns.HTTP_PATHS)
        user_agent = random.choice(self.patterns.USER_AGENTS)
        accept = random.choice(self.patterns.ACCEPT_HEADERS)

        # Build HTTP request
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {self.dst_ip}\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += f"Accept: {accept}\r\n"
        request += "Accept-Encoding: gzip, deflate\r\n"
        request += "Accept-Language: en-US,en;q=0.9\r\n"
        request += "Connection: keep-alive\r\n"

        # Add body for POST/PUT requests
        body = ""
        if method in ["POST", "PUT"]:
            content_type = random.choice(self.patterns.CONTENT_TYPES)
            request += f"Content-Type: {content_type}\r\n"

            body_size = self.select_request_size()
            if body_size > 0:
                if content_type == "application/json":
                    # Generate JSON payload
                    body = json.dumps({
                        "user_id": random.randint(1000, 9999),
                        "timestamp": time.time(),
                        "data": "x" * (body_size - 100)  # Padding
                    })
                elif content_type == "application/x-www-form-urlencoded":
                    # Generate form data
                    body = f"username=user{random.randint(1000,9999)}&password=pass123&data={'x'*(body_size-50)}"
                else:
                    # Generic payload
                    body = "x" * body_size

                request += f"Content-Length: {len(body)}\r\n"

        request += "\r\n"
        if body:
            request += body

        return request, method

    def create_http_packet(self, seq_num=None):
        """Create a complete HTTP packet"""
        src_ip = self.generate_src_ip()
        src_port = self.generate_src_port()

        # Generate HTTP request
        http_request, method = self.generate_http_request()

        # Create packet layers
        if seq_num is None:
            seq_num = random.randint(1000000, 9999999)

        pkt = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=src_ip, dst=self.dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=self.dst_port,
                  flags='PA', seq=seq_num, ack=1) / \
              Raw(load=http_request)

        # Update statistics
        self.stats['total_packets'] += 1
        self.stats[f'method_{method}'] += 1
        self.stats['total_bytes'] += len(pkt)

        return pkt

    def create_tcp_handshake(self, src_ip, src_port):
        """Create TCP 3-way handshake packets (SYN, SYN-ACK, ACK)"""
        packets = []

        # SYN
        syn = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=src_ip, dst=self.dst_ip) / \
              TCP(sport=src_port, dport=self.dst_port, flags='S', seq=1000)
        packets.append(syn)

        # SYN-ACK (response from server)
        synack = Ether(src=self.dst_mac, dst=self.src_mac) / \
                 IP(src=self.dst_ip, dst=src_ip) / \
                 TCP(sport=self.dst_port, dport=src_port, flags='SA', seq=2000, ack=1001)
        packets.append(synack)

        # ACK
        ack = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=src_ip, dst=self.dst_ip) / \
              TCP(sport=src_port, dport=self.dst_port, flags='A', seq=1001, ack=2001)
        packets.append(ack)

        self.stats['tcp_handshakes'] += 1
        return packets

    def generate_session(self, num_requests=None):
        """Generate a complete HTTP session (handshake + requests + teardown)"""
        if num_requests is None:
            # Realistic session: 1-20 requests per session
            num_requests = random.randint(1, 20)

        src_ip = self.generate_src_ip()
        src_port = self.generate_src_port()

        session_packets = []

        # TCP handshake
        session_packets.extend(self.create_tcp_handshake(src_ip, src_port))

        # HTTP requests
        seq_num = 1001
        for _ in range(num_requests):
            # Create HTTP request
            http_request, method = self.generate_http_request()

            pkt = Ether(src=self.src_mac, dst=self.dst_mac) / \
                  IP(src=src_ip, dst=self.dst_ip, ttl=64) / \
                  TCP(sport=src_port, dport=self.dst_port,
                      flags='PA', seq=seq_num) / \
                  Raw(load=http_request)

            session_packets.append(pkt)
            seq_num += len(http_request)

            self.stats[f'method_{method}'] += 1

            # Simulate server response (ACK)
            # In real traffic, there would be response data, but we simplify here
            ack_pkt = Ether(src=self.dst_mac, dst=self.src_mac) / \
                      IP(src=self.dst_ip, dst=src_ip) / \
                      TCP(sport=self.dst_port, dport=src_port, flags='A', ack=seq_num)
            session_packets.append(ack_pkt)

            # Delay between requests (think time)
            time_delay = random.uniform(0.001, 0.1)  # 1-100ms

        # TCP teardown (FIN)
        fin = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=src_ip, dst=self.dst_ip) / \
              TCP(sport=src_port, dport=self.dst_port, flags='FA', seq=seq_num)
        session_packets.append(fin)

        self.stats['total_packets'] += len(session_packets)
        self.stats['sessions'] += 1
        self.session_counter += 1

        return session_packets

    def generate_traffic(self, num_sessions, output_file=None):
        """Generate benign traffic with specified number of sessions"""
        print(f"Generating {num_sessions} benign HTTP sessions...")

        start_time = time.time()
        all_packets = []

        for i in range(num_sessions):
            session_pkts = self.generate_session()
            all_packets.extend(session_pkts)

            if (i + 1) % 1000 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"Generated {i+1}/{num_sessions} sessions ({rate:.2f} sessions/sec)")

        elapsed = time.time() - start_time
        print(f"Generated {len(all_packets)} packets in {elapsed:.2f} seconds")
        print(f"Average: {len(all_packets)/elapsed:.2f} packets/sec")

        # Save to PCAP if output file specified
        if output_file:
            print(f"Saving to {output_file}...")
            wrpcap(output_file, all_packets)
            print(f"Saved {len(all_packets)} packets")

        self.packets = all_packets
        return all_packets

    def print_stats(self):
        """Print traffic generation statistics"""
        print("\n=== Benign Traffic Statistics ===")
        print(f"Total Sessions:     {self.stats['sessions']}")
        print(f"Total Packets:      {self.stats['total_packets']}")
        print(f"Total Bytes:        {self.stats['total_bytes']:,}")
        print(f"Total MB:           {self.stats['total_bytes']/1024/1024:.2f}")
        print(f"TCP Handshakes:     {self.stats['tcp_handshakes']}")
        print("\nHTTP Methods:")
        for method, _ in BenignTrafficPatterns.HTTP_METHODS:
            count = self.stats.get(f'method_{method}', 0)
            if count > 0:
                pct = (count / self.stats['sessions']) * 100
                print(f"  {method:8s}: {count:8d} ({pct:5.2f}%)")
        print("=" * 40)

    def save_stats(self, filename):
        """Save statistics to JSON file"""
        stats_dict = dict(self.stats)
        stats_dict['timestamp'] = datetime.now().isoformat()
        stats_dict['config'] = self.config

        with open(filename, 'w') as f:
            json.dump(stats_dict, f, indent=2)

        print(f"Statistics saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description='Benign HTTP Traffic Dataset Generator')
    parser.add_argument('-n', '--num-sessions', type=int, default=100000,
                        help='Number of HTTP sessions to generate (default: 100000)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output PCAP file (default: benign_traffic_<timestamp>.pcap)')
    parser.add_argument('--dst-ip', type=str, default='10.0.0.1',
                        help='Destination IP address (default: 10.0.0.1)')
    parser.add_argument('--dst-mac', type=str, default='bb:bb:bb:bb:bb:bb',
                        help='Destination MAC address')
    parser.add_argument('--src-ip-base', type=str, default='192.168.',
                        help='Source IP base (default: 192.168.)')
    parser.add_argument('--dst-port', type=int, default=80,
                        help='Destination port (default: 80)')
    parser.add_argument('--stats-file', type=str, default=None,
                        help='Save statistics to JSON file')

    args = parser.parse_args()

    # Setup output file
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'benign_traffic_{timestamp}.pcap'

    # Setup stats file
    if args.stats_file is None:
        base_name = os.path.splitext(args.output)[0]
        args.stats_file = f'{base_name}_stats.json'

    # Configuration
    config = {
        'dst_ip': args.dst_ip,
        'dst_mac': args.dst_mac,
        'src_ip_base': args.src_ip_base,
        'dst_port': args.dst_port,
        'num_sessions': args.num_sessions
    }

    print("=== Benign HTTP Traffic Dataset Generator ===")
    print(f"Configuration:")
    print(f"  Sessions:        {args.num_sessions:,}")
    print(f"  Destination IP:  {args.dst_ip}")
    print(f"  Destination MAC: {args.dst_mac}")
    print(f"  Source IP Base:  {args.src_ip_base}x.x")
    print(f"  Destination Port:{args.dst_port}")
    print(f"  Output File:     {args.output}")
    print(f"  Stats File:      {args.stats_file}")
    print()

    # Generate traffic
    generator = BenignTrafficGenerator(config)
    generator.generate_traffic(args.num_sessions, args.output)

    # Print and save statistics
    generator.print_stats()
    generator.save_stats(args.stats_file)

    print(f"\nDataset generation complete!")
    print(f"PCAP file: {args.output}")
    print(f"Stats file: {args.stats_file}")


if __name__ == '__main__':
    main()
