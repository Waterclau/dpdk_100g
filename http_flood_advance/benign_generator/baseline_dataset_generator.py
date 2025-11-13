#!/usr/bin/env python3
"""
Realistic Baseline HTTP Traffic Dataset Generator

Generates realistic baseline HTTP traffic patterns that simulate
normal web server behavior for DDoS detection baseline establishment.

Features:
- Realistic traffic patterns (hourly/daily variations)
- Natural request distributions
- Varied session behaviors
- Multiple traffic profiles (low, medium, high, peak)
- Large dataset generation capability
"""

import os
import sys
import time
import random
import argparse
import json
import math
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)


class TrafficProfile:
    """Defines realistic traffic profiles for different scenarios"""

    # Traffic profile definitions (requests per second)
    PROFILES = {
        'very_low': {
            'base_rps': 100,      # 100 req/sec
            'peak_rps': 300,
            'description': 'Very light traffic (small website)'
        },
        'low': {
            'base_rps': 1000,     # 1K req/sec
            'peak_rps': 3000,
            'description': 'Low traffic (personal blog, small business)'
        },
        'medium': {
            'base_rps': 10000,    # 10K req/sec
            'peak_rps': 30000,
            'description': 'Medium traffic (popular website)'
        },
        'high': {
            'base_rps': 50000,    # 50K req/sec
            'peak_rps': 150000,
            'description': 'High traffic (large e-commerce)'
        },
        'very_high': {
            'base_rps': 100000,   # 100K req/sec
            'peak_rps': 300000,
            'description': 'Very high traffic (major platform)'
        }
    }

    @classmethod
    def get_profile(cls, name):
        """Get traffic profile by name"""
        return cls.PROFILES.get(name, cls.PROFILES['medium'])


class RealisticTrafficPatterns:
    """Defines realistic web application traffic patterns"""

    # HTTP paths with realistic distributions
    # Format: (path, weight, method, has_body)
    HTTP_PATHS = [
        # Homepage and main pages (40% of traffic)
        ('/', 0.20, 'GET', False),
        ('/index.html', 0.10, 'GET', False),
        ('/home', 0.05, 'GET', False),
        ('/about', 0.03, 'GET', False),
        ('/contact', 0.02, 'GET', False),

        # API endpoints (25% of traffic)
        ('/api/v1/users', 0.05, 'GET', False),
        ('/api/v1/products', 0.05, 'GET', False),
        ('/api/v1/orders', 0.03, 'GET', False),
        ('/api/v1/auth/login', 0.04, 'POST', True),
        ('/api/v1/search', 0.03, 'POST', True),
        ('/api/v1/profile', 0.03, 'GET', False),
        ('/api/v1/notifications', 0.02, 'GET', False),

        # Static resources (20% of traffic)
        ('/static/css/main.css', 0.05, 'GET', False),
        ('/static/js/app.js', 0.05, 'GET', False),
        ('/static/images/logo.png', 0.04, 'GET', False),
        ('/static/fonts/roboto.woff2', 0.03, 'GET', False),
        ('/favicon.ico', 0.03, 'GET', False),

        # Dynamic content (15% of traffic)
        ('/search', 0.03, 'GET', False),
        ('/category/electronics', 0.03, 'GET', False),
        ('/product/123', 0.03, 'GET', False),
        ('/user/profile', 0.03, 'GET', False),
        ('/cart', 0.02, 'GET', False),
        ('/checkout', 0.01, 'POST', True),
    ]

    # User agents (realistic browser distribution)
    USER_AGENTS = [
        ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', 0.35),
        ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36', 0.15),
        ('Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0', 0.15),
        ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36', 0.10),
        ('Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1', 0.10),
        ('Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1', 0.05),
        ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15', 0.05),
        ('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.6099.43 Mobile Safari/537.36', 0.05),
    ]

    @classmethod
    def select_weighted(cls, items):
        """Select item from weighted list"""
        total_weight = sum(weight for *_, weight in items)
        rand_val = random.random() * total_weight
        cumulative = 0.0

        for *item, weight in items:
            cumulative += weight
            if rand_val <= cumulative:
                return item if len(item) > 1 else item[0]

        # Fallback
        return items[0][:-1] if len(items[0]) > 1 else items[0][0]


class BaselineTrafficGenerator:
    """Generates realistic baseline HTTP traffic"""

    def __init__(self, config):
        self.config = config
        self.patterns = RealisticTrafficPatterns()
        self.stats = defaultdict(int)
        self.packets = []

        # Network configuration
        self.src_ip_base = config.get('src_ip_base', '192.168.')
        self.dst_ip = config.get('dst_ip', '10.0.0.1')
        self.src_mac = config.get('src_mac', 'aa:aa:aa:aa:aa:aa')
        self.dst_mac = config.get('dst_mac', 'bb:bb:bb:bb:bb:bb')
        self.dst_port = config.get('dst_port', 80)

        # Traffic profile
        profile_name = config.get('traffic_profile', 'medium')
        self.profile = TrafficProfile.get_profile(profile_name)

        # Time-based variations
        self.enable_time_variations = config.get('enable_time_variations', True)
        self.simulation_start_hour = config.get('start_hour', 0)

    def generate_src_ip(self):
        """Generate realistic source IP from pool"""
        # Use /16 network (65K IPs) for realistic client distribution
        octet3 = random.randint(0, 255)
        octet4 = random.randint(1, 254)
        return f"{self.src_ip_base}{octet3}.{octet4}"

    def calculate_rate_multiplier(self, elapsed_seconds):
        """
        Calculate rate multiplier based on time of day
        Simulates realistic daily traffic patterns:
        - Low traffic at night (2am-6am): 0.3x
        - Rising in morning (6am-12pm): 0.5x -> 1.0x
        - Peak hours (12pm-6pm): 1.0x -> 1.2x
        - Evening (6pm-11pm): 0.8x -> 0.5x
        - Night (11pm-2am): 0.5x -> 0.3x
        """
        if not self.enable_time_variations:
            return 1.0

        # Calculate simulated hour of day
        hours_elapsed = elapsed_seconds / 3600.0
        simulated_hour = (self.simulation_start_hour + hours_elapsed) % 24

        # Sinusoidal pattern with peaks at 2pm (14:00)
        # Low point at 4am (04:00)
        hour_angle = ((simulated_hour - 4) / 24.0) * 2 * math.pi
        base_variation = 0.6 + 0.4 * math.sin(hour_angle)

        # Add weekday vs weekend variation (simplified)
        day_variation = 1.0
        if random.random() < 0.2:  # 20% chance of "weekend" behavior
            day_variation = 0.7

        # Add random noise (±15%)
        noise = 0.85 + 0.3 * random.random()

        return base_variation * day_variation * noise

    def generate_http_request(self):
        """Generate realistic HTTP request"""
        # Select path with weighted distribution
        path, method, has_body = self.patterns.select_weighted(
            [(p, m, b, w) for p, w, m, b in self.patterns.HTTP_PATHS]
        )

        # Select user agent
        user_agent = self.patterns.select_weighted(self.patterns.USER_AGENTS)

        # Build HTTP request
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {self.dst_ip}\r\n"
        request += f"User-Agent: {user_agent}\r\n"
        request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        request += "Accept-Language: en-US,en;q=0.9\r\n"
        request += "Accept-Encoding: gzip, deflate\r\n"
        request += "Connection: keep-alive\r\n"

        # Add cookies for some requests (60% have cookies)
        if random.random() < 0.6:
            session_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
            request += f"Cookie: session_id={session_id}\r\n"

        # Add body for POST requests
        body = ""
        if has_body and method in ['POST', 'PUT']:
            if 'login' in path:
                body = json.dumps({
                    'email': f'user{random.randint(1000, 9999)}@example.com',
                    'password': 'pass123'
                })
            elif 'search' in path:
                queries = ['laptop', 'phone', 'tablet', 'camera', 'headphones']
                body = json.dumps({'query': random.choice(queries)})
            elif 'checkout' in path:
                body = json.dumps({
                    'cart_id': random.randint(1000, 9999),
                    'payment_method': 'credit_card'
                })
            else:
                body = json.dumps({'data': 'test'})

            request += "Content-Type: application/json\r\n"
            request += f"Content-Length: {len(body)}\r\n"

        request += "\r\n"
        if body:
            request += body

        return request, method, path

    def create_http_packet(self, seq_num):
        """Create a complete HTTP packet"""
        src_ip = self.generate_src_ip()
        src_port = random.randint(32768, 65535)

        # Generate HTTP request
        http_request, method, path = self.generate_http_request()

        # Create packet
        pkt = Ether(src=self.src_mac, dst=self.dst_mac) / \
              IP(src=src_ip, dst=self.dst_ip, ttl=64) / \
              TCP(sport=src_port, dport=self.dst_port,
                  flags='PA', seq=seq_num) / \
              Raw(load=http_request.encode())

        # Update statistics
        self.stats['total_packets'] += 1
        self.stats[f'method_{method}'] += 1
        self.stats[f'path_{path}'] = self.stats.get(f'path_{path}', 0) + 1
        self.stats['total_bytes'] += len(pkt)

        return pkt

    def generate_session(self):
        """Generate a realistic user session"""
        src_ip = self.generate_src_ip()
        src_port = random.randint(32768, 65535)

        # Realistic session: 1-10 requests (most users make 2-5 requests)
        num_requests = random.choices(
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            weights=[0.15, 0.20, 0.20, 0.15, 0.10, 0.08, 0.05, 0.04, 0.02, 0.01],
            k=1
        )[0]

        session_packets = []
        seq_num = random.randint(1000000, 9999999)

        # Generate requests in session
        for _ in range(num_requests):
            http_request, method, path = self.generate_http_request()

            pkt = Ether(src=self.src_mac, dst=self.dst_mac) / \
                  IP(src=src_ip, dst=self.dst_ip, ttl=64) / \
                  TCP(sport=src_port, dport=self.dst_port,
                      flags='PA', seq=seq_num) / \
                  Raw(load=http_request.encode())

            session_packets.append(pkt)
            seq_num += len(http_request)

            self.stats[f'method_{method}'] += 1

        self.stats['total_packets'] += len(session_packets)
        self.stats['sessions'] += 1

        return session_packets

    def generate_baseline_traffic(self, duration_seconds, output_file=None):
        """
        Generate baseline traffic for specified duration

        Args:
            duration_seconds: How long to simulate traffic for
            output_file: Optional PCAP file to save traffic
        """
        print(f"Generating baseline traffic for {duration_seconds} seconds...")
        print(f"Profile: {self.profile['description']}")
        print(f"Base rate: {self.profile['base_rps']} req/sec")
        print(f"Peak rate: {self.profile['peak_rps']} req/sec")

        start_time = time.time()
        all_packets = []

        packets_generated = 0
        elapsed = 0

        while elapsed < duration_seconds:
            # Calculate current rate based on time of day
            rate_multiplier = self.calculate_rate_multiplier(elapsed)
            current_rps = int(self.profile['base_rps'] * rate_multiplier)

            # Generate packets for this second
            packets_this_second = current_rps

            for _ in range(packets_this_second):
                # 70% single packets, 30% as part of session
                if random.random() < 0.7:
                    pkt = self.create_http_packet(packets_generated)
                    all_packets.append(pkt)
                    packets_generated += 1
                else:
                    session_pkts = self.generate_session()
                    all_packets.extend(session_pkts)
                    packets_generated += len(session_pkts)

            elapsed = time.time() - start_time

            # Progress update every 10 seconds
            if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                print(f"  Progress: {int(elapsed)}/{duration_seconds}s - "
                      f"Generated {packets_generated} packets "
                      f"(current rate: {current_rps} rps)")

        total_time = time.time() - start_time
        avg_rate = packets_generated / total_time

        print(f"\nGenerated {packets_generated} packets in {total_time:.2f} seconds")
        print(f"Average rate: {avg_rate:.2f} pps")

        # Save to PCAP if requested
        if output_file:
            print(f"Saving to {output_file}...")
            wrpcap(output_file, all_packets)
            print(f"Saved {len(all_packets)} packets")

        self.packets = all_packets
        return all_packets

    def print_stats(self):
        """Print traffic generation statistics"""
        print("\n=== Baseline Traffic Statistics ===")
        print(f"Profile:            {self.profile['description']}")
        print(f"Total Sessions:     {self.stats['sessions']}")
        print(f"Total Packets:      {self.stats['total_packets']}")
        print(f"Total Bytes:        {self.stats['total_bytes']:,}")
        print(f"Total MB:           {self.stats['total_bytes']/1024/1024:.2f}")

        if self.stats['sessions'] > 0:
            print(f"Avg Packets/Session:{self.stats['total_packets']/self.stats['sessions']:.2f}")

        print("\nHTTP Methods:")
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
        for method in methods:
            count = self.stats.get(f'method_{method}', 0)
            if count > 0:
                pct = (count / self.stats['total_packets']) * 100
                print(f"  {method:8s}: {count:8d} ({pct:5.2f}%)")

        print("\nTop 10 Paths:")
        path_counts = {k: v for k, v in self.stats.items() if k.startswith('path_')}
        top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for path_key, count in top_paths:
            path = path_key.replace('path_', '')
            pct = (count / self.stats['total_packets']) * 100
            print(f"  {path:40s}: {count:6d} ({pct:5.2f}%)")

        print("=" * 50)

    def save_stats(self, filename):
        """Save statistics to JSON file"""
        stats_dict = dict(self.stats)
        stats_dict['timestamp'] = datetime.now().isoformat()
        stats_dict['config'] = self.config
        stats_dict['profile'] = self.profile

        with open(filename, 'w') as f:
            json.dump(stats_dict, f, indent=2)

        print(f"Statistics saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Realistic Baseline HTTP Traffic Dataset Generator'
    )
    parser.add_argument('-d', '--duration', type=int, default=300,
                        help='Duration to simulate in seconds (default: 300 = 5 min)')
    parser.add_argument('-p', '--profile', type=str,
                        choices=['very_low', 'low', 'medium', 'high', 'very_high'],
                        default='medium',
                        help='Traffic profile (default: medium)')
    parser.add_argument('-o', '--output', type=str, default=None,
                        help='Output PCAP file')
    parser.add_argument('--dst-ip', type=str, default='10.0.0.1',
                        help='Destination IP address')
    parser.add_argument('--dst-mac', type=str, default='bb:bb:bb:bb:bb:bb',
                        help='Destination MAC address')
    parser.add_argument('--src-ip-base', type=str, default='192.168.',
                        help='Source IP base (default: 192.168.)')
    parser.add_argument('--dst-port', type=int, default=80,
                        help='Destination port (default: 80)')
    parser.add_argument('--start-hour', type=int, default=8,
                        help='Simulated start hour (0-23, default: 8 = 8am)')
    parser.add_argument('--no-time-variations', action='store_true',
                        help='Disable time-based rate variations')
    parser.add_argument('--stats-file', type=str, default=None,
                        help='Save statistics to JSON file')

    args = parser.parse_args()

    # Setup output file
    if args.output is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f'baseline_traffic_{args.profile}_{timestamp}.pcap'

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
        'traffic_profile': args.profile,
        'enable_time_variations': not args.no_time_variations,
        'start_hour': args.start_hour,
        'duration': args.duration
    }

    print("=== Realistic Baseline Traffic Generator ===")
    print(f"Configuration:")
    print(f"  Duration:        {args.duration} seconds")
    print(f"  Profile:         {args.profile}")
    print(f"  Destination IP:  {args.dst_ip}")
    print(f"  Destination MAC: {args.dst_mac}")
    print(f"  Source IP Base:  {args.src_ip_base}x.x")
    print(f"  Time Variations: {'Enabled' if config['enable_time_variations'] else 'Disabled'}")
    print(f"  Start Hour:      {args.start_hour}:00")
    print(f"  Output File:     {args.output}")
    print()

    # Generate traffic
    generator = BaselineTrafficGenerator(config)
    generator.generate_baseline_traffic(args.duration, args.output)

    # Print and save statistics
    generator.print_stats()
    generator.save_stats(args.stats_file)

    print(f"\nBaseline dataset generation complete!")
    print(f"PCAP file: {args.output}")
    print(f"Stats file: {args.stats_file}")


if __name__ == '__main__':
    main()
