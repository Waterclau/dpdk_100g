#!/usr/bin/env python3
"""
Generador de Ataques HTTP Flood en PCAP
Simula diferentes tipos de ataques HTTP flood para detección con DPDK/OctoSketch

Tipos de ataque:
1. GET Flood: Peticiones GET repetitivas a la misma URL
2. POST Flood: Peticiones POST con payloads
3. Slowloris: Conexiones lentas incompletas
4. Random GET Flood: GETs a URLs aleatorias
5. Mixed Flood: Combinación de varios tipos
"""

import sys
import random
import argparse
import os
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy no está instalado")
    print("Instalar con: pip install scapy")
    sys.exit(1)

# Configuración de red (Atacante -> Monitor)
DEFAULT_SRC_IP = "203.0.113.0"         # Red del atacante
DEFAULT_DST_IP = "10.0.0.1"            # Monitor (víctima)
DEFAULT_SRC_MAC = "aa:bb:cc:dd:ee:ff"  # MAC atacante
DEFAULT_DST_MAC = "0c:42:a1:8c:dd:0c"  # MAC del Monitor

# Patrones de ataque HTTP flood
ATTACK_PATTERNS = {
    'get_flood': {
        'description': 'GET flood a una URL específica',
        'methods': ['GET'],
        'paths': ['/'],  # Misma URL repetida
        'rate_multiplier': 1.0,
    },
    'post_flood': {
        'description': 'POST flood con payloads',
        'methods': ['POST'],
        'paths': ['/login', '/api/auth', '/submit'],
        'rate_multiplier': 0.8,
    },
    'random_get': {
        'description': 'GET flood a URLs aleatorias',
        'methods': ['GET'],
        'paths': 'random',
        'rate_multiplier': 1.2,
    },
    'slowloris': {
        'description': 'Slowloris - conexiones lentas',
        'methods': ['GET'],
        'paths': ['/'],
        'rate_multiplier': 0.3,
        'incomplete': True,
    },
    'mixed': {
        'description': 'Ataque mixto (GET + POST)',
        'methods': ['GET', 'POST'],
        'paths': ['/', '/login', '/api', '/search'],
        'rate_multiplier': 1.5,
    }
}

# URLs maliciosas para random flood
MALICIOUS_PATHS = [
    '/', '/index.php', '/login', '/admin', '/wp-login.php',
    '/administrator', '/phpmyadmin', '/xmlrpc.php', '/wp-admin',
    '/.env', '/config.php', '/backup.sql', '/admin.php',
    '/user/login', '/api/v1/login', '/auth/login', '/signin',
]

# User-Agents típicos de bots/atacantes
MALICIOUS_USER_AGENTS = [
    'Mozilla/5.0',
    'python-requests/2.25.1',
    'curl/7.68.0',
    'Wget/1.20.3',
    'Go-http-client/1.1',
    'Apache-HttpClient/4.5.13',
    '',  # Sin User-Agent
]

def generate_random_path():
    """Genera una URL aleatoria para el ataque"""
    prefixes = ['/', '/api/', '/admin/', '/user/', '/data/']
    suffixes = ['', '.php', '.html', '.asp', '.jsp']

    if random.random() < 0.3:
        return random.choice(MALICIOUS_PATHS)
    else:
        prefix = random.choice(prefixes)
        random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 15)))
        suffix = random.choice(suffixes)
        return f"{prefix}{random_str}{suffix}"

def create_http_flood_packet(src_ip, dst_ip, src_mac, dst_mac, attack_type, src_port=None):
    """Crea un paquete de ataque HTTP flood"""

    if src_port is None:
        src_port = random.randint(1024, 65535)

    dst_port = 80
    pattern = ATTACK_PATTERNS[attack_type]

    # Seleccionar método
    method = random.choice(pattern['methods'])

    # Seleccionar path
    if pattern['paths'] == 'random':
        path = generate_random_path()
    else:
        path = random.choice(pattern['paths'])

    # User-Agent malicioso
    user_agent = random.choice(MALICIOUS_USER_AGENTS)

    # Construir petición HTTP
    http_request = f"{method} {path} HTTP/1.1\r\n"
    http_request += f"Host: {dst_ip}\r\n"

    if user_agent:
        http_request += f"User-Agent: {user_agent}\r\n"

    # Para Slowloris, headers incompletos
    if pattern.get('incomplete', False):
        http_request += "X-Slowloris: "
        # No cerrar la petición
    else:
        if method == 'POST':
            body = f'{{"user":"bot{random.randint(1,9999)}","pass":"attack"}}'
            http_request += "Content-Type: application/json\r\n"
            http_request += f"Content-Length: {len(body)}\r\n"
            http_request += f"\r\n{body}"
        else:
            http_request += "Connection: close\r\n"
            http_request += "\r\n"

    # Construir paquete
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip, id=random.randint(1, 65535)) / \
          TCP(sport=src_port, dport=dst_port, flags='PA',
              seq=random.randint(1000, 100000),
              ack=random.randint(1000, 100000)) / \
          Raw(load=http_request)

    return pkt

def generate_attack_traffic(attack_type, num_packets, output_file,
                           src_ip_base, dst_ip, src_mac, dst_mac,
                           botnet_size=100, verbose=False):
    """Genera tráfico de ataque HTTP flood"""

    print(f"[*] Generando ataque HTTP flood: {attack_type}")
    print(f"[*] Tipo: {ATTACK_PATTERNS[attack_type]['description']}")
    print(f"[*] Paquetes: {num_packets}")
    print(f"[*] Tamaño de botnet: {botnet_size} IPs")
    print(f"[*] Origen: {src_ip_base}/24 -> Destino: {dst_ip}")
    print(f"[*] Output: {output_file}\n")

    packets = []

    # Generar pool de IPs del botnet
    ip_parts = src_ip_base.split('.')
    botnet_ips = []
    for _ in range(botnet_size):
        bot_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{random.randint(1, 254)}"
        botnet_ips.append(bot_ip)

    # Generar paquetes de ataque
    for i in range(num_packets):
        src_ip = random.choice(botnet_ips)
        pkt = create_http_flood_packet(src_ip, dst_ip, src_mac, dst_mac, attack_type)
        packets.append(pkt)

        if verbose and (i + 1) % 10000 == 0:
            print(f"[*] Generados {i + 1}/{num_packets} paquetes...")

    # Guardar PCAP
    print(f"[*] Guardando PCAP...")
    wrpcap(output_file, packets)

    # Estadísticas
    file_size = os.path.getsize(output_file)
    print(f"\n[✓] PCAP de ataque generado exitosamente!")
    print(f"    Archivo: {output_file}")
    print(f"    Paquetes: {num_packets}")
    print(f"    Tamaño: {file_size / 1024 / 1024:.2f} MB")
    print(f"    IPs atacantes: {len(set(botnet_ips))}")

    print(f"\n[*] Características del ataque:")
    pattern = ATTACK_PATTERNS[attack_type]
    print(f"    Métodos HTTP: {', '.join(pattern['methods'])}")
    if pattern['paths'] == 'random':
        print(f"    Paths: Aleatorios (variados)")
    else:
        print(f"    Paths objetivo: {', '.join(pattern['paths'])}")
    print(f"    Intensidad: {pattern['rate_multiplier']}x")

def main():
    parser = argparse.ArgumentParser(
        description='Generador de ataques HTTP flood en PCAP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tipos de ataque:
  get_flood    : GET flood a URL específica
  post_flood   : POST flood a login endpoints
  random_get   : GET flood a URLs aleatorias
  slowloris    : Conexiones lentas incompletas
  mixed        : Ataque mixto (GET + POST)

Ejemplos:
  python generate_http_flood.py -t get_flood -n 100000
  python generate_http_flood.py -t mixed -n 1000000 -b 200 -v
        """
    )

    parser.add_argument('-t', '--type', type=str, required=True,
                        choices=list(ATTACK_PATTERNS.keys()),
                        help='Tipo de ataque HTTP flood')
    parser.add_argument('-n', '--num-packets', type=int, default=100000,
                        help='Número de paquetes (default: 100000)')
    parser.add_argument('-o', '--output', type=str, default='http_flood_attack.pcap',
                        help='Archivo PCAP de salida')
    parser.add_argument('-s', '--src-ip', type=str, default=DEFAULT_SRC_IP,
                        help=f'IP origen base /24 (default: {DEFAULT_SRC_IP})')
    parser.add_argument('-d', '--dst-ip', type=str, default=DEFAULT_DST_IP,
                        help=f'IP destino (default: {DEFAULT_DST_IP})')
    parser.add_argument('--src-mac', type=str, default=DEFAULT_SRC_MAC,
                        help=f'MAC origen (default: {DEFAULT_SRC_MAC})')
    parser.add_argument('--dst-mac', type=str, default=DEFAULT_DST_MAC,
                        help=f'MAC destino (default: {DEFAULT_DST_MAC})')
    parser.add_argument('-b', '--botnet-size', type=int, default=100,
                        help='Tamaño del botnet (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Modo verbose')

    args = parser.parse_args()

    start_time = datetime.now()

    generate_attack_traffic(
        attack_type=args.type,
        num_packets=args.num_packets,
        output_file=args.output,
        src_ip_base=args.src_ip,
        dst_ip=args.dst_ip,
        src_mac=args.src_mac,
        dst_mac=args.dst_mac,
        botnet_size=args.botnet_size,
        verbose=args.verbose
    )

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Tiempo: {elapsed:.2f} segundos")
    print(f"[*] Tasa: {args.num_packets / elapsed:.0f} paquetes/segundo")

if __name__ == '__main__':
    main()
