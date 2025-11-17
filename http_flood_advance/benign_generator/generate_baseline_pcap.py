#!/usr/bin/env python3
"""
Generador de PCAPs de Tráfico HTTP Baseline Realista
Crea archivos PCAP con tráfico HTTP normal para usar como baseline
Diseñado para simulación de ataques HTTP flood
"""

import sys
import random
import argparse
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTP
except ImportError:
    print("Error: Scapy no está instalado")
    print("Instalar con: pip install scapy")
    sys.exit(1)

# Configuración de IPs y MACs (Controlador -> Monitor)
DEFAULT_SRC_IP = "192.168.1.0"  # Base IP, se randomiza
DEFAULT_DST_IP = "10.0.0.1"     # Monitor
DEFAULT_SRC_MAC = "00:11:22:33:44:55"
DEFAULT_DST_MAC = "04:3f:72:ac:cd:e7"

# Plantillas de peticiones HTTP realistas
# Distribución basada en patrones de tráfico web normal
HTTP_REQUESTS = {
    # Homepage y recursos principales (30%)
    'homepage': [
        {'method': 'GET', 'path': '/', 'host': 'www.example.com', 'weight': 10},
        {'method': 'GET', 'path': '/index.html', 'host': 'www.example.com', 'weight': 8},
        {'method': 'GET', 'path': '/home', 'host': 'example.com', 'weight': 7},
        {'method': 'GET', 'path': '/main', 'host': 'www.site.com', 'weight': 5},
    ],

    # API endpoints (25%)
    'api': [
        {'method': 'GET', 'path': '/api/v1/users', 'host': 'api.example.com', 'weight': 8},
        {'method': 'GET', 'path': '/api/v1/products', 'host': 'api.example.com', 'weight': 7},
        {'method': 'POST', 'path': '/api/v1/auth', 'host': 'api.example.com', 'weight': 5},
        {'method': 'GET', 'path': '/api/v2/data', 'host': 'api.example.com', 'weight': 5},
    ],

    # Recursos estáticos (25%)
    'static': [
        {'method': 'GET', 'path': '/static/css/style.css', 'host': 'cdn.example.com', 'weight': 6},
        {'method': 'GET', 'path': '/static/js/main.js', 'host': 'cdn.example.com', 'weight': 6},
        {'method': 'GET', 'path': '/images/logo.png', 'host': 'cdn.example.com', 'weight': 5},
        {'method': 'GET', 'path': '/static/fonts/roboto.woff2', 'host': 'cdn.example.com', 'weight': 4},
        {'method': 'GET', 'path': '/favicon.ico', 'host': 'www.example.com', 'weight': 4},
    ],

    # Contenido dinámico (15%)
    'dynamic': [
        {'method': 'GET', 'path': '/search?q=test', 'host': 'www.example.com', 'weight': 5},
        {'method': 'GET', 'path': '/products/12345', 'host': 'shop.example.com', 'weight': 4},
        {'method': 'GET', 'path': '/user/profile', 'host': 'www.example.com', 'weight': 3},
        {'method': 'POST', 'path': '/forms/contact', 'host': 'www.example.com', 'weight': 3},
    ],

    # AJAX/WebSocket handshakes (5%)
    'realtime': [
        {'method': 'GET', 'path': '/ws/notifications', 'host': 'ws.example.com', 'weight': 3},
        {'method': 'GET', 'path': '/poll/updates', 'host': 'api.example.com', 'weight': 2},
    ]
}

# User-Agents realistas
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

# Accept headers
ACCEPT_HEADERS = {
    'html': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'json': 'application/json, text/plain, */*',
    'css': 'text/css,*/*;q=0.1',
    'js': 'application/javascript, */*;q=0.8',
    'image': 'image/webp,image/apng,image/*,*/*;q=0.8',
    'any': '*/*'
}

def get_accept_header(path):
    """Retorna el Accept header apropiado según el tipo de recurso"""
    if '.css' in path:
        return ACCEPT_HEADERS['css']
    elif '.js' in path:
        return ACCEPT_HEADERS['js']
    elif any(ext in path for ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp']):
        return ACCEPT_HEADERS['image']
    elif '/api/' in path:
        return ACCEPT_HEADERS['json']
    else:
        return ACCEPT_HEADERS['html']

def create_weighted_request_pool():
    """Crea un pool de requests ponderado por peso"""
    pool = []
    for category, requests in HTTP_REQUESTS.items():
        for req in requests:
            pool.extend([req] * req['weight'])
    return pool

def generate_http_packet(src_ip, dst_ip, src_mac, dst_mac, request_template, src_port=None):
    """Genera un paquete HTTP sobre TCP/IP"""

    # Randomizar puerto origen si no se especifica
    if src_port is None:
        src_port = random.randint(1024, 65535)

    dst_port = 80  # HTTP

    # Construir headers HTTP
    method = request_template['method']
    path = request_template['path']
    host = request_template['host']

    user_agent = random.choice(USER_AGENTS)
    accept = get_accept_header(path)

    http_headers = f"{method} {path} HTTP/1.1\r\n"
    http_headers += f"Host: {host}\r\n"
    http_headers += f"User-Agent: {user_agent}\r\n"
    http_headers += f"Accept: {accept}\r\n"
    http_headers += "Accept-Language: en-US,en;q=0.9\r\n"
    http_headers += "Accept-Encoding: gzip, deflate\r\n"
    http_headers += "Connection: keep-alive\r\n"

    # POST requests llevan body
    if method == 'POST':
        body = '{"username":"user123","password":"pass456"}'
        http_headers += f"Content-Type: application/json\r\n"
        http_headers += f"Content-Length: {len(body)}\r\n"
        http_headers += f"\r\n{body}"
    else:
        http_headers += "\r\n"

    # Construir paquete
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=src_port, dport=dst_port, flags='PA', seq=random.randint(1000, 100000)) / \
          Raw(load=http_headers)

    return pkt

def generate_baseline_traffic(num_packets, output_file, src_ip_base, dst_ip, src_mac, dst_mac, verbose=False):
    """Genera tráfico HTTP baseline y lo guarda en PCAP"""

    print(f"[*] Generando {num_packets} paquetes HTTP baseline...")
    print(f"[*] Origen: {src_ip_base}/16 -> Destino: {dst_ip}")
    print(f"[*] Output: {output_file}")

    request_pool = create_weighted_request_pool()
    packets = []

    # Generar paquetes
    for i in range(num_packets):
        # Randomizar IP origen dentro de /16
        ip_parts = src_ip_base.split('.')
        src_ip = f"{ip_parts[0]}.{ip_parts[1]}.{random.randint(0, 255)}.{random.randint(1, 254)}"

        # Seleccionar request del pool ponderado
        request_template = random.choice(request_pool)

        # Generar paquete
        pkt = generate_http_packet(src_ip, dst_ip, src_mac, dst_mac, request_template)
        packets.append(pkt)

        if verbose and (i + 1) % 10000 == 0:
            print(f"[*] Generados {i + 1}/{num_packets} paquetes...")

    # Guardar PCAP
    print(f"[*] Guardando PCAP...")
    wrpcap(output_file, packets)

    # Estadísticas
    file_size = os.path.getsize(output_file)
    print(f"\n[✓] PCAP generado exitosamente!")
    print(f"    Archivo: {output_file}")
    print(f"    Paquetes: {num_packets}")
    print(f"    Tamaño: {file_size / 1024 / 1024:.2f} MB")

    # Calcular distribución
    print(f"\n[*] Distribución de requests:")
    category_counts = {cat: 0 for cat in HTTP_REQUESTS.keys()}
    for req in request_pool:
        for cat, reqs in HTTP_REQUESTS.items():
            if req in reqs:
                category_counts[cat] += 1
                break

    total_weight = sum(category_counts.values())
    for cat, count in category_counts.items():
        percentage = (count / total_weight) * 100
        print(f"    {cat:12} : {percentage:5.1f}%")

def main():
    parser = argparse.ArgumentParser(
        description='Generador de PCAP de tráfico HTTP baseline realista',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Generar 100K paquetes (default)
  python generate_baseline_pcap.py

  # Generar 1M paquetes
  python generate_baseline_pcap.py -n 1000000

  # Especificar IPs personalizadas
  python generate_baseline_pcap.py -s 192.168.0.0 -d 10.10.10.1

  # Archivo de salida personalizado
  python generate_baseline_pcap.py -o my_baseline.pcap -n 500000
        """
    )

    parser.add_argument('-n', '--num-packets', type=int, default=100000,
                        help='Número de paquetes a generar (default: 100000)')
    parser.add_argument('-o', '--output', type=str, default='baseline_traffic.pcap',
                        help='Archivo PCAP de salida (default: baseline_traffic.pcap)')
    parser.add_argument('-s', '--src-ip', type=str, default=DEFAULT_SRC_IP,
                        help=f'IP origen base /16 (default: {DEFAULT_SRC_IP})')
    parser.add_argument('-d', '--dst-ip', type=str, default=DEFAULT_DST_IP,
                        help=f'IP destino (default: {DEFAULT_DST_IP})')
    parser.add_argument('--src-mac', type=str, default=DEFAULT_SRC_MAC,
                        help=f'MAC origen (default: {DEFAULT_SRC_MAC})')
    parser.add_argument('--dst-mac', type=str, default=DEFAULT_DST_MAC,
                        help=f'MAC destino (default: {DEFAULT_DST_MAC})')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Modo verbose (mostrar progreso)')

    args = parser.parse_args()

    # Validaciones
    if args.num_packets <= 0:
        print("Error: El número de paquetes debe ser mayor que 0")
        sys.exit(1)

    if args.num_packets > 10000000:
        print("Advertencia: Generar más de 10M paquetes puede tomar mucho tiempo")
        confirm = input("¿Continuar? (y/n): ")
        if confirm.lower() != 'y':
            sys.exit(0)

    # Generar tráfico
    start_time = datetime.now()

    generate_baseline_traffic(
        num_packets=args.num_packets,
        output_file=args.output,
        src_ip_base=args.src_ip,
        dst_ip=args.dst_ip,
        src_mac=args.src_mac,
        dst_mac=args.dst_mac,
        verbose=args.verbose
    )

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Tiempo de generación: {elapsed:.2f} segundos")
    print(f"[*] Tasa: {args.num_packets / elapsed:.0f} paquetes/segundo")

if __name__ == '__main__':
    main()
