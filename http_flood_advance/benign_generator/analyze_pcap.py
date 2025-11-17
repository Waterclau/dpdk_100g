#!/usr/bin/env python3
"""
Analizador de PCAPs de tráfico baseline
Muestra estadísticas y verifica la calidad del tráfico generado
"""

import sys
import argparse
from collections import Counter, defaultdict

try:
    from scapy.all import *
except ImportError:
    print("Error: Scapy no está instalado")
    print("Instalar con: pip install scapy")
    sys.exit(1)

def analyze_pcap(pcap_file, max_packets=None, verbose=False):
    """Analiza un PCAP y muestra estadísticas"""

    print(f"[*] Analizando: {pcap_file}\n")

    # Contadores
    total_packets = 0
    ip_srcs = Counter()
    ip_dsts = Counter()
    tcp_sports = Counter()
    tcp_dports = Counter()
    http_methods = Counter()
    http_paths = Counter()
    http_hosts = Counter()
    user_agents = Counter()

    packet_sizes = []
    protocols = Counter()

    # Leer PCAP
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error leyendo PCAP: {e}")
        sys.exit(1)

    total_in_file = len(packets)
    packets_to_analyze = packets[:max_packets] if max_packets else packets

    print(f"[*] Paquetes en archivo: {total_in_file}")
    if max_packets and max_packets < total_in_file:
        print(f"[*] Analizando primeros: {max_packets}\n")
    else:
        print(f"[*] Analizando todos los paquetes\n")

    # Analizar cada paquete
    for i, pkt in enumerate(packets_to_analyze):
        total_packets += 1

        # Tamaño
        packet_sizes.append(len(pkt))

        # Protocolo Ethernet
        if pkt.haslayer(Ether):
            protocols['Ethernet'] += 1

        # IP
        if pkt.haslayer(IP):
            protocols['IP'] += 1
            ip_srcs[pkt[IP].src] += 1
            ip_dsts[pkt[IP].dst] += 1

        # TCP
        if pkt.haslayer(TCP):
            protocols['TCP'] += 1
            tcp_sports[pkt[TCP].sport] += 1
            tcp_dports[pkt[TCP].dport] += 1

            # HTTP (buscar en Raw payload)
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')

                # Detectar método HTTP
                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                    lines = payload.split('\r\n')
                    if len(lines) > 0:
                        request_line = lines[0].split(' ')
                        if len(request_line) >= 2:
                            method = request_line[0]
                            path = request_line[1]
                            http_methods[method] += 1
                            http_paths[path] += 1

                    # Host header
                    for line in lines[1:]:
                        if line.startswith('Host: '):
                            host = line.split('Host: ')[1].strip()
                            http_hosts[host] += 1
                        elif line.startswith('User-Agent: '):
                            ua = line.split('User-Agent: ')[1].strip()
                            # Simplificar UA
                            if 'Chrome' in ua:
                                user_agents['Chrome'] += 1
                            elif 'Firefox' in ua:
                                user_agents['Firefox'] += 1
                            elif 'Safari' in ua:
                                user_agents['Safari'] += 1
                            else:
                                user_agents['Other'] += 1

        if verbose and (i + 1) % 10000 == 0:
            print(f"[*] Analizados {i + 1}/{len(packets_to_analyze)} paquetes...")

    # Estadísticas generales
    print("\n" + "="*60)
    print(" ESTADÍSTICAS GENERALES")
    print("="*60)
    print(f"Total paquetes:        {total_packets}")
    print(f"Tamaño promedio:       {sum(packet_sizes) / len(packet_sizes):.2f} bytes")
    print(f"Tamaño mínimo:         {min(packet_sizes)} bytes")
    print(f"Tamaño máximo:         {max(packet_sizes)} bytes")

    # Protocolos
    print(f"\nProtocolos:")
    for proto, count in protocols.most_common():
        percentage = (count / total_packets) * 100
        print(f"  {proto:15} : {count:8} ({percentage:5.1f}%)")

    # IPs destino
    print(f"\nIPs Destino:")
    for ip, count in ip_dsts.most_common(10):
        percentage = (count / total_packets) * 100
        print(f"  {ip:15} : {count:8} ({percentage:5.1f}%)")

    # IPs origen (top 10)
    print(f"\nIPs Origen (Top 10):")
    for ip, count in ip_srcs.most_common(10):
        percentage = (count / total_packets) * 100
        print(f"  {ip:15} : {count:8} ({percentage:5.1f}%)")

    print(f"\nTotal IPs origen únicas: {len(ip_srcs)}")

    # Puertos TCP
    print(f"\nPuertos TCP Destino (Top 5):")
    for port, count in tcp_dports.most_common(5):
        percentage = (count / total_packets) * 100
        print(f"  {port:6} : {count:8} ({percentage:5.1f}%)")

    # HTTP
    if http_methods:
        print(f"\n" + "="*60)
        print(" ESTADÍSTICAS HTTP")
        print("="*60)

        total_http = sum(http_methods.values())
        print(f"Total peticiones HTTP: {total_http}")

        print(f"\nMétodos HTTP:")
        for method, count in http_methods.most_common():
            percentage = (count / total_http) * 100
            print(f"  {method:10} : {count:8} ({percentage:5.1f}%)")

        print(f"\nPaths más comunes (Top 15):")
        for path, count in http_paths.most_common(15):
            percentage = (count / total_http) * 100
            path_short = path[:40] + '...' if len(path) > 40 else path
            print(f"  {path_short:43} : {count:6} ({percentage:4.1f}%)")

        print(f"\nHosts (Top 10):")
        for host, count in http_hosts.most_common(10):
            percentage = (count / total_http) * 100
            print(f"  {host:30} : {count:6} ({percentage:4.1f}%)")

        print(f"\nUser-Agents:")
        for ua, count in user_agents.most_common():
            percentage = (count / total_http) * 100
            print(f"  {ua:15} : {count:6} ({percentage:4.1f}%)")

    # Distribución de categorías (estimada)
    print(f"\n" + "="*60)
    print(" DISTRIBUCIÓN ESTIMADA DE CATEGORÍAS")
    print("="*60)

    categories = {
        'Homepage': 0,
        'API': 0,
        'Static': 0,
        'Dynamic': 0,
        'Realtime': 0,
        'Other': 0
    }

    for path, count in http_paths.items():
        if path in ['/', '/index.html', '/home', '/main']:
            categories['Homepage'] += count
        elif '/api/' in path:
            categories['API'] += count
        elif any(ext in path for ext in ['.css', '.js', '.png', '.jpg', '.woff', '.ico']):
            categories['Static'] += count
        elif any(word in path for word in ['/search', '/products/', '/user/', '/forms/']):
            categories['Dynamic'] += count
        elif any(word in path for word in ['/ws/', '/poll/']):
            categories['Realtime'] += count
        else:
            categories['Other'] += count

    total_categorized = sum(categories.values())
    if total_categorized > 0:
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_categorized) * 100
            print(f"  {category:15} : {count:6} ({percentage:5.1f}%)")

    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description='Analiza PCAPs de tráfico baseline HTTP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Analizar PCAP completo
  python analyze_pcap.py baseline_traffic.pcap

  # Analizar solo primeros 10K paquetes
  python analyze_pcap.py baseline_traffic.pcap -n 10000

  # Modo verbose
  python analyze_pcap.py baseline_traffic.pcap -v
        """
    )

    parser.add_argument('pcap_file', help='Archivo PCAP a analizar')
    parser.add_argument('-n', '--max-packets', type=int, default=None,
                        help='Número máximo de paquetes a analizar (default: todos)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Mostrar progreso')

    args = parser.parse_args()

    # Validar archivo
    if not os.path.exists(args.pcap_file):
        print(f"Error: Archivo no encontrado: {args.pcap_file}")
        sys.exit(1)

    # Analizar
    analyze_pcap(args.pcap_file, args.max_packets, args.verbose)

if __name__ == '__main__':
    main()
