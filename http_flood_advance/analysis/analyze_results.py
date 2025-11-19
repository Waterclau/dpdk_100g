#!/usr/bin/env python3
"""
HTTP Flood Attack Analysis
Analiza los resultados del detector HTTP Flood y genera metricas y graficas
"""

import re
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import numpy as np
import os

class HTTPFloodAnalyzer:
    def __init__(self, log_file, output_dir, avg_packet_size=700, link_capacity_gbps=100):
        self.log_file = log_file
        self.output_dir = output_dir
        self.snapshots = []
        self.avg_packet_size = avg_packet_size  # bytes
        self.link_capacity_gbps = link_capacity_gbps  # Gbps

        # Crear directorio de salida si no existe
        os.makedirs(output_dir, exist_ok=True)

        self.parse_log()

    def pps_to_gbps(self, pps):
        """Convierte paquetes por segundo a Gbps"""
        # Gbps = (pps * packet_size_bytes * 8) / 1e9
        return (pps * self.avg_packet_size * 8) / 1e9

    def calculate_link_utilization(self, gbps):
        """Calcula el porcentaje de utilizacion del enlace"""
        return (gbps / self.link_capacity_gbps) * 100

    def parse_log(self):
        """Parse el archivo de log y extrae las estadisticas"""
        with open(self.log_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Buscar todas las secciones de estadisticas
        stats_sections = re.split(r'╔═+╗\n║\s+HTTP FLOOD DETECTOR - STATISTICS\s+║', content)[1:]

        for i, section in enumerate(stats_sections):
            snapshot = self.parse_snapshot(section, i)
            if snapshot:
                self.snapshots.append(snapshot)

    def parse_snapshot(self, section, index):
        """Parse un snapshot individual de estadisticas"""
        snapshot = {'index': index, 'interval': (index + 1) * 5}  # 5 segundos por intervalo

        # Total packets
        match = re.search(r'Total packets:\s+(\d+)', section)
        if match:
            snapshot['total_packets'] = int(match.group(1))

        # HTTP packets
        match = re.search(r'HTTP packets:\s+(\d+)', section)
        if match:
            snapshot['http_packets'] = int(match.group(1))

        # Baseline packets
        match = re.search(r'Baseline \(192\.168\):\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['baseline_packets'] = int(match.group(1))
            snapshot['baseline_percent'] = float(match.group(2))

        # Attack packets
        match = re.search(r'Attack \(203\.0\.113\):\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['attack_packets'] = int(match.group(1))
            snapshot['attack_percent'] = float(match.group(2))

        # Unique IPs
        match = re.search(r'Unique IPs:\s+(\d+)', section)
        if match:
            snapshot['unique_ips'] = int(match.group(1))

        # Heavy hitters
        match = re.search(r'Heavy hitters:\s+(\d+)', section)
        if match:
            snapshot['heavy_hitters'] = int(match.group(1))

        # HTTP Methods
        match = re.search(r'GET:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['get_count'] = int(match.group(1))
            snapshot['get_percent'] = float(match.group(2))

        match = re.search(r'POST:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['post_count'] = int(match.group(1))
            snapshot['post_percent'] = float(match.group(2))

        # URL Concentration
        match = re.search(r'Top URL count:\s+(\d+)\s+\(([\d.]+)%\)', section)
        if match:
            snapshot['top_url_count'] = int(match.group(1))
            snapshot['top_url_percent'] = float(match.group(2))

        # Alert level
        match = re.search(r'Alert level:\s+(\w+)', section)
        if match:
            snapshot['alert_level'] = match.group(1)

        # Alert reason
        match = re.search(r'Reason:\s+(.+?)(?:\n|$)', section)
        if match:
            snapshot['alert_reason'] = match.group(1).strip()
        else:
            snapshot['alert_reason'] = 'None'

        return snapshot if snapshot.get('total_packets') else None

    def calculate_metrics(self):
        """Calcula metricas generales del experimento"""
        if not self.snapshots:
            return {}

        # Fase de baseline (antes del ataque)
        baseline_phase = [s for s in self.snapshots if s.get('attack_percent', 0) == 0]

        # Fase de ataque
        attack_phase = [s for s in self.snapshots if s.get('attack_percent', 0) > 0]

        metrics = {
            'total_snapshots': len(self.snapshots),
            'baseline_snapshots': len(baseline_phase),
            'attack_snapshots': len(attack_phase),
        }

        if baseline_phase:
            last_baseline = baseline_phase[-1]
            metrics['baseline_total_packets'] = last_baseline['total_packets']
            metrics['baseline_avg_pps'] = last_baseline['total_packets'] / last_baseline['interval']
            metrics['baseline_unique_ips'] = last_baseline['unique_ips']

            # Calcular Gbps y utilizacion del enlace para baseline
            metrics['baseline_gbps'] = self.pps_to_gbps(metrics['baseline_avg_pps'])
            metrics['baseline_link_utilization'] = self.calculate_link_utilization(metrics['baseline_gbps'])

        if attack_phase:
            first_attack = attack_phase[0]
            last_attack = attack_phase[-1]

            # Paquetes de ataque
            total_attack_packets = last_attack.get('attack_packets', 0)
            attack_duration = last_attack['interval'] - first_attack['interval'] + 5

            metrics['attack_start_time'] = first_attack['interval']
            metrics['attack_duration'] = attack_duration
            metrics['total_attack_packets'] = total_attack_packets
            metrics['attack_avg_pps'] = total_attack_packets / attack_duration if attack_duration > 0 else 0

            # Calcular Gbps y utilizacion del enlace para ataque
            metrics['attack_gbps'] = self.pps_to_gbps(metrics['attack_avg_pps'])
            metrics['attack_link_utilization'] = self.calculate_link_utilization(metrics['attack_gbps'])

            # Calcular total durante ataque (baseline + attack)
            # Obtener PPS total promedio durante fase de ataque
            total_pps_during_attack = []
            for i, s in enumerate(attack_phase):
                if i == 0:
                    prev_total = baseline_phase[-1]['total_packets'] if baseline_phase else 0
                else:
                    prev_total = attack_phase[i-1]['total_packets']
                pps = (s['total_packets'] - prev_total) / 5
                total_pps_during_attack.append(pps)

            metrics['total_avg_pps_during_attack'] = np.mean(total_pps_during_attack) if total_pps_during_attack else 0
            metrics['total_gbps_during_attack'] = self.pps_to_gbps(metrics['total_avg_pps_during_attack'])
            metrics['total_link_utilization_during_attack'] = self.calculate_link_utilization(metrics['total_gbps_during_attack'])

            # Porcentaje maximo de ataque
            metrics['max_attack_percent'] = max(s.get('attack_percent', 0) for s in attack_phase)

            # Tiempo hasta primera deteccion
            first_detection = next((s for s in self.snapshots if s.get('alert_level') != 'NONE'), None)
            if first_detection:
                metrics['time_to_detection'] = first_detection['interval']
                metrics['detection_alert_level'] = first_detection['alert_level']

            # Alertas generadas
            alert_counts = {'NONE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0}
            for s in self.snapshots:
                level = s.get('alert_level', 'NONE')
                alert_counts[level] = alert_counts.get(level, 0) + 1

            metrics['alert_counts'] = alert_counts

            # Heavy hitters maximos
            metrics['max_heavy_hitters'] = max(s.get('heavy_hitters', 0) for s in self.snapshots)

        return metrics

    def print_metrics(self):
        """Imprime las metricas calculadas"""
        metrics = self.calculate_metrics()

        print("\n" + "="*80)
        print("METRICAS DE ANALISIS - HTTP FLOOD ATTACK")
        print("="*80)

        print("\n[RESUMEN GENERAL]")
        print(f"  Total de snapshots:           {metrics.get('total_snapshots', 0)}")
        print(f"  Snapshots baseline:           {metrics.get('baseline_snapshots', 0)}")
        print(f"  Snapshots con ataque:         {metrics.get('attack_snapshots', 0)}")

        print("\n[TRAFICO BASELINE]")
        print(f"  Total paquetes:               {metrics.get('baseline_total_packets', 0):,}")
        print(f"  Promedio pps:                 {metrics.get('baseline_avg_pps', 0):,.0f}")
        print(f"  IPs unicas:                   {metrics.get('baseline_unique_ips', 0):,}")

        print("\n[ATAQUE HTTP FLOOD]")
        print(f"  Tiempo de inicio:             {metrics.get('attack_start_time', 0)} segundos")
        print(f"  Duracion del ataque:          {metrics.get('attack_duration', 0)} segundos")
        print(f"  Total paquetes de ataque:     {metrics.get('total_attack_packets', 0):,}")
        print(f"  Promedio pps (ataque):        {metrics.get('attack_avg_pps', 0):,.0f}")
        print(f"  Porcentaje maximo de ataque:  {metrics.get('max_attack_percent', 0):.1f}%")

        print("\n[DETECCION]")
        if metrics.get('time_to_detection'):
            print(f"  Tiempo hasta deteccion:       {metrics.get('time_to_detection', 0)} segundos")
            print(f"  Nivel de alerta inicial:      {metrics.get('detection_alert_level', 'N/A')}")
        else:
            print(f"  No se detecto ataque")

        print(f"  Heavy hitters maximos:        {metrics.get('max_heavy_hitters', 0):,}")

        print("\n[ALERTAS GENERADAS]")
        alert_counts = metrics.get('alert_counts', {})
        for level in ['NONE', 'LOW', 'MEDIUM', 'HIGH']:
            count = alert_counts.get(level, 0)
            print(f"  {level:8s}: {count:3d} snapshots")

        print("\n[EFICACIA DEL SISTEMA]")
        if metrics.get('attack_snapshots', 0) > 0:
            detection_rate = (metrics.get('attack_snapshots', 0) - alert_counts.get('NONE', 0)) / metrics.get('attack_snapshots', 1) * 100
            print(f"  Tasa de deteccion:            {detection_rate:.1f}%")

            # Falsos positivos (alertas durante baseline)
            baseline_alerts = sum(1 for s in self.snapshots[:metrics.get('baseline_snapshots', 0)]
                                 if s.get('alert_level', 'NONE') != 'NONE')
            print(f"  Falsos positivos (baseline):  {baseline_alerts}")

            # Precision
            if metrics.get('time_to_detection'):
                response_time = metrics.get('time_to_detection', 0) - metrics.get('attack_start_time', 0)
                print(f"  Tiempo de respuesta:          {response_time} segundos")

        print("="*80 + "\n")

        return metrics

    def plot_traffic_analysis(self):
        """Genera grafica de analisis de trafico"""
        if not self.snapshots:
            print("No hay datos para graficar")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Analisis de Trafico HTTP Flood', fontsize=16, fontweight='bold')

        # Datos para los graficos
        intervals = [s['interval'] for s in self.snapshots]
        total_packets = [s['total_packets'] for s in self.snapshots]
        baseline_packets = [s.get('baseline_packets', 0) for s in self.snapshots]
        attack_packets = [s.get('attack_packets', 0) for s in self.snapshots]
        attack_percent = [s.get('attack_percent', 0) for s in self.snapshots]

        # 1. Paquetes acumulados (baseline vs ataque)
        ax1 = axes[0, 0]
        ax1.plot(intervals, total_packets, 'k-', linewidth=2, label='Total')
        ax1.fill_between(intervals, baseline_packets, alpha=0.3, color='green', label='Baseline')
        ax1.fill_between(intervals, baseline_packets, total_packets, alpha=0.3, color='red', label='Ataque')
        ax1.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax1.set_ylabel('Paquetes Acumulados', fontsize=12)
        ax1.set_title('Distribucion de Trafico: Baseline vs Ataque', fontsize=14, fontweight='bold')
        ax1.legend(loc='upper left')
        ax1.grid(True, alpha=0.3)
        ax1.ticklabel_format(style='plain', axis='y')

        # 2. Porcentaje de trafico de ataque
        ax2 = axes[0, 1]
        colors = ['green' if p == 0 else 'orange' if p < 30 else 'red' for p in attack_percent]
        ax2.bar(intervals, attack_percent, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax2.axhline(y=30, color='red', linestyle='--', linewidth=2, label='Umbral critico (30%)')
        ax2.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax2.set_ylabel('% Trafico de Ataque', fontsize=12)
        ax2.set_title('Intensidad del Ataque a lo Largo del Tiempo', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Tasa de paquetes por segundo (incremental)
        ax3 = axes[1, 0]
        pps_baseline = []
        pps_attack = []
        for i in range(len(self.snapshots)):
            if i == 0:
                pps_baseline.append(baseline_packets[i] / 5)
                pps_attack.append(attack_packets[i] / 5)
            else:
                pps_baseline.append((baseline_packets[i] - baseline_packets[i-1]) / 5)
                pps_attack.append((attack_packets[i] - attack_packets[i-1]) / 5)

        ax3.plot(intervals, pps_baseline, 'g-', linewidth=2, marker='o', markersize=4, label='Baseline PPS')
        ax3.plot(intervals, pps_attack, 'r-', linewidth=2, marker='s', markersize=4, label='Ataque PPS')
        ax3.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax3.set_ylabel('Paquetes por Segundo (PPS)', fontsize=12)
        ax3.set_title('Tasa de Trafico Incremental', fontsize=14, fontweight='bold')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        ax3.ticklabel_format(style='plain', axis='y')

        # 4. Niveles de alerta
        ax4 = axes[1, 1]
        alert_levels = [s.get('alert_level', 'NONE') for s in self.snapshots]
        alert_numeric = []
        for level in alert_levels:
            if level == 'NONE':
                alert_numeric.append(0)
            elif level == 'LOW':
                alert_numeric.append(1)
            elif level == 'MEDIUM':
                alert_numeric.append(2)
            elif level == 'HIGH':
                alert_numeric.append(3)
            else:
                alert_numeric.append(0)

        colors_alert = ['green' if a == 0 else 'yellow' if a == 1 else 'orange' if a == 2 else 'red' for a in alert_numeric]
        ax4.bar(intervals, alert_numeric, width=4, color=colors_alert, alpha=0.7, edgecolor='black')
        ax4.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax4.set_ylabel('Nivel de Alerta', fontsize=12)
        ax4.set_title('Estado de Alertas del Sistema Detector', fontsize=14, fontweight='bold')
        ax4.set_yticks([0, 1, 2, 3])
        ax4.set_yticklabels(['NONE', 'LOW', 'MEDIUM', 'HIGH'])
        ax4.grid(True, alpha=0.3, axis='x')

        # Leyenda personalizada
        none_patch = mpatches.Patch(color='green', alpha=0.7, label='NONE')
        low_patch = mpatches.Patch(color='yellow', alpha=0.7, label='LOW')
        medium_patch = mpatches.Patch(color='orange', alpha=0.7, label='MEDIUM')
        high_patch = mpatches.Patch(color='red', alpha=0.7, label='HIGH')
        ax4.legend(handles=[none_patch, low_patch, medium_patch, high_patch], loc='upper left')

        plt.tight_layout()

        # Guardar grafica
        output_path = os.path.join(self.output_dir, '01_traffic_analysis.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[GRAFICA 1: Analisis de Trafico] - Guardada en {output_path}")

    def plot_detection_metrics(self):
        """Genera grafica de metricas de deteccion"""
        if not self.snapshots:
            print("No hay datos para graficar")
            return

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Metricas de Deteccion HTTP Flood', fontsize=16, fontweight='bold')

        intervals = [s['interval'] for s in self.snapshots]

        # 1. IPs unicas y Heavy Hitters
        ax1 = axes[0, 0]
        unique_ips = [s.get('unique_ips', 0) for s in self.snapshots]
        heavy_hitters = [s.get('heavy_hitters', 0) for s in self.snapshots]

        ax1_twin = ax1.twinx()
        line1 = ax1.plot(intervals, unique_ips, 'b-', linewidth=2, marker='o', markersize=4, label='IPs Unicas')
        line2 = ax1_twin.plot(intervals, heavy_hitters, 'r-', linewidth=2, marker='s', markersize=4, label='Heavy Hitters')

        ax1.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax1.set_ylabel('IPs Unicas', fontsize=12, color='b')
        ax1_twin.set_ylabel('Heavy Hitters', fontsize=12, color='r')
        ax1.set_title('Deteccion de Heavy Hitters', fontsize=14, fontweight='bold')
        ax1.tick_params(axis='y', labelcolor='b')
        ax1_twin.tick_params(axis='y', labelcolor='r')
        ax1.grid(True, alpha=0.3)

        # Combinar leyendas
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc='upper left')

        # 2. Distribucion de metodos HTTP
        ax2 = axes[0, 1]
        get_percent = [s.get('get_percent', 0) for s in self.snapshots]
        post_percent = [s.get('post_percent', 0) for s in self.snapshots]

        ax2.plot(intervals, get_percent, 'g-', linewidth=2, marker='o', markersize=4, label='GET %')
        ax2.plot(intervals, post_percent, 'b-', linewidth=2, marker='s', markersize=4, label='POST %')
        ax2.axhline(y=98, color='red', linestyle='--', linewidth=2, label='Umbral anomalia GET (98%)')
        ax2.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax2.set_ylabel('Porcentaje (%)', fontsize=12)
        ax2.set_title('Distribucion de Metodos HTTP', fontsize=14, fontweight='bold')
        ax2.set_ylim(0, 100)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Concentracion de URLs
        ax3 = axes[1, 0]
        top_url_percent = [s.get('top_url_percent', 0) for s in self.snapshots]

        colors = ['green' if p < 80 else 'red' for p in top_url_percent]
        ax3.bar(intervals, top_url_percent, width=4, color=colors, alpha=0.7, edgecolor='black')
        ax3.axhline(y=80, color='red', linestyle='--', linewidth=2, label='Umbral anomalia (80%)')
        ax3.set_xlabel('Tiempo (segundos)', fontsize=12)
        ax3.set_ylabel('% URL mas frecuente', fontsize=12)
        ax3.set_title('Concentracion de URLs', fontsize=14, fontweight='bold')
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. Resumen de detecciones
        ax4 = axes[1, 1]

        # Contar tipos de deteccion por razon
        detection_types = {
            'Heavy Hitters': 0,
            'Botnet Pattern': 0,
            'High Attack Rate': 0,
            'None': 0
        }

        for s in self.snapshots:
            reason = s.get('alert_reason', 'None')
            if 'HEAVY HITTERS' in reason:
                detection_types['Heavy Hitters'] += 1
            if 'BOTNET PATTERN' in reason:
                detection_types['Botnet Pattern'] += 1
            if 'HIGH ATTACK RATE' in reason:
                detection_types['High Attack Rate'] += 1
            if reason == 'None':
                detection_types['None'] += 1

        labels = list(detection_types.keys())
        sizes = list(detection_types.values())
        colors_pie = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
        explode = (0.1, 0.1, 0.1, 0)

        ax4.pie(sizes, explode=explode, labels=labels, colors=colors_pie, autopct='%1.1f%%',
                shadow=True, startangle=90)
        ax4.set_title('Tipos de Deteccion Activados', fontsize=14, fontweight='bold')

        plt.tight_layout()

        # Guardar grafica
        output_path = os.path.join(self.output_dir, '02_detection_metrics.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[GRAFICA 2: Metricas de Deteccion] - Guardada en {output_path}")

    def plot_attack_effectiveness(self):
        """Genera grafica de efectividad del ataque"""
        metrics = self.calculate_metrics()

        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle('Efectividad del Ataque HTTP Flood', fontsize=16, fontweight='bold')

        # 1. Comparacion baseline vs ataque
        ax1 = axes[0]
        categories = ['Paquetes Totales', 'Tasa Promedio (PPS)']
        baseline_values = [
            metrics.get('baseline_total_packets', 0),
            metrics.get('baseline_avg_pps', 0)
        ]
        attack_values = [
            metrics.get('total_attack_packets', 0),
            metrics.get('attack_avg_pps', 0)
        ]

        x = np.arange(len(categories))
        width = 0.35

        bars1 = ax1.bar(x - width/2, baseline_values, width, label='Baseline', color='green', alpha=0.7)
        bars2 = ax1.bar(x + width/2, attack_values, width, label='Ataque', color='red', alpha=0.7)

        ax1.set_ylabel('Valores', fontsize=12)
        ax1.set_title('Comparacion: Trafico Baseline vs Ataque', fontsize=14, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(categories)
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')

        # Añadir valores encima de las barras
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax1.annotate(f'{height:,.0f}',
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3),
                            textcoords="offset points",
                            ha='center', va='bottom', fontsize=9)

        # 2. Distribucion de alertas
        ax2 = axes[1]
        alert_counts = metrics.get('alert_counts', {})
        labels = list(alert_counts.keys())
        sizes = list(alert_counts.values())
        colors_pie = ['#90ee90', '#ffeb3b', '#ff9800', '#f44336']
        explode = (0, 0.1, 0.1, 0.15)

        wedges, texts, autotexts = ax2.pie(sizes, explode=explode, labels=labels, colors=colors_pie,
                                            autopct='%1.1f%%', shadow=True, startangle=90)

        # Mejorar texto
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(10)

        ax2.set_title('Distribucion de Niveles de Alerta', fontsize=14, fontweight='bold')

        plt.tight_layout()

        # Guardar grafica
        output_path = os.path.join(self.output_dir, '03_attack_effectiveness.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"\n[GRAFICA 3: Efectividad del Ataque] - Guardada en {output_path}")


def main():
    # Rutas
    log_file = r'C:\Users\claud\Comi_archi\MD\codigo\dpdk_100g\results\results_http_flood_1.log'
    output_dir = os.path.join(os.path.dirname(__file__))

    print("\n" + "="*80)
    print("ANALIZADOR DE RESULTADOS - HTTP FLOOD DETECTOR")
    print("="*80)
    print(f"\nArchivo de log: {log_file}")
    print(f"Directorio de salida: {output_dir}")

    # Crear analizador
    analyzer = HTTPFloodAnalyzer(log_file, output_dir)

    # Calcular e imprimir metricas
    metrics = analyzer.print_metrics()

    # Generar graficas
    print("\nGenerando graficas de analisis...\n")
    analyzer.plot_traffic_analysis()
    analyzer.plot_detection_metrics()
    analyzer.plot_attack_effectiveness()

    print("\n" + "="*80)
    print("ANALISIS COMPLETADO")
    print("="*80)
    print(f"\nTodas las graficas han sido guardadas en: {output_dir}")
    print("Archivos generados:")
    print("  - 01_traffic_analysis.png")
    print("  - 02_detection_metrics.png")
    print("  - 03_attack_effectiveness.png\n")


if __name__ == "__main__":
    main()
