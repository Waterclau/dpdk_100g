"""
Configuración del detector DDoS
"""
import json
from pathlib import Path
from typing import Dict, Any


class DetectorConfig:
    """Configuración centralizada del detector"""

    # Parámetros DPDK
    DPDK_LCORE = "0"
    DPDK_PCI_ADDR = "0000:41:00.0"  # Cambiar según tu configuración

    # Parámetros de red
    RX_RING_SIZE = 2048
    NUM_MBUFS = 16383
    MBUF_CACHE_SIZE = 512
    BURST_SIZE = 64

    # Parámetros de detección
    DETECTION_WINDOW_SEC = 1  # Ventana de análisis en segundos
    FEATURE_LOG_INTERVAL = 1   # Intervalo de logging de features

    # Umbrales de detección
    THRESHOLDS = {
        'pps_threshold': 100000,
        'gbps_threshold': 10.0,
        'syn_ratio_threshold': 0.7,
        'udp_ratio_threshold': 0.8,
        'frag_ratio_threshold': 0.3,
        'entropy_threshold_low': 3.0,
        'small_packet_ratio': 0.6,
    }

    # Sketches
    SKETCH_CONFIG = {
        'count_min': {
            'width': 2048,
            'depth': 4,
        },
        'hyperloglog': {
            'precision': 14,
        },
        'bloom_filter': {
            'size': 1000000,
            'num_hashes': 7,
        }
    }

    # Paths de salida
    OUTPUT_DIR = Path("/local/logs")
    DETECTION_LOG = OUTPUT_DIR / "detection.log"
    ML_FEATURES_LOG = OUTPUT_DIR / "ml_features.csv"
    ALERTS_LOG = OUTPUT_DIR / "alerts.log"

    # Configuración de ML
    ML_CONFIG = {
        'model_path': '/local/models/xgboost_detector.pkl',
        'threshold': 0.5,
        'features': [
            'gbps', 'pps', 'avg_pkt_size', 'std_dev',
            'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'syn_ratio', 'ack_ratio', 'rst_ratio', 'fin_ratio',
            'frag_ratio', 'small_pkt_ratio',
            'entropy_src_ip', 'entropy_dst_port',
            'unique_src_ips', 'unique_dst_ports',
            'syn_per_sec', 'ack_per_sec'
        ]
    }

    @classmethod
    def create_output_dirs(cls):
        """Crea directorios de salida"""
        cls.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
