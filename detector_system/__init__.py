"""
DDoS Detector - Sistema de detección en tiempo real con DPDK + ML
"""

__version__ = '2.0.0'

from .feature_extractor import FeatureExtractor
from .model_inferencer import ModelInferencer
from .config import DetectorConfig

__all__ = [
    'FeatureExtractor',
    'ModelInferencer',
    'DetectorConfig',
]
