"""
Attack Generator - Generador modular de PCAPs de ataques DDoS realistas
"""

__version__ = '1.0.0'

from .attacks import ATTACK_GENERATORS
from .generator import AttackPcapGenerator
from .utils import (
    TimestampGenerator,
    DistributionSampler,
    RealisticPayloadGenerator,
    IPGenerator,
    extract_dataset_distributions
)
from .benign_traffic import (
    BenignTrafficGenerator,
    BenignTrafficMixer,
    generate_benign_pcap
)

__all__ = [
    'ATTACK_GENERATORS',
    'AttackPcapGenerator',
    'TimestampGenerator',
    'DistributionSampler',
    'RealisticPayloadGenerator',
    'IPGenerator',
    'extract_dataset_distributions',
    'BenignTrafficGenerator',
    'BenignTrafficMixer',
    'generate_benign_pcap',
]
