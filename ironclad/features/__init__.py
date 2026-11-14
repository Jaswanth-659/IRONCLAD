"""
IRONCLAD Feature Extraction Module.
"""

from ironclad.features.entropy import (
    analyze_payload_cryptography,
    block_entropy,
    chi_squared_uniformity,
    shannon_entropy,
)
from ironclad.features.flow_aggregator import FlowAggregator
from ironclad.features.temporal import (
    calculate_burstiness,
    calculate_inter_arrival_times,
    calculate_jitter,
    extract_temporal_metrics,
)

__all__ = [
    "shannon_entropy",
    "block_entropy",
    "chi_squared_uniformity",
    "analyze_payload_cryptography",
    "calculate_inter_arrival_times",
    "calculate_jitter",
    "calculate_burstiness",
    "extract_temporal_metrics",
    "FlowAggregator",
]
