"""
IRONCLAD Temporal & Inter-Arrival Time Analysis Engine.

Calculates timing distributions, jitter, burstiness, and packet rate dynamics.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple


def calculate_inter_arrival_times(timestamps: List[float]) -> List[float]:
    """
    Compute successive inter-arrival time (IAT) deltas between consecutive packets.

    Args:
        timestamps: Ordered list of packet arrival timestamps (seconds).

    Returns:
        List of delta times in seconds.
    """
    if len(timestamps) < 2:
        return []

    iats = []
    for i in range(1, len(timestamps)):
        delta = max(0.0, timestamps[i] - timestamps[i - 1])
        iats.append(delta)

    return iats


def calculate_jitter(iats: List[float]) -> float:
    """
    Compute mean packet delay variation (jitter) as average absolute difference
    between consecutive inter-arrival intervals.

    Args:
        iats: List of inter-arrival times.

    Returns:
        Mean jitter in seconds.
    """
    if len(iats) < 2:
        return 0.0

    diffs = [abs(iats[i] - iats[i - 1]) for i in range(1, len(iats))]
    return float(round(sum(diffs) / len(diffs), 6))


def calculate_burstiness(mean_val: float, std_val: float) -> float:
    """
    Compute standard burstiness parameter $B = \\frac{\\sigma - \\mu}{\\sigma + \\mu}$.
    Bounded in range [-1.0, 1.0].
    $B = -1$: completely deterministic / periodic.
    $B = 0$: memoryless Poisson process (exponential).
    $B > 0$: heavy-tailed, bursty traffic typical of automated beacons or floods.
    """
    total = std_val + mean_val
    if total <= 0:
        return 0.0
    return float(round((std_val - mean_val) / total, 4))


def extract_temporal_metrics(timestamps: List[float]) -> Dict[str, float]:
    """
    Compute full temporal feature profile for a timestamp sequence.

    Returns:
        Dictionary containing duration, pps, iat_mean, iat_std, iat_min, iat_max, jitter, burstiness.
    """
    if not timestamps:
        return {
            "duration": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "iat_min": 0.0,
            "iat_max": 0.0,
            "jitter": 0.0,
            "burstiness": 0.0,
        }

    duration = max(0.0, timestamps[-1] - timestamps[0])
    iats = calculate_inter_arrival_times(timestamps)

    if not iats:
        return {
            "duration": duration,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "iat_min": 0.0,
            "iat_max": 0.0,
            "jitter": 0.0,
            "burstiness": 0.0,
        }

    iat_mean = sum(iats) / len(iats)
    variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
    iat_std = math.sqrt(variance)
    iat_min = min(iats)
    iat_max = max(iats)
    jitter = calculate_jitter(iats)
    burst = calculate_burstiness(iat_mean, iat_std)

    return {
        "duration": float(round(duration, 4)),
        "iat_mean": float(round(iat_mean, 6)),
        "iat_std": float(round(iat_std, 6)),
        "iat_min": float(round(iat_min, 6)),
        "iat_max": float(round(iat_max, 6)),
        "jitter": float(round(jitter, 6)),
        "burstiness": float(round(burst, 4)),
    }
