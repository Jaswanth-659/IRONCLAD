"""
IRONCLAD Statistical Analysis Engine.

Provides distribution profiling, higher-order moments (skewness, kurtosis),
robust dispersion metrics (IQR, MAD), and statistical hypothesis testing (KS-test).
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple, Union

import numpy as np
import scipy.stats as stats

from ironclad.core.exceptions import StatisticalAnalysisError
from ironclad.core.logging import get_logger

logger = get_logger("stats.distribution")


def compute_distribution_summary(
    values: Union[Sequence[float], np.ndarray]
) -> Dict[str, float]:
    """
    Compute comprehensive parametric and non-parametric statistical moments.

    Args:
        values: Numerical series (e.g. packet lengths, IATs, entropy).

    Returns:
        Dictionary containing mean, median, std, variance, skewness, kurtosis,
        iqr, p25, p75, p95, p99.
    """
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return {
            "count": 0.0,
            "mean": 0.0,
            "median": 0.0,
            "std": 0.0,
            "variance": 0.0,
            "skewness": 0.0,
            "kurtosis": 0.0,
            "iqr": 0.0,
            "p25": 0.0,
            "p75": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }

    count = float(arr.size)
    mean_val = float(np.mean(arr))
    median_val = float(np.median(arr))
    var_val = float(np.var(arr))
    std_val = float(np.std(arr))

    # Skewness and kurtosis require at least 3 samples
    if arr.size >= 3 and std_val > 1e-9:
        skew_val = float(stats.skew(arr))
        kurt_val = float(stats.kurtosis(arr))
    else:
        skew_val = 0.0
        kurt_val = 0.0

    p25, p75 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
    p95, p99 = float(np.percentile(arr, 95)), float(np.percentile(arr, 99))
    iqr_val = p75 - p25

    return {
        "count": count,
        "mean": round(mean_val, 6),
        "median": round(median_val, 6),
        "std": round(std_val, 6),
        "variance": round(var_val, 6),
        "skewness": round(skew_val, 4),
        "kurtosis": round(kurt_val, 4),
        "iqr": round(iqr_val, 6),
        "p25": round(p25, 6),
        "p75": round(p75, 6),
        "p95": round(p95, 6),
        "p99": round(p99, 6),
    }


def compute_z_scores(
    values: Union[Sequence[float], np.ndarray]
) -> np.ndarray:
    """
    Calculate standard Z-scores $z = \\frac{x - \\mu}{\\sigma}$.
    Safely handles zero-variance arrays without DivisionByZero warnings.

    Returns:
        NumPy array of z-scores.
    """
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return np.array([], dtype=np.float64)

    std = np.std(arr)
    if std < 1e-9:
        return np.zeros_like(arr)

    mean = np.mean(arr)
    return (arr - mean) / std


def compute_iqr_bounds(
    values: Union[Sequence[float], np.ndarray], multiplier: float = 1.5
) -> Tuple[float, float]:
    """
    Compute Tukey's Fence outlier thresholds [Q1 - k*IQR, Q3 + k*IQR].

    Returns:
        Tuple of (lower_bound, upper_bound).
    """
    arr = np.asarray(values, dtype=np.float64)
    if arr.size == 0:
        return 0.0, 0.0

    q25, q75 = np.percentile(arr, [25, 75])
    iqr = q75 - q25
    lower = float(q25 - multiplier * iqr)
    upper = float(q75 + multiplier * iqr)
    return lower, upper


def evaluate_distribution_shift(
    baseline_sample: Union[Sequence[float], np.ndarray],
    observed_sample: Union[Sequence[float], np.ndarray],
    alpha: float = 0.05,
) -> Dict[str, Any]:
    """
    Two-sample Kolmogorov-Smirnov test to detect significant telemetry distribution shift.

    Args:
        baseline_sample: Known baseline measurements.
        observed_sample: Current capture measurements.
        alpha: Significance level threshold (default 0.05).

    Returns:
        Dict with statistic, p_value, and boolean is_shifted.
    """
    base = np.asarray(baseline_sample, dtype=np.float64)
    obs = np.asarray(observed_sample, dtype=np.float64)

    if base.size < 5 or obs.size < 5:
        return {
            "statistic": 0.0,
            "p_value": 1.0,
            "is_shifted": False,
            "reason": "Insufficient samples for KS test (minimum 5 required)",
        }

    res = stats.ks_2samp(base, obs)
    stat = float(res.statistic)
    p_val = float(res.pvalue)

    return {
        "statistic": round(stat, 6),
        "p_value": round(p_val, 6),
        "is_shifted": bool(p_val < alpha),
    }
