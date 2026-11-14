"""
IRONCLAD Traffic Baseline Tracker.

Maintains statistical profiles of normal network telemetry parameters and
detects behavioral drift across subsequent monitoring intervals.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ironclad.core.exceptions import StatisticalAnalysisError
from ironclad.core.logging import get_logger
from ironclad.stats.distribution import compute_distribution_summary, evaluate_distribution_shift

logger = get_logger("stats.baseline")


class TrafficBaseline:
    """
    Stateful repository of normal traffic distributions.
    Stores moments and sample distributions across metrics (packet lengths, IATs, entropy, etc.).
    """

    def __init__(self, name: str = "default_baseline") -> None:
        self.name = name
        self.metric_summaries: Dict[str, Dict[str, float]] = {}
        self.reference_samples: Dict[str, List[float]] = {}

    def fit_metric(self, metric_name: str, samples: List[float]) -> None:
        """
        Record and summarize baseline data for a given network metric.

        Args:
            metric_name: Identifier (e.g., 'packet_length', 'iat', 'payload_entropy').
            samples: Numerical observations from a known benign period.
        """
        if not samples:
            logger.warning("Empty sample list passed to fit_metric for %s", metric_name)
            return

        summary = compute_distribution_summary(samples)
        self.metric_summaries[metric_name] = summary
        # Keep up to 1000 representative samples for two-sample KS hypothesis testing
        self.reference_samples[metric_name] = samples[:1000]
        logger.info(
            "Fitted baseline metric '%s' (N=%d, mean=%.3f, std=%.3f)",
            metric_name,
            len(samples),
            summary["mean"],
            summary["std"],
        )

    def check_anomaly(
        self, metric_name: str, observed_values: List[float], alpha: float = 0.05
    ) -> Dict[str, Any]:
        """
        Check if an observed sequence diverges significantly from baseline.

        Returns:
            Dict containing comparison against baseline moments and shift test.
        """
        if metric_name not in self.metric_summaries:
            raise StatisticalAnalysisError(
                f"No baseline profile exists for metric '{metric_name}'"
            )

        base_summary = self.metric_summaries[metric_name]
        obs_summary = compute_distribution_summary(observed_values)

        shift_result = evaluate_distribution_shift(
            self.reference_samples.get(metric_name, []), observed_values, alpha=alpha
        )

        # Deviation of observed mean in units of baseline standard deviation
        base_std = base_summary["std"]
        mean_deviation_z = (
            abs(obs_summary["mean"] - base_summary["mean"]) / base_std
            if base_std > 1e-9
            else 0.0
        )

        return {
            "metric": metric_name,
            "baseline_mean": base_summary["mean"],
            "baseline_std": base_summary["std"],
            "observed_mean": obs_summary["mean"],
            "observed_std": obs_summary["std"],
            "mean_z_deviation": round(mean_deviation_z, 4),
            "is_shifted": shift_result["is_shifted"],
            "ks_statistic": shift_result.get("statistic", 0.0),
            "p_value": shift_result.get("p_value", 1.0),
        }

    def save(self, filepath: Union[str, Path]) -> None:
        """Serialize baseline summaries to JSON."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "name": self.name,
            "metric_summaries": self.metric_summaries,
            "reference_samples": self.reference_samples,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved baseline profile to %s", path)

    @classmethod
    def load(cls, filepath: Union[str, Path]) -> TrafficBaseline:
        """Load baseline from serialized JSON file."""
        path = Path(filepath)
        if not path.exists():
            raise StatisticalAnalysisError(f"Baseline file does not exist: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        instance = cls(name=data.get("name", "loaded_baseline"))
        instance.metric_summaries = data.get("metric_summaries", {})
        instance.reference_samples = data.get("reference_samples", {})
        return instance
