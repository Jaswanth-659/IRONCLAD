"""
IRONCLAD Dynamic Threshold and Adaptive Flag Management System.

Replaces static, hardcoded thresholds with an empirical, multi-statistical adaptive engine:
1. Baseline calculation via Mean, Standard Deviation, Median, Percentiles (p25, p75, p95, p99),
   Interquartile Range (IQR), and Coefficient of Variation (CV).
2. Protocol- and Host-aware adaptive threshold derivation with strict min/max boundary clamping.
3. Contamination protection (suspicious traffic cannot redefine baseline).
4. Rich Dynamic Anomaly Flags (category, observed, baseline, threshold, deviation %, severity, confidence).
5. Correlated multi-anomaly priority synthesis without double-counting.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


class AnomalyCategory(str, Enum):
    """Monitored telemetry and detection anomaly categories."""
    PACKET_RATE = "PACKET_RATE"
    TRAFFIC_VOLUME = "TRAFFIC_VOLUME"
    PACKET_SIZE = "PACKET_SIZE"
    INTER_ARRIVAL_TIME = "INTER_ARRIVAL_TIME"
    PERIODICITY = "PERIODICITY"
    JITTER = "JITTER"
    BURST_TRAFFIC = "BURST_TRAFFIC"
    DIRECTIONAL_IMBALANCE = "DIRECTIONAL_IMBALANCE"
    CONNECTION_FAILURES = "CONNECTION_FAILURES"
    DESTINATION_DIVERSITY = "DESTINATION_DIVERSITY"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    DATA_LOSS = "DATA_LOSS"


class FlagSeverity(str, Enum):
    """Dynamic alert severity classifications."""
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class StatisticalBaseline:
    """Empirical statistical characteristics of historical normal traffic."""
    category: AnomalyCategory
    sample_count: int
    mean: float
    std_dev: float
    median: float
    p25: float
    p75: float
    p95: float
    p99: float
    iqr: float
    coefficient_of_variation: float
    min_val: float
    max_val: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "sample_count": self.sample_count,
            "mean": round(self.mean, 4),
            "std_dev": round(self.std_dev, 4),
            "median": round(self.median, 4),
            "p25": round(self.p25, 4),
            "p75": round(self.p75, 4),
            "p95": round(self.p95, 4),
            "p99": round(self.p99, 4),
            "iqr": round(self.iqr, 4),
            "coefficient_of_variation": round(self.coefficient_of_variation, 4),
            "min_val": round(self.min_val, 4),
            "max_val": round(self.max_val, 4),
        }


@dataclass
class DynamicAnomalyFlag:
    """
    Standardized, highly explainable dynamic telemetry flag.
    Exposes full mathematical deviation context for dashboard and SOC analysts.
    """
    anomaly_category: str
    observed_value: float
    expected_baseline: float
    current_threshold: float
    deviation_percentage: float
    severity: FlagSeverity
    confidence: float
    detection_explanation: str
    associated_host: str
    timestamp: float
    protocol: str = "ANY"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_category": self.anomaly_category,
            "observed_value": round(self.observed_value, 4),
            "expected_baseline": round(self.expected_baseline, 4),
            "current_threshold": round(self.current_threshold, 4),
            "deviation_percentage": round(self.deviation_percentage, 2),
            "severity": self.severity.value,
            "confidence": round(self.confidence, 1),
            "detection_explanation": self.detection_explanation,
            "associated_host": self.associated_host,
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "metadata": self.metadata,
        }


@dataclass
class CategoryThresholdConfig:
    """Configurable boundaries and adaptation sensitivities for each anomaly category."""
    category: AnomalyCategory
    default_baseline: float
    min_bound: float
    max_bound: float
    direction: str = "upper"  # "upper" (higher is anomalous) or "lower" (lower is anomalous, e.g. CV for periodicity)
    iqr_multiplier_low: float = 1.5
    iqr_multiplier_med: float = 2.5
    iqr_multiplier_high: float = 4.0
    iqr_multiplier_crit: float = 6.0


# Default operational configurations per anomaly category
DEFAULT_CATEGORY_CONFIGS: Dict[AnomalyCategory, CategoryThresholdConfig] = {
    AnomalyCategory.PACKET_RATE: CategoryThresholdConfig(
        category=AnomalyCategory.PACKET_RATE,
        default_baseline=20.0,
        min_bound=5.0,
        max_bound=5000.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.5,
    ),
    AnomalyCategory.TRAFFIC_VOLUME: CategoryThresholdConfig(
        category=AnomalyCategory.TRAFFIC_VOLUME,
        default_baseline=50000.0,
        min_bound=1000.0,
        max_bound=50000000.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.0,
    ),
    AnomalyCategory.PACKET_SIZE: CategoryThresholdConfig(
        category=AnomalyCategory.PACKET_SIZE,
        default_baseline=512.0,
        min_bound=40.0,
        max_bound=1500.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.2,
        iqr_multiplier_high=3.5,
        iqr_multiplier_crit=5.0,
    ),
    AnomalyCategory.INTER_ARRIVAL_TIME: CategoryThresholdConfig(
        category=AnomalyCategory.INTER_ARRIVAL_TIME,
        default_baseline=0.05,
        min_bound=0.0001,
        max_bound=10.0,
        direction="lower",
        iqr_multiplier_low=1.2,
        iqr_multiplier_med=2.0,
        iqr_multiplier_high=3.0,
        iqr_multiplier_crit=4.5,
    ),
    AnomalyCategory.PERIODICITY: CategoryThresholdConfig(
        category=AnomalyCategory.PERIODICITY,
        default_baseline=1.2,
        min_bound=0.01,
        max_bound=2.5,
        direction="lower",  # Lower CV indicates beacon periodicity
        iqr_multiplier_low=1.2,
        iqr_multiplier_med=2.0,
        iqr_multiplier_high=3.0,
        iqr_multiplier_crit=4.0,
    ),
    AnomalyCategory.JITTER: CategoryThresholdConfig(
        category=AnomalyCategory.JITTER,
        default_baseline=0.02,
        min_bound=0.0001,
        max_bound=5.0,
        direction="lower",
        iqr_multiplier_low=1.2,
        iqr_multiplier_med=2.0,
        iqr_multiplier_high=3.2,
        iqr_multiplier_crit=4.5,
    ),
    AnomalyCategory.BURST_TRAFFIC: CategoryThresholdConfig(
        category=AnomalyCategory.BURST_TRAFFIC,
        default_baseline=1.0,
        min_bound=0.0,
        max_bound=25.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.0,
    ),
    AnomalyCategory.DIRECTIONAL_IMBALANCE: CategoryThresholdConfig(
        category=AnomalyCategory.DIRECTIONAL_IMBALANCE,
        default_baseline=1.0,
        min_bound=0.05,
        max_bound=20.0,
        direction="upper",  # Severe upload asymmetry
        iqr_multiplier_low=1.8,
        iqr_multiplier_med=3.0,
        iqr_multiplier_high=5.0,
        iqr_multiplier_crit=8.0,
    ),
    AnomalyCategory.CONNECTION_FAILURES: CategoryThresholdConfig(
        category=AnomalyCategory.CONNECTION_FAILURES,
        default_baseline=0.05,
        min_bound=0.0,
        max_bound=100.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.0,
    ),
    AnomalyCategory.DESTINATION_DIVERSITY: CategoryThresholdConfig(
        category=AnomalyCategory.DESTINATION_DIVERSITY,
        default_baseline=2.0,
        min_bound=1.0,
        max_bound=1000.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.0,
    ),
    AnomalyCategory.PROTOCOL_ANOMALY: CategoryThresholdConfig(
        category=AnomalyCategory.PROTOCOL_ANOMALY,
        default_baseline=1.0,
        min_bound=0.0,
        max_bound=10.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=2.5,
        iqr_multiplier_high=4.0,
        iqr_multiplier_crit=6.0,
    ),
    AnomalyCategory.DATA_LOSS: CategoryThresholdConfig(
        category=AnomalyCategory.DATA_LOSS,
        default_baseline=0.5,
        min_bound=0.0,
        max_bound=100.0,
        direction="upper",
        iqr_multiplier_low=1.5,
        iqr_multiplier_med=3.0,
        iqr_multiplier_high=6.0,
        iqr_multiplier_crit=10.0,
    ),
}


class DynamicThresholdManager:
    """
    Central adaptive threshold manager.
    Maintains clean baseline memory, computes percentiles/IQR, adapts thresholds,
    and produces explainable DynamicAnomalyFlags.
    """

    def __init__(
        self,
        category_configs: Optional[Dict[AnomalyCategory, CategoryThresholdConfig]] = None,
        max_history_samples: int = 500,
    ) -> None:
        self.configs = dict(DEFAULT_CATEGORY_CONFIGS)
        if category_configs:
            self.configs.update(category_configs)
        self.max_history_samples = max_history_samples

        # History stores: key -> list of float observations
        # Keys can be (category,), (category, host), (category, protocol)
        self._history: Dict[str, List[float]] = {}

    def _get_key(
        self,
        category: AnomalyCategory,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> str:
        h = host.strip() if host else "*"
        p = protocol.strip().upper() if protocol else "*"
        return f"{category.value}::{h}::{p}"

    def record_observation(
        self,
        category: AnomalyCategory,
        value: float,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
        is_clean: bool = True,
    ) -> None:
        """
        Record an observed metric into baseline history.
        CRITICAL: If is_clean is False (known or suspected attack traffic), the observation
        is not admitted into baseline history, preventing malicious contamination.
        """
        if not is_clean or not math.isfinite(value):
            return

        # Check existing baseline to avoid contaminating with extreme outliers (> 5 IQR)
        base = self.calculate_baseline(category, host, protocol)
        if base.sample_count >= 10:
            if base.iqr > 0:
                deviation = abs(value - base.median) / base.iqr
                if deviation > 5.0:
                    # Extreme outlier: quarantine from normal baseline
                    return

        # Record at specific key and global category key
        keys = [
            self._get_key(category, host, protocol),
            self._get_key(category, host=None, protocol=None),
        ]
        if host:
            keys.append(self._get_key(category, host=host, protocol=None))
        if protocol:
            keys.append(self._get_key(category, host=None, protocol=protocol))

        for k in set(keys):
            hist = self._history.setdefault(k, [])
            hist.append(float(value))
            if len(hist) > self.max_history_samples:
                hist.pop(0)

    def calculate_baseline(
        self,
        category: AnomalyCategory,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> StatisticalBaseline:
        """
        Calculate complete statistical properties across historical observations.
        Falls back to global category history, then default configuration baseline if empty.
        """
        # Try most specific key first, then fallback to global
        specific_key = self._get_key(category, host, protocol)
        samples = list(self._history.get(specific_key, []))

        if len(samples) < 5:
            global_key = self._get_key(category, None, None)
            samples = list(self._history.get(global_key, []))

        cfg = self.configs.get(category, DEFAULT_CATEGORY_CONFIGS[category])

        if not samples:
            # Fallback to configured operational default
            default_val = cfg.default_baseline
            return StatisticalBaseline(
                category=category,
                sample_count=0,
                mean=default_val,
                std_dev=0.1 * default_val if default_val != 0 else 0.1,
                median=default_val,
                p25=default_val * 0.9,
                p75=default_val * 1.1,
                p95=default_val * 1.3,
                p99=default_val * 1.5,
                iqr=default_val * 0.2 if default_val != 0 else 0.2,
                coefficient_of_variation=0.1,
                min_val=cfg.min_bound,
                max_val=cfg.max_bound,
            )

        sorted_s = sorted(samples)
        n = len(sorted_s)
        mean_val = sum(sorted_s) / n

        # Variance and Standard Deviation
        variance = sum((x - mean_val) ** 2 for x in sorted_s) / max(1, n - 1)
        std_val = math.sqrt(variance)

        # Percentiles helper
        def percentile(p: float) -> float:
            k = (n - 1) * p
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return sorted_s[int(k)]
            return sorted_s[f] * (c - k) + sorted_s[c] * (k - f)

        median_val = percentile(0.50)
        p25_val = percentile(0.25)
        p75_val = percentile(0.75)
        p95_val = percentile(0.95)
        p99_val = percentile(0.99)
        iqr_val = max(1e-6, p75_val - p25_val)
        cv_val = std_val / abs(mean_val) if abs(mean_val) > 1e-6 else 0.0

        return StatisticalBaseline(
            category=category,
            sample_count=n,
            mean=mean_val,
            std_dev=std_val,
            median=median_val,
            p25=p25_val,
            p75=p75_val,
            p95=p95_val,
            p99=p99_val,
            iqr=iqr_val,
            coefficient_of_variation=cv_val,
            min_val=sorted_s[0],
            max_val=sorted_s[-1],
        )

    def get_adaptive_threshold(
        self,
        category: AnomalyCategory,
        severity: FlagSeverity,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> float:
        """
        Derives an adaptive threshold for a given category and severity.
        Clamps strictly between minimum and maximum bounds to ensure system stability.
        """
        cfg = self.configs.get(category, DEFAULT_CATEGORY_CONFIGS[category])
        base = self.calculate_baseline(category, host, protocol)

        multiplier = {
            FlagSeverity.LOW: cfg.iqr_multiplier_low,
            FlagSeverity.MEDIUM: cfg.iqr_multiplier_med,
            FlagSeverity.HIGH: cfg.iqr_multiplier_high,
            FlagSeverity.CRITICAL: cfg.iqr_multiplier_crit,
        }.get(severity, cfg.iqr_multiplier_med)

        # Use robust scale (IQR or std dev)
        spread = max(base.iqr, base.std_dev, 0.05 * abs(base.median))

        if cfg.direction == "lower":
            # Anomaly is when value drops below threshold (e.g. low jitter / low CV in beacons)
            thresh = base.median - multiplier * spread
            thresh = max(cfg.min_bound, min(cfg.max_bound, thresh))
        else:
            # Anomaly is when value rises above threshold (e.g. rate, volume, burst, loss)
            thresh = base.median + multiplier * spread
            thresh = max(cfg.min_bound, min(cfg.max_bound, thresh))

        return float(thresh)

    def get_thresholds(
        self,
        category: AnomalyCategory,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> Dict[str, float]:
        """Convenience method returning low, medium, high, critical thresholds for a category."""
        return {
            "LOW": self.get_adaptive_threshold(category, FlagSeverity.LOW, host, protocol),
            "MEDIUM": self.get_adaptive_threshold(category, FlagSeverity.MEDIUM, host, protocol),
            "HIGH": self.get_adaptive_threshold(category, FlagSeverity.HIGH, host, protocol),
            "CRITICAL": self.get_adaptive_threshold(category, FlagSeverity.CRITICAL, host, protocol),
        }

    @property
    def contamination_protection_active(self) -> bool:
        """Indicates whether clean-baseline outlier filtering and contamination protection is active."""
        return True

    def get_all_baselines(
        self,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Return empirical statistical baselines across all 12 anomaly categories."""
        return {
            cat.value: self.calculate_baseline(cat, host=host, protocol=protocol).to_dict()
            for cat in AnomalyCategory
        }

    def get_all_thresholds(
        self,
        host: Optional[str] = None,
        protocol: Optional[str] = None,
    ) -> Dict[str, Dict[str, float]]:
        """Return dynamic adaptive thresholds (LOW, MEDIUM, HIGH, CRITICAL) for all categories."""
        return {
            cat.value: {
                k: round(v, 4)
                for k, v in self.get_thresholds(cat, host=host, protocol=protocol).items()
            }
            for cat in AnomalyCategory
        }

    def evaluate(
        self,
        category: AnomalyCategory,
        observed_value: float,
        host: str = "0.0.0.0",
        protocol: str = "ANY",
        timestamp: Optional[float] = None,
        context_detail: str = "",
    ) -> DynamicAnomalyFlag:
        """
        Evaluates an observed metric against dynamic multi-level thresholds.
        Returns a rich DynamicAnomalyFlag with severity, deviation %, and confidence.
        """
        ts = timestamp if timestamp is not None else time.time()
        cfg = self.configs.get(category, DEFAULT_CATEGORY_CONFIGS[category])
        base = self.calculate_baseline(category, host, protocol)

        t_low = self.get_adaptive_threshold(category, FlagSeverity.LOW, host, protocol)
        t_med = self.get_adaptive_threshold(category, FlagSeverity.MEDIUM, host, protocol)
        t_high = self.get_adaptive_threshold(category, FlagSeverity.HIGH, host, protocol)
        t_crit = self.get_adaptive_threshold(category, FlagSeverity.CRITICAL, host, protocol)

        # Deviation percentage relative to baseline
        denom = abs(base.median) if abs(base.median) > 1e-4 else 1.0
        dev_pct = ((observed_value - base.median) / denom) * 100.0

        if cfg.direction == "lower":
            # Smaller is more anomalous
            if observed_value <= t_crit:
                sev = FlagSeverity.CRITICAL
                current_thresh = t_crit
            elif observed_value <= t_high:
                sev = FlagSeverity.HIGH
                current_thresh = t_high
            elif observed_value <= t_med:
                sev = FlagSeverity.MEDIUM
                current_thresh = t_med
            elif observed_value <= t_low:
                sev = FlagSeverity.LOW
                current_thresh = t_low
            else:
                sev = FlagSeverity.NORMAL
                current_thresh = t_low
        else:
            # Larger is more anomalous
            if observed_value >= t_crit:
                sev = FlagSeverity.CRITICAL
                current_thresh = t_crit
            elif observed_value >= t_high:
                sev = FlagSeverity.HIGH
                current_thresh = t_high
            elif observed_value >= t_med:
                sev = FlagSeverity.MEDIUM
                current_thresh = t_med
            elif observed_value >= t_low:
                sev = FlagSeverity.LOW
                current_thresh = t_low
            else:
                sev = FlagSeverity.NORMAL
                current_thresh = t_low

        # Calculate confidence based on sample size and signal strength
        sample_conf = min(50.0, base.sample_count * 2.5) if base.sample_count > 0 else 25.0
        deviation_strength = min(50.0, abs(dev_pct) * 0.25)
        confidence = min(99.0, max(30.0, sample_conf + deviation_strength))

        # Build clear explanation
        if sev == FlagSeverity.NORMAL:
            explanation = (
                f"Observed {category.value} value ({observed_value:.2f}) conforms to expected baseline "
                f"({base.median:.2f} ± {base.iqr:.2f})."
            )
        else:
            explanation = (
                f"Dynamic {sev.value} anomaly in {category.value} for host {host}: "
                f"Observed {observed_value:.2f} deviates by {dev_pct:+.1f}% from baseline ({base.median:.2f}), "
                f"exceeding dynamic threshold of {current_thresh:.2f}."
            )
        if context_detail:
            explanation += f" ({context_detail})"

        flag = DynamicAnomalyFlag(
            anomaly_category=category.value,
            observed_value=float(observed_value),
            expected_baseline=float(base.median),
            current_threshold=float(current_thresh),
            deviation_percentage=float(dev_pct),
            severity=sev,
            confidence=float(confidence),
            detection_explanation=explanation,
            associated_host=host,
            timestamp=ts,
            protocol=protocol,
            metadata={
                "mean": round(base.mean, 4),
                "std_dev": round(base.std_dev, 4),
                "iqr": round(base.iqr, 4),
                "sample_count": base.sample_count,
            },
        )

        # If normal or low, record observation into baseline history for continuous adaptation
        if sev in (FlagSeverity.NORMAL, FlagSeverity.LOW):
            self.record_observation(category, observed_value, host, protocol, is_clean=True)

        return flag

    def correlate_anomalies(
        self, flags: List[DynamicAnomalyFlag]
    ) -> Dict[str, Any]:
        """
        Multi-Anomaly Correlator.
        When multiple related anomalies occur on the same host:
        - Groups by host.
        - Boosts overall priority based on combined independent evidence.
        - Applies sub-additive damping to prevent double-counting correlated anomalies
          (e.g., PACKET_RATE + TRAFFIC_VOLUME + BURST).
        """
        host_flags: Dict[str, List[DynamicAnomalyFlag]] = {}
        for f in flags:
            if f.severity != FlagSeverity.NORMAL:
                host_flags.setdefault(f.associated_host, []).append(f)

        host_assessments = []

        severity_weights = {
            FlagSeverity.CRITICAL: 10.0,
            FlagSeverity.HIGH: 7.5,
            FlagSeverity.MEDIUM: 5.0,
            FlagSeverity.LOW: 2.5,
            FlagSeverity.NORMAL: 0.0,
        }

        # Correlated category groups (findings within same group get diminishing returns)
        VOLUME_CORRELATED = {
            AnomalyCategory.PACKET_RATE.value,
            AnomalyCategory.TRAFFIC_VOLUME.value,
            AnomalyCategory.BURST_TRAFFIC.value,
        }
        TEMPORAL_CORRELATED = {
            AnomalyCategory.PERIODICITY.value,
            AnomalyCategory.JITTER.value,
            AnomalyCategory.INTER_ARRIVAL_TIME.value,
        }

        for host, f_list in host_flags.items():
            if not f_list:
                continue

            # Sort by severity descending
            f_list.sort(key=lambda x: severity_weights[x.severity], reverse=True)
            primary_flag = f_list[0]
            base_score = severity_weights[primary_flag.severity]

            # Corroborate subsequent flags with correlation discount
            corroboration_boost = 0.0
            categories_seen = {primary_flag.anomaly_category}

            for f in f_list[1:]:
                cat = f.anomaly_category
                weight = severity_weights[f.severity] * (f.confidence / 100.0)

                # Check if correlated with existing finding
                is_vol_corr = (cat in VOLUME_CORRELATED) and bool(categories_seen.intersection(VOLUME_CORRELATED))
                is_temp_corr = (cat in TEMPORAL_CORRELATED) and bool(categories_seen.intersection(TEMPORAL_CORRELATED))

                if is_vol_corr or is_temp_corr:
                    # Correlated: discounted boost
                    corroboration_boost += weight * 0.15
                else:
                    # Independent anomaly domain: full corroboration boost
                    corroboration_boost += weight * 0.35

                categories_seen.add(cat)

            composite_score = min(10.0, base_score + corroboration_boost)

            if composite_score >= 8.0:
                comp_sev = FlagSeverity.CRITICAL
            elif composite_score >= 6.0:
                comp_sev = FlagSeverity.HIGH
            elif composite_score >= 4.0:
                comp_sev = FlagSeverity.MEDIUM
            else:
                comp_sev = FlagSeverity.LOW

            host_assessments.append({
                "host": host,
                "flag_count": len(f_list),
                "composite_score": round(composite_score, 2),
                "composite_severity": comp_sev.value,
                "primary_anomaly": primary_flag.anomaly_category,
                "categories": sorted(list(categories_seen)),
                "flags": [f.to_dict() for f in f_list],
            })

        host_assessments.sort(key=lambda x: x["composite_score"], reverse=True)
        return {
            "total_flagged_hosts": len(host_assessments),
            "total_anomalies": sum(len(f_list) for f_list in host_flags.values()),
            "host_assessments": host_assessments,
        }

    # Convenience aliases
    evaluate_value = evaluate
    correlate_flags = correlate_anomalies


# Global singleton threshold manager
dynamic_threshold_manager = DynamicThresholdManager()
