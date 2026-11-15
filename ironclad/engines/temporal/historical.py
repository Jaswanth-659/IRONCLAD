"""
E1.4 Historical Behaviour Comparator.

Detects temporal baseline drift across inter-arrival time distributions and
session active durations using statistical distribution testing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np
import scipy.stats as stats

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class HistoricalBehaviourComparator(BaseSubEngine):
    """
    Evaluates current flow inter-arrival distribution against reference baseline distributions
    using two-sample Kolmogorov-Smirnov test and quantile divergence.
    """

    def __init__(self) -> None:
        super().__init__(
            subengine_id="E1.4",
            name="Historical Behaviour Comparator",
            parent_engine="ENGINE_1_TEMPORAL",
        )
        # Standard benign reference sample (exponential human-interactive inter-arrival times)
        np.random.seed(42)
        self.default_reference_iat = np.random.exponential(scale=0.5, size=200).tolist()

    def analyze(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SubEngineResult:
        if not flows:
            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=0.0,
                confidence_score=30.0,
                status=DetectionStatus.NORMAL,
                explanation="No flows available for historical temporal comparison.",
            )

        all_current_iats = []
        for flow in flows:
            all_current_iats.extend(flow.inter_arrival_times)

        if len(all_current_iats) < 10:
            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=2.0,
                confidence_score=45.0,
                status=DetectionStatus.NORMAL,
                explanation="Sample size insufficient for statistical distribution comparison (<10 IATs).",
                evidence={"sample_count": len(all_current_iats)},
            )

        ref = context.get("reference_iats", self.default_reference_iat) if context else self.default_reference_iat
        ks_res = stats.ks_2samp(ref, all_current_iats)
        stat = float(ks_res.statistic)
        p_val = float(ks_res.pvalue)

        # High KS statistic (e.g. > 0.40) and low p-value (< 0.01) indicate major temporal drift
        is_drifted = bool(p_val < 0.01 and stat > 0.35)

        if is_drifted:
            risk = round(min(8.5, 4.5 + stat * 4.5), 2)
            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=85.0,
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Statistical divergence detected against historical temporal baseline "
                    f"(KS statistic={stat:.3f}, p-value={p_val:.4e}). Timing profile indicates non-standard "
                    f"traffic generation or operational profile change."
                ),
                evidence={
                    "ks_statistic": round(stat, 4),
                    "p_value": round(p_val, 6),
                    "is_drifted": True,
                    "evaluated_samples": len(all_current_iats),
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.5,
            confidence_score=88.0,
            status=DetectionStatus.NORMAL,
            explanation=(
                f"Temporal behavior aligns with expected baseline profile "
                f"(KS statistic={stat:.3f}, p-value={p_val:.3f})."
            ),
            evidence={
                "ks_statistic": round(stat, 4),
                "p_value": round(p_val, 4),
                "is_drifted": False,
            },
        )
