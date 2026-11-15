"""
E1.2 Jitter Analyzer.

Evaluates timing perturbations and intentionally introduced sleep jitter designed
to disguise C2 heartbeat periodicity from basic frequency analysis.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class JitterAnalyzer(BaseSubEngine):
    """
    Detects bounded uniform jitter patterns characteristic of advanced C2 sleep algorithms
    (e.g., Cobalt Strike sleep jitter percentage, Sliver beacon delay).
    """

    def __init__(self) -> None:
        super().__init__(
            subengine_id="E1.2",
            name="Jitter Analyzer",
            parent_engine="ENGINE_1_TEMPORAL",
        )

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
                confidence_score=20.0,
                status=DetectionStatus.NORMAL,
                explanation="No flows available for jitter analysis.",
            )

        jitter_candidates = []

        for flow in flows:
            iats = flow.inter_arrival_times
            if len(iats) < 6:
                continue

            arr = np.asarray(iats, dtype=np.float64)
            mean_iat = float(np.mean(arr))
            if mean_iat < 0.2:
                continue  # High speed bursts evaluated by burst analyzer

            # Calculate relative deviations |IAT_i - mean| / mean
            rel_devs = np.abs(arr - mean_iat) / mean_iat
            max_dev = float(np.max(rel_devs))
            mean_dev = float(np.mean(rel_devs))

            # Successive difference jitter (RFC 3550 style)
            diffs = np.abs(arr[1:] - arr[:-1])
            mean_jitter = float(np.mean(diffs))

            # In C2 with jitter (e.g., 20% jitter), rel_devs is strictly bounded (< 0.40)
            # but variance is non-zero (unlike fixed periodicity)
            if 0.05 < max_dev <= 0.45 and mean_dev < 0.25:
                jitter_candidates.append({
                    "flow_id": flow.canonical_id,
                    "mean_iat": round(mean_iat, 3),
                    "max_deviation_ratio": round(max_dev, 4),
                    "mean_deviation_ratio": round(mean_dev, 4),
                    "mean_jitter_sec": round(mean_jitter, 4),
                    "sample_count": len(iats),
                })

        if jitter_candidates:
            jitter_candidates.sort(key=lambda x: x["mean_deviation_ratio"])
            top = jitter_candidates[0]
            risk = round(min(8.8, 6.0 + (1.0 - top["max_deviation_ratio"]) * 3.0), 2)
            confidence = min(90.0, 65.0 + len(jitter_candidates) * 4.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Detected {len(jitter_candidates)} flow(s) matching bounded artificial sleep jitter "
                    f"(target IAT={top['mean_iat']}s, jitter window ±{top['max_deviation_ratio']*100:.1f}%). "
                    f"Characteristic of evasive C2 beaconing (Cobalt Strike / Sliver sleep mask)."
                ),
                evidence={
                    "flagged_flows": jitter_candidates[:5],
                    "best_fit": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.5,
            confidence_score=80.0,
            status=DetectionStatus.NORMAL,
            explanation="Inter-arrival jitter conforms to non-bounded natural network latency variations.",
            evidence={"jitter_candidates_count": 0},
        )
