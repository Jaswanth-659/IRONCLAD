"""
E1.1 Periodicity Validator.

Evaluates inter-arrival time distributions to detect automated beaconing,
C2 heartbeats, and programmed polling with low dispersion.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class PeriodicityValidator(BaseSubEngine):
    """
    Validates periodic timing regularity using coefficient of variation (CV)
    and autocorrelation of inter-arrival times (IAT).
    """

    def __init__(self) -> None:
        super().__init__(
            subengine_id="E1.1",
            name="Periodicity Validator",
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
                confidence_score=30.0,
                status=DetectionStatus.NORMAL,
                explanation="No network flows available for periodicity evaluation.",
                evidence={"flow_count": 0},
            )

        suspicious_flows = []
        min_cv = 999.0
        most_periodic_flow = None

        for flow in flows:
            iats = flow.inter_arrival_times
            # Need at least 5 packet intervals for meaningful periodicity testing
            if len(iats) < 5:
                continue

            arr = np.asarray(iats, dtype=np.float64)
            mean_iat = float(np.mean(arr))
            std_iat = float(np.std(arr))

            if mean_iat <= 1e-4:
                continue

            # Coefficient of Variation (CV = std / mean)
            # Machine beacons typically exhibit CV < 0.25 (highly deterministic)
            # Human browsing is typically CV > 1.2
            cv = std_iat / mean_iat
            if cv < min_cv:
                min_cv = cv
                most_periodic_flow = flow.canonical_id

            # Lag-1 Autocorrelation
            diff = arr - mean_iat
            var = np.sum(diff ** 2)
            if var > 1e-9:
                acf_1 = float(np.sum(diff[:-1] * diff[1:]) / var)
            else:
                acf_1 = 1.0

            if cv < 0.35 and mean_iat > 0.5:
                suspicious_flows.append({
                    "flow_id": flow.canonical_id,
                    "cv": round(cv, 4),
                    "mean_iat": round(mean_iat, 4),
                    "std_iat": round(std_iat, 4),
                    "acf_1": round(acf_1, 4),
                    "packet_count": flow.packet_count,
                })

        if suspicious_flows:
            # Sort by lowest CV (highest periodicity)
            suspicious_flows.sort(key=lambda x: x["cv"])
            top = suspicious_flows[0]
            # Risk scaled: lower CV => higher risk of automated C2 beacon
            risk = round(min(9.5, max(5.0, 10.0 * (1.0 - top["cv"]))), 2)
            confidence = min(95.0, 60.0 + len(suspicious_flows) * 5.0)
            status = DetectionStatus.CRITICAL if risk >= 7.0 else DetectionStatus.SUSPICIOUS

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=status,
                explanation=(
                    f"Detected {len(suspicious_flows)} flow(s) exhibiting strict automated periodicity "
                    f"(lowest CV={top['cv']:.3f}, interval={top['mean_iat']:.2f}s). "
                    f"Signature strongly resembles C2 heartbeat or malware beaconing."
                ),
                evidence={
                    "suspicious_count": len(suspicious_flows),
                    "top_periodic_flow": top,
                    "all_candidates": suspicious_flows[:5],
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.2,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation=(
                f"Evaluated {len(flows)} flow(s). Inter-arrival timing reflects natural stochastic "
                f"traffic dispersion (lowest observed CV={min_cv:.2f})."
            ),
            evidence={"min_cv": round(min_cv if min_cv < 900 else 0.0, 3)},
        )
