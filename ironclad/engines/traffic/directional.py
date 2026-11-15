"""
E2.3 Directional Traffic Analyzer.

Analyzes asymmetric transmission patterns, forward-to-backward byte ratios,
and upload-heavy covert channels.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class DirectionalTrafficAnalyzer(BaseSubEngine):
    """
    Evaluates upload vs download byte asymmetries.
    Client sessions normally download far more than they upload (R_fwd/bwd < 0.2).
    Data exfiltration exhibits extreme upload ratios (R_fwd/bwd > 5.0 or backward_bytes == 0).
    """

    def __init__(self, exfil_ratio_threshold: float = 5.0) -> None:
        super().__init__(
            subengine_id="E2.3",
            name="Directional Traffic Analyzer",
            parent_engine="ENGINE_2_TRAFFIC",
        )
        self.exfil_ratio_threshold = exfil_ratio_threshold

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
                explanation="No flows available for directional traffic analysis.",
            )

        asymmetric_exfil_flows = []

        for flow in flows:
            # Need minimum data transfer to evaluate directional intent
            if flow.byte_count < 1500:
                continue

            fwd_bytes = flow.forward_bytes
            bwd_bytes = flow.backward_bytes

            # Ratio of outbound to inbound bytes
            ratio = fwd_bytes / (bwd_bytes + 1.0)

            # Check if high outbound transmission with low/negligible inbound acknowledgement
            if ratio >= self.exfil_ratio_threshold and fwd_bytes > 2000:
                asymmetric_exfil_flows.append({
                    "flow_id": flow.canonical_id,
                    "fwd_bytes": fwd_bytes,
                    "bwd_bytes": bwd_bytes,
                    "directional_ratio": round(ratio, 2),
                    "mean_entropy": round(flow.mean_payload_entropy, 3),
                    "dst_port": flow.key.dst_port,
                })

        if asymmetric_exfil_flows:
            asymmetric_exfil_flows.sort(key=lambda x: x["directional_ratio"], reverse=True)
            top = asymmetric_exfil_flows[0]
            # If high entropy accompanies asymmetric upload, risk is critical
            entropy_boost = 1.5 if top["mean_entropy"] > 7.0 else 0.0
            risk = round(min(9.5, 6.0 + min(2.5, top["directional_ratio"] * 0.1) + entropy_boost), 2)
            confidence = min(92.0, 75.0 + len(asymmetric_exfil_flows) * 3.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Detected {len(asymmetric_exfil_flows)} flow(s) displaying extreme upload asymmetry "
                    f"(outbound ratio {top['directional_ratio']}:1, {top['fwd_bytes']}B out vs {top['bwd_bytes']}B in, "
                    f"entropy={top['mean_entropy']}). Highly indicative of data exfiltration or unidirectional tunneling."
                ),
                evidence={
                    "flagged_flows_count": len(asymmetric_exfil_flows),
                    "top_exfil_candidate": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.1,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation="Directional traffic ratios conform to typical client-server request/response profiles.",
            evidence={"asymmetric_flows": 0},
        )
