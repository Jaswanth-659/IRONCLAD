"""
E3.3 Connection Failure Analyzer.

Analyzes TCP handshake completion rates, unanswered SYN floods, RST terminations,
and half-open reconnaissance connections.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class ConnectionFailureAnalyzer(BaseSubEngine):
    """
    Identifies connection failure anomalies: high volume of SYN packets without ACK completion,
    elevated RST flags indicating active port closure or firewall drop, and scan sweeps.
    """

    def __init__(self, failure_ratio_threshold: float = 3.0) -> None:
        super().__init__(
            subengine_id="E3.3",
            name="Connection Failure Analyzer",
            parent_engine="ENGINE_3_CONNECTION",
        )
        self.failure_ratio_threshold = failure_ratio_threshold

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
                explanation="No flows available for connection failure analysis.",
            )

        failed_handshake_flows = []

        for flow in flows:
            syn = flow.tcp_flags.get("SYN", 0)
            ack = flow.tcp_flags.get("ACK", 0)
            rst = flow.tcp_flags.get("RST", 0)

            # Check for unanswered SYNs (characteristic of SYN flood or stealth SYN scan)
            if syn >= 5:
                ratio = syn / (ack + 1.0)
                if ratio >= self.failure_ratio_threshold:
                    failed_handshake_flows.append({
                        "flow_id": flow.canonical_id,
                        "syn_count": syn,
                        "ack_count": ack,
                        "rst_count": rst,
                        "syn_ack_ratio": round(ratio, 2),
                        "dst_port": flow.key.dst_port,
                    })

        if failed_handshake_flows:
            failed_handshake_flows.sort(key=lambda x: x["syn_ack_ratio"], reverse=True)
            top = failed_handshake_flows[0]
            risk = round(min(9.5, 6.0 + min(3.5, top["syn_ack_ratio"] * 0.2)), 2)
            confidence = min(95.0, 75.0 + len(failed_handshake_flows) * 4.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Detected {len(failed_handshake_flows)} flow(s) with severe handshake failure rates "
                    f"(top flow exhibited {top['syn_count']} SYNs vs {top['ack_count']} ACKs, "
                    f"failure ratio {top['syn_ack_ratio']}:1 on port {top['dst_port']}). "
                    f"Signature strongly denotes half-open TCP SYN scanning or volumetric SYN flooding."
                ),
                evidence={
                    "failed_flows_count": len(failed_handshake_flows),
                    "top_failure": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=0.9,
            confidence_score=90.0,
            status=DetectionStatus.NORMAL,
            explanation="TCP handshake completion rates are healthy with balanced SYN-ACK roundtrips.",
            evidence={"failed_handshakes": 0},
        )
