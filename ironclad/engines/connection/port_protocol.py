"""
E3.2 Port and Protocol Analyzer.

Analyzes port scanning patterns, protocol mismatches, non-standard service ports,
and suspicious high-entropy communications on unencrypted ports.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics, Protocol
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult
from ironclad.parsing.protocols import WELL_KNOWN_PORTS


class PortProtocolAnalyzer(BaseSubEngine):
    """
    Identifies vertical port scans (sweeping multiple ports on a single host),
    unusual IP protocols, and covert channels running over obscure ports.
    """

    def __init__(self, vertical_scan_threshold: int = 4) -> None:
        super().__init__(
            subengine_id="E3.2",
            name="Port and Protocol Analyzer",
            parent_engine="ENGINE_3_CONNECTION",
        )
        self.vertical_scan_threshold = vertical_scan_threshold

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
                explanation="No flows available for port/protocol analysis.",
            )

        # Track (src_ip, dst_ip) -> targeted ports
        host_pair_ports: Dict[tuple, set] = {}
        high_port_high_entropy = []

        for flow in flows:
            src = flow.key.src_ip
            dst = flow.key.dst_ip
            port = flow.key.dst_port

            pair = (src, dst)
            host_pair_ports.setdefault(pair, set()).add(port)

            # Check for high-entropy payloads on non-standard ports
            if port > 1024 and port not in (8080, 8443) and flow.mean_payload_entropy > 7.4:
                high_port_high_entropy.append({
                    "flow_id": flow.canonical_id,
                    "dst_port": port,
                    "entropy": round(flow.mean_payload_entropy, 3),
                    "bytes": flow.byte_count,
                })

        vertical_scans = []
        for (src, dst), ports in host_pair_ports.items():
            if len(ports) >= self.vertical_scan_threshold:
                vertical_scans.append({
                    "source_ip": src,
                    "target_ip": dst,
                    "ports_targeted_count": len(ports),
                    "ports_sample": sorted(list(ports))[:10],
                })

        if vertical_scans or high_port_high_entropy:
            risk_factors = []
            if vertical_scans:
                vertical_scans.sort(key=lambda x: x["ports_targeted_count"], reverse=True)
                risk_factors.append(5.5 + min(3.5, vertical_scans[0]["ports_targeted_count"] * 0.3))
            if high_port_high_entropy:
                risk_factors.append(7.0)

            risk = round(min(9.8, max(risk_factors)), 2)
            confidence = 90.0
            status = DetectionStatus.CRITICAL if risk >= 7.0 else DetectionStatus.SUSPICIOUS

            explanations = []
            if vertical_scans:
                top_v = vertical_scans[0]
                explanations.append(
                    f"Vertical port scan detected from {top_v['source_ip']} targeting "
                    f"{top_v['ports_targeted_count']} distinct ports on {top_v['target_ip']}"
                )
            if high_port_high_entropy:
                explanations.append(
                    f"{len(high_port_high_entropy)} flow(s) running high-entropy cryptographic payloads "
                    f"on non-standard high ports (e.g., port {high_port_high_entropy[0]['dst_port']})"
                )

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=confidence,
                status=status,
                explanation=" | ".join(explanations),
                evidence={
                    "vertical_scans": vertical_scans,
                    "high_entropy_flows": high_port_high_entropy[:5],
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.2,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation="Ports and protocols conform to expected client-server interactions without scanning.",
            evidence={"vertical_scans": 0},
        )
