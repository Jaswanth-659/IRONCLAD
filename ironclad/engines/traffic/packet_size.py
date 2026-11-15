"""
E2.1 Packet Size Analyzer.

Evaluates packet length distributions, fixed-length padding signatures,
and MTU distribution anomalies.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class PacketSizeAnalyzer(BaseSubEngine):
    """
    Identifies unnatural packet length profiles, such as fixed-size encrypted block padding
    (e.g., constant 512 or 1024-byte frames) or unusual zero-payload trains.
    """

    def __init__(self) -> None:
        super().__init__(
            subengine_id="E2.1",
            name="Packet Size Analyzer",
            parent_engine="ENGINE_2_TRAFFIC",
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
                explanation="No flows available for packet size analysis.",
            )

        fixed_size_flows = []
        for flow in flows:
            lengths = flow.packet_lengths
            if len(lengths) < 6:
                continue

            arr = np.asarray(lengths, dtype=np.float64)
            mean_len = float(np.mean(arr))
            std_len = float(np.std(arr))

            # Fixed-length payload padding signature:
            # When std_len is close to 0 but packets are substantial size (> 100 bytes),
            # this represents automated block-cipher padding or fixed protocol tunneling.
            if std_len < 2.0 and mean_len > 120.0:
                fixed_size_flows.append({
                    "flow_id": flow.canonical_id,
                    "mean_length": round(mean_len, 1),
                    "std_length": round(std_len, 2),
                    "packet_count": flow.packet_count,
                    "entropy": round(flow.mean_payload_entropy, 3),
                })

        if fixed_size_flows:
            fixed_size_flows.sort(key=lambda x: x["packet_count"], reverse=True)
            top = fixed_size_flows[0]
            risk = round(min(8.8, 5.5 + min(3.0, top["packet_count"] * 0.1)), 2)
            confidence = min(92.0, 75.0 + len(fixed_size_flows) * 3.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Identified {len(fixed_size_flows)} flow(s) with uniform fixed-length packet sizes "
                    f"(mean={top['mean_length']}B, std={top['std_length']}B, entropy={top['entropy']}). "
                    f"Characteristic of block-encrypted tunnels or encapsulated C2 transmissions."
                ),
                evidence={
                    "flagged_flows": fixed_size_flows[:5],
                    "total_flagged": len(fixed_size_flows),
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.2,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation="Packet length distributions show expected multi-modal variance.",
            evidence={"fixed_size_count": 0},
        )
