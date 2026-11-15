"""
ENGINE 3 — CONNECTION BEHAVIOUR Orchestrator.

Orchestrates primary connection behavioral evaluation and automatic escalation across:
- E3.1 Destination Analyzer
- E3.2 Port and Protocol Analyzer
- E3.3 Connection Failure Analyzer
- E3.4 Threat Intelligence Checker
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import (
    BasePrimaryEngine,
    DetectionStatus,
    EscalationLevel,
    PrimaryEngineResult,
)
from ironclad.engines.connection.connection_failure import ConnectionFailureAnalyzer
from ironclad.engines.connection.destination import DestinationAnalyzer
from ironclad.engines.connection.port_protocol import PortProtocolAnalyzer
from ironclad.engines.connection.threat_intel import ThreatIntelChecker


class ConnectionBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 3: Evaluates destination fan-outs, port scans, and threat intel."""

    def __init__(self) -> None:
        super().__init__(
            engine_id="ENGINE_3_CONNECTION",
            name="Connection Behaviour Engine",
        )
        self.dest_sub = DestinationAnalyzer()
        self.port_sub = PortProtocolAnalyzer()
        self.failure_sub = ConnectionFailureAnalyzer()
        self.threat_intel_sub = ThreatIntelChecker()

        self.register_subengine(self.dest_sub)
        self.register_subengine(self.port_sub)
        self.register_subengine(self.failure_sub)
        self.register_subengine(self.threat_intel_sub)

    def evaluate(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PrimaryEngineResult:
        t0 = time.perf_counter()

        # Execute all 4 sub-engines
        sub_results = [
            self.dest_sub.analyze(flows, host_metrics, context),
            self.port_sub.analyze(flows, host_metrics, context),
            self.failure_sub.analyze(flows, host_metrics, context),
            self.threat_intel_sub.analyze(flows, host_metrics, context),
        ]

        sub_scores = [r.risk_score for r in sub_results]
        max_sub = max(sub_scores) if sub_scores else 0.0
        mean_sub = sum(sub_scores) / len(sub_scores) if sub_scores else 0.0

        # Weighted risk prioritizing confirmed threat intel and port scans
        composite_risk = (0.80 * max_sub) + (0.20 * mean_sub)
        primary_risk = round(min(10.0, max(0.0, composite_risk)), 2)

        confidence = round(
            sum(r.confidence_score for r in sub_results) / len(sub_results)
            if sub_results else 50.0,
            1
        )

        escalation = EscalationLevel.from_score(primary_risk)
        triggered_secondary = escalation != EscalationLevel.NORMAL

        if primary_risk >= 7.0:
            status = DetectionStatus.CRITICAL
        elif primary_risk >= 5.0:
            status = DetectionStatus.SUSPICIOUS
        else:
            status = DetectionStatus.NORMAL

        active_sub_findings = [r.explanation for r in sub_results if r.risk_score >= 4.5]
        if active_sub_findings:
            explanation = " | ".join(active_sub_findings)
        else:
            explanation = (
                f"Evaluated {len(flows)} flow(s) across destination dispersion, port/protocol conformance, "
                "TCP handshake completions, and threat intelligence. No connection anomalies detected."
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return PrimaryEngineResult(
            engine_id=self.engine_id,
            name=self.name,
            risk_score=primary_risk,
            confidence_score=confidence,
            explanation=explanation,
            evidence={
                "max_subengine_score": max_sub,
                "mean_subengine_score": round(mean_sub, 2),
                "subengine_count": len(sub_results),
            },
            status=status,
            escalation=escalation,
            subengine_results=sub_results,
            secondary_investigation_triggered=triggered_secondary,
            execution_time_ms=round(elapsed_ms, 2),
        )
