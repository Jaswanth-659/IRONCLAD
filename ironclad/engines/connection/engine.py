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
    RiskClassificationBand,
)
from ironclad.engines.connection.connection_failure import ConnectionFailureAnalyzer
from ironclad.engines.connection.destination import DestinationAnalyzer
from ironclad.engines.connection.port_protocol import PortProtocolAnalyzer
from ironclad.engines.connection.threat_intel import ThreatIntelChecker
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_primary_engine_scores,
)


class ConnectionBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 3: Evaluates destination fan-outs, port scans, and threat intel."""

    EXPECTED_SUBENGINES = ["E3.1", "E3.2", "E3.3", "E3.4"]

    def __init__(self, scoring_config: Optional[ScoringConfig] = None) -> None:
        super().__init__(
            engine_id="ENGINE_3_CONNECTION",
            name="Connection Behaviour Engine",
        )
        self.scoring_config = scoring_config or DEFAULT_SCORING_CONFIG
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

        # Mathematically corrected, non-dilutive, credibility-weighted aggregation
        agg = aggregate_primary_engine_scores(
            engine_id=self.engine_id,
            engine_name=self.name,
            subengine_results=sub_results,
            expected_ids=self.EXPECTED_SUBENGINES,
            config=self.scoring_config,
        )

        triggered_secondary = agg.escalation != EscalationLevel.NORMAL

        active_sub_findings = [r.explanation for r in sub_results if r.risk_score >= 4.5]
        if active_sub_findings:
            explanation = " | ".join(active_sub_findings)
        else:
            explanation = (
                f"Evaluated {len(flows)} flow(s) across destination dispersion, port/protocol conformance, "
                "TCP handshake completions, and threat intelligence. No connection anomalies detected."
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        evidence_pkg = {
            "max_subengine_score": max((r.risk_score for r in sub_results), default=0.0),
            "mean_subengine_score": round(sum(r.risk_score for r in sub_results) / len(sub_results), 2) if sub_results else 0.0,
            "subengine_count": len(sub_results),
            "scoring_metadata": agg.scoring_metadata,
            "calculation_explanation": agg.calculation_explanation,
        }

        return PrimaryEngineResult(
            engine_id=self.engine_id,
            name=self.name,
            risk_score=agg.aggregated_risk_score,
            confidence_score=agg.aggregated_confidence,
            explanation=explanation,
            evidence=evidence_pkg,
            status=agg.status,
            escalation=agg.escalation,
            subengine_results=sub_results,
            secondary_investigation_triggered=triggered_secondary,
            execution_time_ms=round(elapsed_ms, 2),
            classification=agg.classification,
            contributing_subengines=agg.contributing_subengines,
            valid_subengine_count=agg.valid_subengine_count,
            unavailable_subengine_count=agg.unavailable_subengine_count,
            calculation_explanation=agg.calculation_explanation,
            scoring_metadata=agg.scoring_metadata,
        )
