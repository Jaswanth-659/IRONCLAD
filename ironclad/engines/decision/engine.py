"""
ENGINE 4 — FINAL DECISION AND CORRELATION ENGINE.

Aggregates the three primary detection engines, evaluates secondary investigation modules,
correlates multi-vector findings from the same hosts, tests evidence independence,
and synthesizes an explainable final classification and response guidance.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import (
    CorrelationItem,
    DecisionReport,
    DetectionStatus,
    FinalClassification,
    PrimaryEngineResult,
    RiskClassificationBand,
)
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_engine4_final_decision,
)


class DecisionCorrelationEngine:
    """
    ENGINE 4: The master forensic synthesizer.
    Evaluates evidence independence, correlates host anomalies across engines,
    and produces defensible cybersecurity classifications without simplistic averaging.
    """

    def __init__(self, scoring_config: Optional[ScoringConfig] = None) -> None:
        self.scoring_config = scoring_config or DEFAULT_SCORING_CONFIG

    def evaluate(
        self,
        engine_results: Dict[str, PrimaryEngineResult],
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> DecisionReport:
        # Execute corrected, deterministic, mathematically grounded correlation aggregation
        out = aggregate_engine4_final_decision(
            engine_results=engine_results,
            flows=flows,
            host_metrics=host_metrics,
            context=context,
            config=self.scoring_config,
        )

        # Build timeline events
        timeline_events = [
            {
                "stage": "INGESTION_AND_PARSING",
                "status": "COMPLETED",
                "detail": f"Processed {len(flows)} flows across session boundaries.",
            }
        ]
        for eng_key, eng in engine_results.items():
            if eng is not None:
                timeline_events.append({
                    "stage": eng.name,
                    "status": eng.status.value,
                    "risk_score": eng.risk_score,
                    "confidence_score": eng.confidence_score,
                    "escalation": eng.escalation.value,
                    "classification": eng.classification.value if hasattr(eng, "classification") else "NORMAL",
                    "detail": eng.explanation,
                })

        timeline_events.append({
            "stage": "DECISION_AND_CORRELATION",
            "status": out.final_classification.value,
            "overall_risk": out.overall_risk_score,
            "overall_confidence": out.overall_confidence_score,
            "detail": out.executive_summary,
        })

        return DecisionReport(
            overall_risk_score=out.overall_risk_score,
            final_classification=out.final_classification,
            executive_summary=out.executive_summary,
            engine_results=engine_results,
            correlations=out.correlations,
            evidence_quality_score=out.evidence_quality_score,
            recommended_actions=out.recommended_actions,
            timeline_events=timeline_events,
            overall_confidence_score=out.overall_confidence_score,
            classification_band=out.classification_band,
            contributing_engines=out.contributing_engines,
            unavailable_engine_count=out.unavailable_engine_count,
            calculation_explanation=out.calculation_explanation,
            scoring_metadata=out.scoring_metadata,
        )
