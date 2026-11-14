"""
IRONCLAD Multi-Factor Risk Scoring Engine.

Combines statistical & ML anomaly confidences, topological graph metrics,
and heuristic cybersecurity rule findings into a composite risk index [0, 100].
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ironclad.config.settings import RiskConfig
from ironclad.core.exceptions import RiskScoringError
from ironclad.core.logging import get_logger
from ironclad.core.types import (
    AnomalyScore,
    FlowRecord,
    GraphNodeMetrics,
    RiskFinding,
    RiskScore,
    RiskSeverity,
)
from ironclad.risk.rules import RuleEngine

logger = get_logger("risk.scorer")


class RiskScorer:
    """
    Synthesizes multiple indicators into normalized, categorized risk assessments.
    """

    def __init__(
        self,
        config: Optional[RiskConfig] = None,
        rule_engine: Optional[RuleEngine] = None,
    ) -> None:
        self.config = config or RiskConfig()
        self.rule_engine = rule_engine or RuleEngine()

    def _determine_severity(self, score: float) -> RiskSeverity:
        thresh = self.config.severity_thresholds
        if score >= thresh.get("critical", 80.0):
            return RiskSeverity.CRITICAL
        elif score >= thresh.get("high", 60.0):
            return RiskSeverity.HIGH
        elif score >= thresh.get("medium", 35.0):
            return RiskSeverity.MEDIUM
        return RiskSeverity.LOW

    def score_flow(
        self,
        flow: FlowRecord,
        anomaly_score: Optional[AnomalyScore] = None,
        graph_metrics: Optional[GraphNodeMetrics] = None,
    ) -> RiskScore:
        """
        Evaluate composite risk for an individual network flow.

        Args:
            flow: Target FlowRecord.
            anomaly_score: Model anomaly evaluation.
            graph_metrics: Source host graph metrics (if available).

        Returns:
            RiskScore object.
        """
        # 1. Evaluate heuristic rules
        findings = self.rule_engine.evaluate_flows([flow])
        rule_impact = sum(f.score_impact for f in findings)
        rule_component = min(100.0, rule_impact)

        # 2. Anomaly detection component
        anomaly_component = 0.0
        if anomaly_score is not None:
            # Scale [0, 1] to [0, 100]
            anomaly_component = anomaly_score.score * 100.0
            if anomaly_score.is_anomaly:
                findings.append(
                    RiskFinding(
                        rule_id="ANOMALY-ML-001",
                        rule_name=f"Statistical/ML Anomaly ({anomaly_score.detector})",
                        severity=RiskSeverity.HIGH if anomaly_score.score > 0.8 else RiskSeverity.MEDIUM,
                        score_impact=anomaly_score.score * 30.0,
                        description=anomaly_score.explanation,
                        target_entity=flow.canonical_id,
                        evidence=anomaly_score.metrics,
                    )
                )

        # 3. Graph topological component
        graph_component = 0.0
        if graph_metrics is not None:
            # High fan-out or extreme out-degree contributes to risk
            if graph_metrics.fan_out_ratio > 5.0:
                graph_component = min(100.0, graph_metrics.fan_out_ratio * 10.0)

        # Weighted combination with dynamic normalization over active components
        active_weight = self.config.anomaly_weight + self.config.rule_weight
        weighted_sum = (anomaly_component * self.config.anomaly_weight) + (rule_component * self.config.rule_weight)

        if graph_metrics is not None:
            active_weight += self.config.graph_weight
            weighted_sum += (graph_component * self.config.graph_weight)

        composite = (weighted_sum / active_weight) if active_weight > 0 else 0.0
        final_score = float(round(min(100.0, max(0.0, composite)), 2))
        severity = self._determine_severity(final_score)

        return RiskScore(
            entity_id=flow.canonical_id,
            score=final_score,
            severity=severity,
            findings=findings,
            breakdown={
                "anomaly_component": round(anomaly_component, 2),
                "graph_component": round(graph_component, 2),
                "rule_component": round(rule_component, 2),
            },
        )

    def score_host(
        self,
        host_metrics: GraphNodeMetrics,
        host_flows: Optional[List[FlowRecord]] = None,
    ) -> RiskScore:
        """
        Evaluate composite risk for an IP host endpoint.
        """
        findings = self.rule_engine.evaluate_hosts({host_metrics.ip: host_metrics})
        rule_impact = sum(f.score_impact for f in findings)
        rule_component = min(100.0, rule_impact)

        graph_component = min(100.0, host_metrics.fan_out_ratio * 8.0)

        composite = (graph_component * 0.5) + (rule_component * 0.5)
        final_score = float(round(min(100.0, max(0.0, composite)), 2))
        severity = self._determine_severity(final_score)

        return RiskScore(
            entity_id=host_metrics.ip,
            score=final_score,
            severity=severity,
            findings=findings,
            breakdown={
                "graph_component": round(graph_component, 2),
                "rule_component": round(rule_component, 2),
            },
        )

    def compute_global_risk(
        self,
        flow_scores: List[RiskScore],
        host_scores: List[RiskScore],
    ) -> RiskScore:
        """
        Aggregate overall network capture risk index.
        """
        all_findings: List[RiskFinding] = []
        for s in flow_scores + host_scores:
            all_findings.extend(s.findings)

        if not flow_scores and not host_scores:
            return RiskScore(
                entity_id="GLOBAL_CAPTURE",
                score=0.0,
                severity=RiskSeverity.LOW,
                findings=[],
            )

        max_flow_score = max((s.score for s in flow_scores), default=0.0)
        max_host_score = max((s.score for s in host_scores), default=0.0)
        mean_flow_score = (
            sum(s.score for s in flow_scores) / len(flow_scores) if flow_scores else 0.0
        )

        # Global risk is heavily driven by worst incident, tempered by overall base
        global_val = (0.7 * max(max_flow_score, max_host_score)) + (0.3 * mean_flow_score)
        global_val = float(round(min(100.0, max(0.0, global_val)), 2))
        severity = self._determine_severity(global_val)

        return RiskScore(
            entity_id="GLOBAL_CAPTURE",
            score=global_val,
            severity=severity,
            findings=all_findings,
            breakdown={
                "max_flow_risk": round(max_flow_score, 2),
                "max_host_risk": round(max_host_score, 2),
                "mean_flow_risk": round(mean_flow_score, 2),
            },
        )
