"""
IRONCLAD Comprehensive Risk Scoring Test Suite.

Automated tests specifically verifying the corrected scoring and aggregation logic:
Test 1: All engines report low risk.
Test 2: One high-confidence sub-engine finding (not diluted by clean sub-engines).
Test 3: One low-confidence sub-engine finding (does not falsely escalate primary engine).
Test 4: Two independent findings corroborate each other (risk increases appropriately).
Test 5: Multiple correlated findings describe the same event (avoids double-counting).
Test 6: One primary engine is high risk while other two are low risk (not diluted by averaging).
Test 7: Verified threat-intelligence match (never averaged down).
Test 8: Unknown threat-intelligence indicator (not classified as malicious; not clean).
Test 9: Missing sub-engine result (not treated as safe; lowers confidence).
Test 10: Missing primary engine result (not treated as zero risk; lowers confidence).
Test 11: Low-confidence findings across multiple engines (dampened appropriately).
Test 12: High-risk findings across multiple independent engines (corroborates to critical risk).
"""

from __future__ import annotations

import pytest
from ironclad.core.types import FlowKey, FlowRecord, Protocol
from ironclad.engines.base import (
    DetectionStatus,
    EscalationLevel,
    FinalClassification,
    PrimaryEngineResult,
    RiskClassificationBand,
    SubEngineResult,
)
from ironclad.engines.connection import ConnectionBehaviourEngine
from ironclad.engines.connection.threat_intel import ThreatIntelChecker
from ironclad.engines.decision import DecisionCorrelationEngine
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_engine4_final_decision,
    aggregate_primary_engine_scores,
    audit_subengine_results,
)
from ironclad.engines.temporal import TemporalBehaviourEngine
from ironclad.engines.traffic import TrafficBehaviourEngine


def _make_dummy_flow(src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2") -> FlowRecord:
    key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=1234, dst_port=80, protocol=Protocol.TCP)
    return FlowRecord(
        key=key,
        canonical_id=f"{src_ip}:1234-{dst_ip}:80",
        start_time=1_000.0,
        end_time=1_001.0,
        packet_count=10,
        byte_count=1000,
        forward_packets=10,
        backward_packets=0,
        forward_bytes=1000,
        backward_bytes=0,
    )


def _make_sub_result(
    subengine_id: str,
    name: str,
    parent_engine: str,
    risk: float,
    conf: float,
    status: DetectionStatus = DetectionStatus.NORMAL,
    evidence: dict | None = None,
) -> SubEngineResult:
    return SubEngineResult(
        subengine_id=subengine_id,
        name=name,
        parent_engine=parent_engine,
        risk_score=risk,
        confidence_score=conf,
        status=status,
        explanation=f"Test explanation for {subengine_id} (risk={risk}, conf={conf}%)",
        evidence=evidence or {},
    )


def _make_primary_result(
    engine_id: str,
    name: str,
    risk: float,
    conf: float,
    sub_results: list[SubEngineResult] | None = None,
    evidence: dict | None = None,
) -> PrimaryEngineResult:
    escalation = EscalationLevel.from_score(risk)
    status = DetectionStatus.CRITICAL if risk >= 7.0 else (DetectionStatus.SUSPICIOUS if risk >= 5.0 else DetectionStatus.NORMAL)
    return PrimaryEngineResult(
        engine_id=engine_id,
        name=name,
        risk_score=risk,
        confidence_score=conf,
        explanation=f"Test explanation for {engine_id}",
        evidence=evidence or {},
        status=status,
        escalation=escalation,
        subengine_results=sub_results or [],
    )


# ===========================================================================
# TEST 1: All engines report low risk
# ===========================================================================

def test_1_all_engines_low_risk():
    """When all engines report normal/low risk, overall assessment remains NORMAL."""
    cfg = ScoringConfig()
    e1_subs = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 1.0, 85.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.5, 90.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 1.2, 80.0),
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.8, 85.0),
    ]
    p1 = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", e1_subs, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )
    assert p1.classification == RiskClassificationBand.NORMAL
    assert p1.aggregated_risk_score <= 2.9
    assert p1.escalation == EscalationLevel.NORMAL

    # Feed into Engine 4
    eng_results = {
        "ENGINE_1_TEMPORAL": _make_primary_result("ENGINE_1_TEMPORAL", "Temporal", 1.2, 85.0, e1_subs),
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 0.8, 90.0),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 1.0, 88.0),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)
    assert decision.overall_risk_score <= 2.9
    assert decision.final_classification == FinalClassification.BENIGN
    assert decision.classification_band == RiskClassificationBand.NORMAL


# ===========================================================================
# TEST 2: One high-confidence sub-engine finding (NOT diluted)
# ===========================================================================

def test_2_one_high_confidence_subengine_not_diluted():
    """A strong high-confidence finding (8.5/10 @ 95%) must not be diluted by clean sub-engines."""
    cfg = ScoringConfig()
    # E1.1 has a strong finding; E1.2, E1.3, E1.4 are completely normal
    subs = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 8.5, 95.0, DetectionStatus.CRITICAL),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.2, 90.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 0.4, 85.0),
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.1, 90.0),
    ]
    p = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )
    # If arithmetic average were used: (8.5 + 0.2 + 0.4 + 0.1)/4 = 2.3 (NORMAL) — completely diluted!
    # With corrected non-dilutive scoring:
    assert p.aggregated_risk_score >= 8.5, (
        f"Strong finding was diluted! Expected >= 8.5, got {p.aggregated_risk_score}"
    )
    assert p.classification == RiskClassificationBand.HIGH_RISK
    assert p.escalation == EscalationLevel.HIGH_PRIORITY_ESCALATION
    assert p.contributing_subengines == ["E1.1"]


# ===========================================================================
# TEST 3: One low-confidence sub-engine finding (does NOT falsely escalate)
# ===========================================================================

def test_3_one_low_confidence_subengine_dampened():
    """A high risk score (8.5/10) with very low confidence (15%) must be dampened."""
    cfg = ScoringConfig()
    subs = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 8.5, 15.0, DetectionStatus.SUSPICIOUS),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.5, 80.0),
    ]
    p = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )
    # The low confidence (15% vs 70% threshold) dampens the effective signal to:
    # 8.5 * (15/70) = 8.5 * 0.214 = 1.82 -> NORMAL
    assert p.aggregated_risk_score < 5.0, (
        f"Low-confidence finding was not dampened! Got {p.aggregated_risk_score}"
    )
    assert p.classification in (RiskClassificationBand.NORMAL, RiskClassificationBand.LOW_RISK)
    assert p.escalation == EscalationLevel.NORMAL


# ===========================================================================
# TEST 4: Two independent findings corroborate each other
# ===========================================================================

def test_4_two_independent_findings_corroborate():
    """Two independent sub-engines flagging distinct anomalies should increase aggregate risk."""
    cfg = ScoringConfig()
    # E1.1 (Periodicity) and E1.3 (Burst Pattern) are distinct independent mechanisms
    subs_single = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 7.0, 85.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.5, 80.0),
    ]
    p_single = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs_single, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )

    subs_dual = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 7.0, 85.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 6.5, 85.0),  # Independent second signal
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.5, 80.0),
    ]
    p_dual = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs_dual, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )

    assert p_dual.aggregated_risk_score > p_single.aggregated_risk_score, (
        f"Corroborating finding did not increase risk! Dual={p_dual.aggregated_risk_score}, Single={p_single.aggregated_risk_score}"
    )
    assert "E1.1" in p_dual.contributing_subengines
    assert "E1.3" in p_dual.contributing_subengines


# ===========================================================================
# TEST 5: Multiple correlated findings describe the same event
# ===========================================================================

def test_5_correlated_findings_do_not_double_count():
    """Correlated sub-engines (e.g. E1.1 Periodicity and E1.2 Jitter) must not repeatedly inflate score."""
    cfg = ScoringConfig()
    # Dual correlated: E1.1 (7.0) and E1.2 (6.5)
    subs_correlated = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 7.0, 85.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 6.5, 85.0),  # Correlated with E1.1
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.5, 80.0),
    ]
    p_corr = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs_correlated, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )

    # Dual independent: E1.1 (7.0) and E1.3 (6.5)
    subs_independent = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 7.0, 85.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 0.5, 80.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 6.5, 85.0),  # Independent
        _make_sub_result("E1.4", "Historical", "ENGINE_1_TEMPORAL", 0.5, 80.0),
    ]
    p_indep = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs_independent, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )

    # Independent corroboration must yield higher risk boost than duplicate/correlated
    assert p_indep.aggregated_risk_score > p_corr.aggregated_risk_score, (
        f"Correlated duplicate produced equal or greater boost! Indep={p_indep.aggregated_risk_score}, Corr={p_corr.aggregated_risk_score}"
    )
    # Check that correlation was explicitly logged in metadata
    assert "correlation_groups" in p_corr.scoring_metadata


# ===========================================================================
# TEST 6: One primary engine high risk while other two are low risk
# ===========================================================================

def test_6_one_primary_engine_high_risk_not_diluted():
    """Engine 4 must not average down an acute threat (e.g. Traffic=8.8) with clean engines (1.0)."""
    cfg = ScoringConfig()
    eng_results = {
        "ENGINE_1_TEMPORAL": _make_primary_result("ENGINE_1_TEMPORAL", "Temporal", 1.0, 90.0),
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 8.8, 92.0),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 1.2, 90.0),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)
    # If averaged: (1.0 + 8.8 + 1.2)/3 = 3.67 (LOW RISK) — unacceptable dilution!
    assert decision.overall_risk_score >= 8.8, (
        f"Engine 4 averaged down the high risk! Expected >= 8.8, got {decision.overall_risk_score}"
    )
    assert decision.classification_band in (RiskClassificationBand.HIGH_RISK, RiskClassificationBand.CRITICAL)
    assert decision.final_classification == FinalClassification.HIGH_RISK


# ===========================================================================
# TEST 7: Verified threat-intelligence match (never averaged down)
# ===========================================================================

def test_7_verified_threat_intelligence_match():
    """A confirmed threat intel match produces CONFIRMED_INDICATOR_MATCH and near-maximum score."""
    cfg = ScoringConfig()
    intel_sub = _make_sub_result(
        "E3.4", "Threat Intel", "ENGINE_3_CONNECTION", 9.8, 98.0,
        DetectionStatus.CRITICAL,
        evidence={
            "confirmed_match": True,
            "matches": [{"ip": "198.51.100.77", "category": "C2_SERVER", "threat_actor": "APT-29", "confidence": 98.0}],
        },
    )
    eng_results = {
        "ENGINE_1_TEMPORAL": _make_primary_result("ENGINE_1_TEMPORAL", "Temporal", 0.5, 90.0),
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 0.5, 90.0),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 9.8, 98.0, [intel_sub]),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)
    assert decision.final_classification == FinalClassification.CONFIRMED_INDICATOR_MATCH
    assert decision.overall_risk_score >= 9.5
    assert decision.overall_confidence_score >= 95.0
    assert "APT-29" in decision.executive_summary or "CONFIRMED" in decision.calculation_explanation


# ===========================================================================
# TEST 8: Unknown threat-intelligence indicator
# ===========================================================================

def test_8_unknown_threat_intelligence_indicator():
    """An unknown indicator is NOT classified as malicious, nor interpreted as clean evidence."""
    flow = _make_dummy_flow(dst_ip="203.0.113.50")
    checker = ThreatIntelChecker()
    result = checker.analyze([flow])
    # Must NOT have confirmed_match=True
    assert result.evidence.get("confirmed_match") is False
    # Risk must remain baseline low, not elevated just because unknown
    assert result.risk_score < 3.0
    # Explanation notes unmatched destinations are not confirmed benign
    assert "unverified" in result.explanation or "unmatched" in result.explanation.lower() or "no known" in result.explanation.lower()


# ===========================================================================
# TEST 9: Missing sub-engine result
# ===========================================================================

def test_9_missing_subengine_result_not_treated_as_safe():
    """If a sub-engine fails or is missing, data completeness factor drops and confidence is penalized."""
    cfg = ScoringConfig()
    # Only 3 of 4 subengines provided (E1.4 is missing)
    subs = [
        _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 6.0, 80.0),
        _make_sub_result("E1.2", "Jitter", "ENGINE_1_TEMPORAL", 5.5, 80.0),
        _make_sub_result("E1.3", "Burst", "ENGINE_1_TEMPORAL", 5.0, 80.0),
    ]
    p = aggregate_primary_engine_scores(
        "ENGINE_1_TEMPORAL", "Temporal Engine", subs, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg
    )
    # Check that missing sub-engine was detected
    assert p.unavailable_subengine_count == 1
    assert p.valid_subengine_count == 3
    # Completeness is 3/4 = 0.75, so confidence must be lower than 80%
    assert p.aggregated_confidence < 80.0
    # Missing sub-engine is NOT treated as safe (risk is not diluted by zero)
    assert p.aggregated_risk_score >= 6.0
    assert "unavailable" in p.calculation_explanation.lower() or "missing" in p.calculation_explanation.lower()


# ===========================================================================
# TEST 10: Missing primary engine result
# ===========================================================================

def test_10_missing_primary_engine_not_treated_as_zero_risk():
    """If Engine 1 is missing, Engine 4 must penalize confidence and not assume the missing vector is safe."""
    cfg = ScoringConfig()
    eng_results = {
        # ENGINE_1_TEMPORAL is missing
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 6.5, 80.0),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 6.0, 80.0),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)
    assert decision.unavailable_engine_count == 1
    # Missing engine must NOT dilute the 6.5 score
    assert decision.overall_risk_score >= 6.5
    # Overall confidence must reflect missing telemetry domain
    assert "ENGINE_1_TEMPORAL" in decision.scoring_metadata.get("missing_engines", [])
    assert "missing" in decision.calculation_explanation.lower() or "unavailable" in decision.calculation_explanation.lower()


# ===========================================================================
# TEST 11: Low-confidence findings across multiple engines
# ===========================================================================

def test_11_low_confidence_findings_dampened_across_engines():
    """Even if two engines report 7.5, if confidence is only 15%, overall risk must be dampened."""
    cfg = ScoringConfig()
    eng_results = {
        "ENGINE_1_TEMPORAL": _make_primary_result("ENGINE_1_TEMPORAL", "Temporal", 7.5, 15.0),
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 7.5, 15.0),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 1.0, 80.0),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)
    # Low confidence (15%) discounts effective signal: 7.5 * (15/70) = ~1.6 -> should not produce HIGH RISK
    assert decision.overall_risk_score < 5.0, (
        f"Low confidence findings falsely escalated to elevated risk! Score={decision.overall_risk_score}"
    )
    assert decision.final_classification != FinalClassification.HIGH_RISK


# ===========================================================================
# TEST 12: High-risk findings across multiple independent engines
# ===========================================================================

def test_12_high_risk_across_multiple_independent_engines():
    """High-risk findings across multiple independent engines corroborate to maximum threat level."""
    cfg = ScoringConfig()
    # High risk with high confidence on all 3 engines targeting the same host
    e1_sub = _make_sub_result("E1.1", "Periodicity", "ENGINE_1_TEMPORAL", 8.0, 90.0, evidence={"ip": "192.168.1.88"})
    e2_sub = _make_sub_result("E2.3", "Directional", "ENGINE_2_TRAFFIC", 8.5, 92.0, evidence={"ip": "192.168.1.88"})
    e3_sub = _make_sub_result("E3.2", "Port Scan", "ENGINE_3_CONNECTION", 8.2, 90.0, evidence={"ip": "192.168.1.88"})

    eng_results = {
        "ENGINE_1_TEMPORAL": _make_primary_result("ENGINE_1_TEMPORAL", "Temporal", 8.0, 90.0, [e1_sub]),
        "ENGINE_2_TRAFFIC": _make_primary_result("ENGINE_2_TRAFFIC", "Traffic", 8.5, 92.0, [e2_sub]),
        "ENGINE_3_CONNECTION": _make_primary_result("ENGINE_3_CONNECTION", "Connection", 8.2, 90.0, [e3_sub]),
    }
    decision = aggregate_engine4_final_decision(eng_results, [_make_dummy_flow()], config=cfg)

    # Multi-engine concurrence should boost the score beyond single engine peak
    assert decision.overall_risk_score > 8.5, (
        f"Multi-engine concurrence did not boost score! Got {decision.overall_risk_score}"
    )
    assert decision.overall_confidence_score >= 90.0
    assert decision.final_classification == FinalClassification.HIGH_RISK
    assert decision.classification_band in (RiskClassificationBand.HIGH_RISK, RiskClassificationBand.CRITICAL)
    assert len(decision.contributing_engines) >= 2


# ===========================================================================
# Mathematical Consistency & Invariant Checks
# ===========================================================================

def test_scoring_monotonicity_and_bounds():
    """Verify that scores are strictly bounded in [0.0, 10.0] and confidences in [0.0, 100.0]."""
    cfg = ScoringConfig()
    for r in [-5.0, 0.0, 5.0, 10.0, 15.0]:
        for c in [-10.0, 0.0, 50.0, 100.0, 150.0]:
            subs = [_make_sub_result(f"E1.{i}", "Sub", "ENGINE_1_TEMPORAL", r, c) for i in range(1, 5)]
            p = aggregate_primary_engine_scores("ENGINE_1_TEMPORAL", "Temporal", subs, ["E1.1", "E1.2", "E1.3", "E1.4"], cfg)
            assert 0.0 <= p.aggregated_risk_score <= 10.0
            assert 0.0 <= p.aggregated_confidence <= 100.0
