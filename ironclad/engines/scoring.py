"""
IRONCLAD Risk Scoring and Correlation Engine.

Implements mathematically rigorous, deterministic, and transparent scoring:
- Credibility-weighted effective signal calculation (risk discounted by low confidence).
- Non-dilutive corroboration operator (strong findings are never diluted by unrelated clean metrics).
- Correlation detection and duplicate discounting (prevents double-counting same underlying events).
- Independent confidence calculation based on data completeness, evidence sample, and finding certainty.
- Transparent audit trail recording inputs, exclusions, correlation handling, and step-by-step explanations.
- Configurable operational classification bands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import (
    CorrelationItem,
    DetectionStatus,
    EscalationLevel,
    FinalClassification,
    PrimaryEngineResult,
    RiskClassificationBand,
    SubEngineResult,
)


@dataclass
class ScoringConfig:
    """
    Configurable operational parameters for risk scoring and classification.
    Thresholds are operational baselines and remain fully configurable.
    """
    # Classification bands
    normal_max: float = 2.9
    low_risk_max: float = 4.9
    suspicious_max: float = 6.9
    high_risk_max: float = 8.9
    # 9.0 - 10.0 is CRITICAL

    # Confidence scaling
    confidence_discount_threshold: float = 70.0  # Under 70%, risk signal is dampened
    min_confidence_floor: float = 0.20          # Floor scaling factor (prevents total wipeout but dampens)

    # Corroboration weights
    independent_corroboration_weight: float = 0.20  # Boost per independent finding above baseline
    correlated_corroboration_weight: float = 0.05   # Diminishing boost for correlated / duplicate findings
    cross_engine_corroboration_weight: float = 0.25 # Boost per independent cross-engine corroboration

    # Baseline threshold below which findings are considered background noise (no corroboration boost)
    baseline_noise_floor: float = 3.0

    def classify_score(self, score: float) -> RiskClassificationBand:
        """Map normalized risk score [0.0 - 10.0] into standardized classification bands."""
        s = max(0.0, min(10.0, round(float(score), 2)))
        if s <= self.normal_max:
            return RiskClassificationBand.NORMAL
        elif s <= self.low_risk_max:
            return RiskClassificationBand.LOW_RISK
        elif s <= self.suspicious_max:
            return RiskClassificationBand.SUSPICIOUS
        elif s <= self.high_risk_max:
            return RiskClassificationBand.HIGH_RISK
        return RiskClassificationBand.CRITICAL

    def escalation_from_score(self, score: float) -> EscalationLevel:
        """Map score to legacy EscalationLevel for backwards compatibility."""
        return EscalationLevel.from_score(score)

    def detection_status_from_score(self, score: float) -> DetectionStatus:
        """Map score to DetectionStatus enum."""
        s = max(0.0, min(10.0, float(score)))
        if s >= 7.0:
            return DetectionStatus.CRITICAL
        elif s >= 5.0:
            return DetectionStatus.SUSPICIOUS
        return DetectionStatus.NORMAL


DEFAULT_SCORING_CONFIG = ScoringConfig()


# ---------------------------------------------------------------------------
# Sub-Engine Validation & Auditing
# ---------------------------------------------------------------------------

@dataclass
class ValidatedSubEngineOutput:
    """Audited sub-engine output with integrity verification."""
    subengine_id: str
    name: str
    parent_engine: str
    risk_score: float
    confidence_score: float
    status: DetectionStatus
    explanation: str
    evidence: Dict[str, Any]
    is_valid: bool
    is_missing: bool = False
    validation_note: str = ""
    effective_signal: float = 0.0


def audit_subengine_results(
    raw_results: List[SubEngineResult],
    expected_ids: List[str],
    parent_engine_id: str,
    config: Optional[ScoringConfig] = None,
) -> Tuple[List[ValidatedSubEngineOutput], List[str]]:
    """
    Audits individual sub-engine scores.
    Ensures:
    - Risk is strictly on 0-10 scale.
    - Confidence is strictly on 0-100% scale.
    - Missing results are NOT interpreted as zero risk.
    - Invalid results are flagged.
    - Scores are traceable to evidence.
    Returns (validated_outputs, missing_or_failed_ids).
    """
    cfg = config or DEFAULT_SCORING_CONFIG
    validated: List[ValidatedSubEngineOutput] = []
    missing_or_failed: List[str] = []

    # Map available results by subengine_id
    results_map: Dict[str, SubEngineResult] = {}
    for r in raw_results:
        if isinstance(r, SubEngineResult) and r.subengine_id:
            results_map[r.subengine_id] = r

    for sid in expected_ids:
        if sid not in results_map:
            missing_or_failed.append(sid)
            validated.append(
                ValidatedSubEngineOutput(
                    subengine_id=sid,
                    name=f"Sub-Engine {sid}",
                    parent_engine=parent_engine_id,
                    risk_score=-1.0,  # Explicitly marked unavailable, NOT 0.0
                    confidence_score=0.0,
                    status=DetectionStatus.NORMAL,
                    explanation=f"Sub-engine {sid} was unavailable or failed to execute.",
                    evidence={"missing": True},
                    is_valid=False,
                    is_missing=True,
                    validation_note="Result missing from execution pipeline; cannot be assumed clean.",
                    effective_signal=0.0,
                )
            )
            continue

        raw = results_map[sid]
        # Validate ranges
        try:
            r_val = float(raw.risk_score)
            c_val = float(raw.confidence_score)
        except (TypeError, ValueError):
            missing_or_failed.append(sid)
            validated.append(
                ValidatedSubEngineOutput(
                    subengine_id=sid,
                    name=getattr(raw, "name", sid),
                    parent_engine=parent_engine_id,
                    risk_score=-1.0,
                    confidence_score=0.0,
                    status=DetectionStatus.NORMAL,
                    explanation=f"Sub-engine {sid} produced invalid numeric score.",
                    evidence={"invalid_data": True},
                    is_valid=False,
                    is_missing=True,
                    validation_note="Non-numeric score rejected; not treated as safe.",
                    effective_signal=0.0,
                )
            )
            continue

        # Clamp strictly within bounded specifications
        clamped_r = max(0.0, min(10.0, r_val))
        clamped_c = max(0.0, min(10.0 if c_val <= 1.0 else 100.0, c_val))
        # If confidence was mistakenly passed on a 0-1 scale, scale to 0-100%
        if 0.0 < clamped_c <= 1.0:
            clamped_c *= 100.0

        # Calculate credibility-weighted effective signal
        # High confidence (>=70%): full signal weight
        # Low confidence (<70%): discounted proportional to certainty
        if clamped_c >= cfg.confidence_discount_threshold:
            conf_factor = 1.0
        else:
            conf_factor = max(cfg.min_confidence_floor, clamped_c / cfg.confidence_discount_threshold)

        eff_signal = round(clamped_r * conf_factor, 2)

        validated.append(
            ValidatedSubEngineOutput(
                subengine_id=sid,
                name=raw.name,
                parent_engine=raw.parent_engine,
                risk_score=round(clamped_r, 2),
                confidence_score=round(clamped_c, 1),
                status=raw.status,
                explanation=raw.explanation,
                evidence=dict(raw.evidence) if raw.evidence else {},
                is_valid=True,
                is_missing=False,
                validation_note="Validated and credibility-calibrated.",
                effective_signal=eff_signal,
            )
        )

    return validated, missing_or_failed


# ---------------------------------------------------------------------------
# Correlation & Duplicate Detection within Primary Engine
# ---------------------------------------------------------------------------

def detect_subengine_correlations(
    valid_outputs: List[ValidatedSubEngineOutput],
    parent_engine_id: str,
) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Identifies which sub-engines within the same primary engine are describing
    the same underlying phenomenon versus distinct phenomena.
    Returns:
    - correlation_groups: {primary_sub_id: [correlated_sub_ids]}
    - handling_log: list of notes explaining deduplication
    """
    correlation_groups: Dict[str, List[str]] = {}
    handling_log: List[str] = []

    # Domain-specific known correlated pairs when both are elevated (>= 4.0)
    known_correlated_pairs: Set[Tuple[str, str]] = set()

    if parent_engine_id == "ENGINE_1_TEMPORAL":
        # E1.1 (Periodicity) and E1.2 (Jitter) both reflect beacon interval consistency
        known_correlated_pairs.add(("E1.1", "E1.2"))
    elif parent_engine_id == "ENGINE_2_TRAFFIC":
        # E2.2 (Volume) and E2.4 (Burst Detection) both measure volumetric surges
        known_correlated_pairs.add(("E2.2", "E2.4"))
        # E2.1 (Packet size) and E2.4 (Burst) on identical payload sizes
        known_correlated_pairs.add(("E2.1", "E2.4"))
    elif parent_engine_id == "ENGINE_3_CONNECTION":
        # E3.2 (Port Scan) and E3.3 (Connection Failure) both track SYN sweep behavior
        known_correlated_pairs.add(("E3.2", "E3.3"))

    elevated = [v for v in valid_outputs if v.effective_signal >= 4.0]
    elevated_ids = {v.subengine_id: v for v in elevated}

    paired: Set[str] = set()
    for id_a, id_b in known_correlated_pairs:
        if id_a in elevated_ids and id_b in elevated_ids:
            # Both are elevated: one is primary, one is duplicate/correlated
            sig_a = elevated_ids[id_a].effective_signal
            sig_b = elevated_ids[id_b].effective_signal
            primary = id_a if sig_a >= sig_b else id_b
            secondary = id_b if primary == id_a else id_a

            correlation_groups.setdefault(primary, []).append(secondary)
            paired.add(secondary)
            handling_log.append(
                f"Correlated pair detected: [{id_a}] and [{id_b}] both reflect related telemetry. "
                f"[{primary}] (signal={max(sig_a, sig_b)}) designated primary; [{secondary}] discounted to prevent double-counting."
            )

    return correlation_groups, handling_log


# ---------------------------------------------------------------------------
# Primary Engine Aggregation
# ---------------------------------------------------------------------------

@dataclass
class PrimaryAggregationOutput:
    """Comprehensive result of primary engine aggregation."""
    aggregated_risk_score: float
    aggregated_confidence: float
    classification: RiskClassificationBand
    escalation: EscalationLevel
    status: DetectionStatus
    contributing_subengines: List[str]
    valid_subengine_count: int
    unavailable_subengine_count: int
    calculation_explanation: str
    scoring_metadata: Dict[str, Any]


def aggregate_primary_engine_scores(
    engine_id: str,
    engine_name: str,
    subengine_results: List[SubEngineResult],
    expected_ids: List[str],
    config: Optional[ScoringConfig] = None,
) -> PrimaryAggregationOutput:
    """
    Aggregates sub-engine scores into a unified primary engine assessment.

    Formula:
    1. Effective signal per sub-engine: S_i = R_i * confidence_discount(C_i)
    2. Dominant signal: S_(1) sets base risk.
    3. Corroboration bonus: Delta_R = sum_{j > 1, S_j > noise_floor} omega_j * (S_j - noise_floor)
       where omega_j = 0.20 for independent findings, 0.05 for correlated findings.
    4. Aggregated Risk: R_agg = min(10.0, S_(1) + Delta_R)
    5. Aggregated Confidence: C_agg = (Weighted_C_of_active_findings * completeness_ratio) + corroboration_bonus
    """
    cfg = config or DEFAULT_SCORING_CONFIG

    # Step 1: Audit and validate individual sub-engine scores
    validated, missing_ids = audit_subengine_results(
        raw_results=subengine_results,
        expected_ids=expected_ids,
        parent_engine_id=engine_id,
        config=cfg,
    )

    valid_subengines = [v for v in validated if v.is_valid]
    valid_count = len(valid_subengines)
    unavailable_count = len(missing_ids)
    completeness_ratio = valid_count / len(expected_ids) if expected_ids else 1.0

    # Step 2: Handle edge cases where all sub-engines failed or missing
    if not valid_subengines:
        explanation = (
            f"All {len(expected_ids)} expected sub-engines for {engine_name} were unavailable or failed. "
            "Missing results cannot be interpreted as safe (zero risk)."
        )
        return PrimaryAggregationOutput(
            aggregated_risk_score=5.0,  # Unverified baseline risk
            aggregated_confidence=0.0,  # Zero confidence due to total absence of data
            classification=RiskClassificationBand.SUSPICIOUS,
            escalation=EscalationLevel.SECONDARY_INVESTIGATION,
            status=DetectionStatus.SUSPICIOUS,
            contributing_subengines=[],
            valid_subengine_count=0,
            unavailable_subengine_count=unavailable_count,
            calculation_explanation=explanation,
            scoring_metadata={
                "error": "all_subengines_unavailable",
                "missing_ids": missing_ids,
            },
        )

    # Step 3: Correlation & Deduplication analysis
    correlation_groups, correlation_notes = detect_subengine_correlations(
        valid_outputs=valid_subengines,
        parent_engine_id=engine_id,
    )
    correlated_secondary_ids: Set[str] = set()
    for sec_list in correlation_groups.values():
        correlated_secondary_ids.update(sec_list)

    # Sort valid subengines by effective signal descending
    sorted_sub = sorted(valid_subengines, key=lambda x: x.effective_signal, reverse=True)
    dominant = sorted_sub[0]
    dominant_signal = dominant.effective_signal

    # Step 4: Non-Dilutive Corroboration Synthesis
    corroboration_delta = 0.0
    contributing_ids = [dominant.subengine_id] if dominant.risk_score > 0.0 else []
    evidence_considered: List[Dict[str, Any]] = []
    evidence_excluded: List[Dict[str, Any]] = []

    evidence_considered.append({
        "subengine_id": dominant.subengine_id,
        "role": "DOMINANT_SIGNAL",
        "raw_risk": dominant.risk_score,
        "confidence": dominant.confidence_score,
        "effective_signal": dominant.effective_signal,
    })

    for sub in sorted_sub[1:]:
        if sub.effective_signal <= cfg.baseline_noise_floor:
            # Below noise floor; does not boost risk
            evidence_excluded.append({
                "subengine_id": sub.subengine_id,
                "reason": "BELOW_BASELINE_NOISE_FLOOR",
                "raw_risk": sub.risk_score,
                "effective_signal": sub.effective_signal,
            })
            continue

        if sub.subengine_id in correlated_secondary_ids:
            weight = cfg.correlated_corroboration_weight  # 0.05
            role = "CORRELATED_CORROBORATION"
        else:
            weight = cfg.independent_corroboration_weight  # 0.20
            role = "INDEPENDENT_CORROBORATION"

        boost = weight * (sub.effective_signal - cfg.baseline_noise_floor)
        corroboration_delta += boost
        contributing_ids.append(sub.subengine_id)

        evidence_considered.append({
            "subengine_id": sub.subengine_id,
            "role": role,
            "raw_risk": sub.risk_score,
            "confidence": sub.confidence_score,
            "effective_signal": sub.effective_signal,
            "weight": weight,
            "boost": round(boost, 3),
        })

    # Aggregated risk score
    raw_aggregated_risk = dominant_signal + corroboration_delta
    aggregated_risk = round(max(0.0, min(10.0, raw_aggregated_risk)), 2)

    # Step 5: Independent Confidence Aggregation
    # Compute active finding confidence (weighted by effective signal)
    active_findings = [s for s in valid_subengines if s.effective_signal >= cfg.baseline_noise_floor]
    if active_findings:
        sum_signal = sum(s.effective_signal for s in active_findings)
        weighted_conf = sum(s.effective_signal * s.confidence_score for s in active_findings) / sum_signal
    else:
        weighted_conf = sum(s.confidence_score for s in valid_subengines) / len(valid_subengines)

    # Corroboration confidence bonus: if multiple independent findings corroborate, certainty increases
    independent_active = [
        s for s in active_findings
        if s.subengine_id not in correlated_secondary_ids
    ]
    conf_corroboration_bonus = 5.0 if len(independent_active) >= 2 else 0.0

    # Completeness penalty: missing sub-engines directly reduce confidence
    calibrated_confidence = (weighted_conf * completeness_ratio) + conf_corroboration_bonus
    aggregated_confidence = round(max(0.0, min(100.0, calibrated_confidence)), 1)

    # Step 6: Classification & Escalation
    classification = cfg.classify_score(aggregated_risk)
    escalation = cfg.escalation_from_score(aggregated_risk)
    detection_status = cfg.detection_status_from_score(aggregated_risk)

    # Step 7: Transparent Calculation Explanation
    explanation_parts = []
    explanation_parts.append(
        f"Dominant signal from [{dominant.subengine_id}] (Risk={dominant.risk_score}/10, Conf={dominant.confidence_score}%, Eff={dominant.effective_signal})."
    )
    if corroboration_delta > 0.0:
        explanation_parts.append(
            f"Corroborating findings added +{round(corroboration_delta, 2)} risk ({len(contributing_ids)-1} additional contributing module(s))."
        )
    if correlation_notes:
        explanation_parts.extend(correlation_notes)
    if unavailable_count > 0:
        explanation_parts.append(
            f"Warning: {unavailable_count} sub-engine(s) ({', '.join(missing_ids)}) were unavailable. "
            f"Data completeness is {int(completeness_ratio*100)}%; missing checks are not assumed safe."
        )

    explanation_str = " ".join(explanation_parts)

    scoring_metadata = {
        "engine_id": engine_id,
        "input_scores": {v.subengine_id: v.risk_score for v in valid_subengines},
        "input_confidences": {v.subengine_id: v.confidence_score for v in valid_subengines},
        "effective_signals": {v.subengine_id: v.effective_signal for v in valid_subengines},
        "evidence_considered": evidence_considered,
        "evidence_excluded": evidence_excluded,
        "correlation_groups": correlation_groups,
        "aggregation_method": "Credibility-Weighted Corroboration Operator",
        "dominant_subengine": dominant.subengine_id,
        "dominant_effective_signal": dominant_signal,
        "corroboration_delta": round(corroboration_delta, 3),
        "valid_subengine_count": valid_count,
        "unavailable_subengine_count": unavailable_count,
        "completeness_ratio": round(completeness_ratio, 2),
        "classification": classification.value,
        "escalation": escalation.value,
    }

    return PrimaryAggregationOutput(
        aggregated_risk_score=aggregated_risk,
        aggregated_confidence=aggregated_confidence,
        classification=classification,
        escalation=escalation,
        status=detection_status,
        contributing_subengines=contributing_ids,
        valid_subengine_count=valid_count,
        unavailable_subengine_count=unavailable_count,
        calculation_explanation=explanation_str,
        scoring_metadata=scoring_metadata,
    )


# ---------------------------------------------------------------------------
# Engine 4 — Final Decision & Multi-Engine Correlation Aggregation
# ---------------------------------------------------------------------------

@dataclass
class Engine4AggregationOutput:
    """Comprehensive verdict from Engine 4 master synthesis."""
    overall_risk_score: float
    overall_confidence_score: float
    final_classification: FinalClassification
    classification_band: RiskClassificationBand
    executive_summary: str
    correlations: List[CorrelationItem]
    evidence_quality_score: float
    recommended_actions: List[str]
    calculation_explanation: str
    contributing_engines: List[str]
    unavailable_engine_count: int
    scoring_metadata: Dict[str, Any]


def aggregate_engine4_final_decision(
    engine_results: Dict[str, PrimaryEngineResult],
    flows: List[FlowRecord],
    host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
    context: Optional[Dict[str, Any]] = None,
    config: Optional[ScoringConfig] = None,
) -> Engine4AggregationOutput:
    """
    Synthesizes the three primary engines and their underlying evidence into the final decision.

    Guarantees:
    - Verified threat intelligence match is never diluted or averaged down.
    - Strong, independently supported findings retain appropriate influence.
    - Multiple independent suspicious findings increase risk appropriately.
    - Related findings describing the same underlying event do not inflate risk repeatedly.
    - Missing engine results are not treated as safe.
    - Low confidence is not presented as high certainty.
    - High behavioral risk score does not automatically mean confirmed malware.
    - Provides human-readable explanation of which evidence drove the score.
    """
    cfg = config or DEFAULT_SCORING_CONFIG
    expected_engines = ["ENGINE_1_TEMPORAL", "ENGINE_2_TRAFFIC", "ENGINE_3_CONNECTION"]

    # Step 1: Audit primary engine completeness
    available_engines: Dict[str, PrimaryEngineResult] = {}
    missing_engines: List[str] = []

    for eid in expected_engines:
        if eid in engine_results and engine_results[eid] is not None:
            available_engines[eid] = engine_results[eid]
        else:
            missing_engines.append(eid)

    completeness_factor = len(available_engines) / len(expected_engines)

    # Step 2: Check for Confirmed Threat Intel Match in Engine 3
    # Rule: Verified malicious threat intelligence match must NOT be averaged down
    confirmed_threat_intel = False
    threat_match_details: List[Dict[str, Any]] = []

    e3 = available_engines.get("ENGINE_3_CONNECTION")
    if e3:
        for sub in e3.subengine_results:
            if sub.subengine_id == "E3.4" and sub.evidence.get("confirmed_match"):
                confirmed_threat_intel = True
                threat_match_details = sub.evidence.get("matches", [])

    # Step 3: Compute Effective Primary Signals with Confidence Weighting
    effective_primary_signals: Dict[str, float] = {}
    for eid, eng in available_engines.items():
        conf = eng.confidence_score
        r = eng.risk_score
        # Confidence discount
        if conf >= cfg.confidence_discount_threshold:
            factor = 1.0
        else:
            factor = max(cfg.min_confidence_floor, conf / cfg.confidence_discount_threshold)
        effective_primary_signals[eid] = round(r * factor, 2)

    # Step 4: Host-Level Cross-Engine Correlation & Evidence Extraction
    host_findings: Dict[str, List[str]] = {}
    host_engines: Dict[str, Set[str]] = {}
    host_max_risk: Dict[str, float] = {}
    evidence_considered: List[Dict[str, Any]] = []
    evidence_excluded: List[Dict[str, Any]] = []

    for eng_key, eng in available_engines.items():
        for sub in eng.subengine_results:
            if sub.risk_score >= 4.0:
                ev = sub.evidence
                extracted_ips = set()
                for k, v in ev.items():
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, dict):
                                for ip_key in ("source_ip", "target_ip", "ip", "src_ip", "dst_ip"):
                                    if ip_key in item and item[ip_key]:
                                        extracted_ips.add(str(item[ip_key]))
                    elif isinstance(v, dict):
                        for ip_key in ("source_ip", "target_ip", "ip"):
                            if ip_key in v and v[ip_key]:
                                extracted_ips.add(str(v[ip_key]))

                for hip in extracted_ips:
                    host_findings.setdefault(hip, []).append(f"[{sub.subengine_id}] {sub.explanation}")
                    host_engines.setdefault(hip, set()).add(eng_key)
                    host_max_risk[hip] = max(host_max_risk.get(hip, 0.0), sub.risk_score)

    correlations: List[CorrelationItem] = []
    for hip, findings in host_findings.items():
        engines_involved = list(host_engines.get(hip, set()))
        independence = min(1.0, len(engines_involved) / 3.0)
        correlations.append(
            CorrelationItem(
                entity_id=hip,
                entity_type="HOST",
                contributing_engines=engines_involved,
                max_risk_score=host_max_risk.get(hip, 0.0),
                correlated_findings=findings,
                evidence_independence_score=round(independence, 2),
            )
        )
    correlations.sort(key=lambda x: (len(x.contributing_engines), x.max_risk_score), reverse=True)

    # Collect all 12 individual sub-engine contributions
    subengine_contributions: Dict[str, Dict[str, Any]] = {}
    for eng_k, eng_obj in available_engines.items():
        for sub in eng_obj.subengine_results:
            subengine_contributions[sub.subengine_id] = {
                "subengine_id": sub.subengine_id,
                "name": sub.name,
                "parent_engine": sub.parent_engine,
                "risk_score": sub.risk_score,
                "confidence_score": sub.confidence_score,
                "status": sub.status.value,
                "explanation": sub.explanation,
            }

    # Step 5: Overall Risk Scoring Synthesis
    contributing_engines: List[str] = []
    calculation_steps: List[str] = []

    # Extra dimensional factors from context
    data_loss_contribution = 0.0
    traffic_rate_contribution = 0.0
    multi_host_contribution = 0.0

    if context:
        # 1. Data-Loss contribution
        dl_report = context.get("data_loss")
        if dl_report:
            loss_pct = getattr(dl_report, "overall_loss_percentage", None)
            if loss_pct is not None and loss_pct > 2.0:
                if loss_pct <= 10.0:
                    data_loss_contribution = round((loss_pct - 2.0) * 0.15, 2)
                else:
                    data_loss_contribution = round(1.2 + min(1.3, (loss_pct - 10.0) * 0.08), 2)
                calculation_steps.append(
                    f"Data loss factor added +{data_loss_contribution} risk ({loss_pct:.1f}% packet loss observed)."
                )

        # 2. Traffic rate surge contribution
        rate_flags = context.get("dynamic_flags", [])
        if rate_flags:
            crit_flags = [f for f in rate_flags if getattr(f, "severity", None) in ("CRITICAL", "HIGH")]
            if crit_flags:
                traffic_rate_contribution = 1.0
                calculation_steps.append(
                    f"Dynamic traffic rate surge added +{traffic_rate_contribution} risk ({len(crit_flags)} rate anomaly flag(s))."
                )

    # 3. Multi-host correlation contribution
    suspicious_hosts = [c for c in correlations if c.max_risk_score >= 5.0]
    if len(suspicious_hosts) >= 2 and not confirmed_threat_intel:
        multi_host_contribution = round(min(1.5, (len(suspicious_hosts) - 1) * 0.5), 2)
        calculation_steps.append(
            f"Multi-host correlation added +{multi_host_contribution} risk ({len(suspicious_hosts)} distinct suspicious client hosts)."
        )

    if confirmed_threat_intel:
        # Rule 6: Verified threat-intel match is never averaged down
        top_match = threat_match_details[0] if threat_match_details else {}
        match_conf = float(top_match.get("confidence", 98.0))
        overall_risk = max(9.5, max(effective_primary_signals.values()) if effective_primary_signals else 9.5)
        overall_confidence = match_conf
        final_classification = FinalClassification.CONFIRMED_INDICATOR_MATCH
        classification_band = RiskClassificationBand.CRITICAL
        contributing_engines = ["ENGINE_3_CONNECTION"]
        calculation_steps.append(
            f"CONFIRMED THREAT INTEL OVERRIDE: Verified malicious indicator match ({top_match.get('category', 'C2')}) "
            f"targeting {top_match.get('ip', 'target')} with {match_conf}% confidence. Risk clamped to {overall_risk}/10."
        )
    else:
        # Sort available primary signals
        sorted_signals = sorted(effective_primary_signals.items(), key=lambda x: x[1], reverse=True)

        if not sorted_signals:
            # All primary engines missing
            overall_risk = 5.0
            overall_confidence = 0.0
            final_classification = FinalClassification.SUSPICIOUS
            classification_band = RiskClassificationBand.SUSPICIOUS
            calculation_steps.append("All primary engines missing; risk set to unverified baseline (5.0/10).")
        else:
            dominant_eid, dominant_sig = sorted_signals[0]
            contributing_engines.append(dominant_eid)
            calculation_steps.append(
                f"Dominant engine is {dominant_eid} with effective signal {dominant_sig}/10 (raw risk={available_engines[dominant_eid].risk_score}, conf={available_engines[dominant_eid].confidence_score}%)."
            )

            # Cross-engine corroboration bonus
            cross_corroboration_delta = 0.0
            for eid, sig in sorted_signals[1:]:
                if sig > cfg.low_risk_max:  # > 4.9 (suspicious or higher)
                    contributing_engines.append(eid)
                    # Check if findings correlate to the same host across distinct domains
                    host_corroborated = any(
                        len(c.contributing_engines) >= 2 and eid in c.contributing_engines
                        for c in correlations
                    )
                    independence_weight = cfg.cross_engine_corroboration_weight if host_corroborated else (cfg.cross_engine_corroboration_weight * 0.5)
                    boost = independence_weight * (sig - cfg.low_risk_max)
                    cross_corroboration_delta += boost
                    calculation_steps.append(
                        f"Cross-engine corroboration from {eid} (signal={sig}) added +{round(boost, 2)} risk."
                    )
                else:
                    evidence_excluded.append({
                        "engine_id": eid,
                        "signal": sig,
                        "reason": "SIGNAL_BELOW_CORROBORATION_THRESHOLD",
                    })

            # Synthesis combining dominant signal + cross-engine corroboration + data loss + rate surge + multi-host
            combined_risk = (
                dominant_sig
                + cross_corroboration_delta
                + data_loss_contribution
                + traffic_rate_contribution
                + multi_host_contribution
            )
            overall_risk = round(min(10.0, max(0.0, combined_risk)), 2)
            classification_band = cfg.classify_score(overall_risk)

            # Map to FinalClassification
            # Rule 7: High behavioral risk does not mean confirmed malware without verified intel
            if classification_band in (RiskClassificationBand.CRITICAL, RiskClassificationBand.HIGH_RISK):
                final_classification = FinalClassification.HIGH_RISK
            elif classification_band == RiskClassificationBand.SUSPICIOUS:
                final_classification = FinalClassification.SUSPICIOUS
            else:
                final_classification = FinalClassification.BENIGN

            # Confidence calculation
            active_confs = [
                available_engines[eid].confidence_score
                for eid in contributing_engines
                if eid in available_engines
            ]
            base_conf = sum(active_confs) / len(active_confs) if active_confs else 50.0

            # Corroboration bonus for confidence: multiple independent engines agreeing
            corroboration_conf_bonus = 10.0 if len(contributing_engines) >= 2 else 0.0
            overall_confidence = round(
                max(10.0, min(100.0, (base_conf * completeness_factor) + corroboration_conf_bonus)),
                1
            )

    # Missing engines audit note
    if missing_engines:
        calculation_steps.append(
            f"Warning: Primary engine(s) {', '.join(missing_engines)} were missing. "
            f"Data completeness factor is {int(completeness_factor*100)}%; missing domains are not assumed safe."
        )

    # Evidence quality score
    evidence_quality = round(overall_confidence * completeness_factor, 1)

    # Step 6: Formulate Actionable Recommendations & Executive Summary
    recommended_actions: List[str] = []
    if final_classification == FinalClassification.CONFIRMED_INDICATOR_MATCH:
        top_threat = threat_match_details[0] if threat_match_details else {}
        threat_ip = top_threat.get("ip", "Flagged Host")
        recommended_actions.append(f"CRITICAL: Isolate host {threat_ip} immediately (simulate containment).")
        recommended_actions.append(f"Block communication to verified {top_threat.get('category', 'C2')} at perimeter.")
        recommended_actions.append("Capture full volatile memory dump and initiate incident response runbook.")
        summary = (
            f"CONFIRMED THREAT MATCH: Host {threat_ip} established communication with verified malicious "
            f"infrastructure ({top_threat.get('category', 'C2')} attributed to '{top_threat.get('threat_actor', 'Unknown')}'). "
            f"Overall Risk Score: {overall_risk}/10 (Confidence: {overall_confidence}%). Immediate containment mandated."
        )
    elif final_classification == FinalClassification.HIGH_RISK:
        top_host = correlations[0].entity_id if correlations else "Target Host"
        recommended_actions.append(f"HIGH: Quarantine affected host {top_host} to containment segment.")
        recommended_actions.append("Inspect outbound encrypted byte streams for unauthorized cryptographic exfiltration.")
        recommended_actions.append("Enforce temporary port and rate limiting on affected switch access ports.")
        summary = (
            f"HIGH RISK ANOMALY DETECTED: Multi-vector telemetry divergence uncovered "
            f"(Peak effective signal {overall_risk}/10, Confidence: {overall_confidence}%). "
            f"Host {top_host} exhibits anomalous traffic/connection behaviors characteristic of active reconnaissance or exfiltration."
        )
    elif final_classification == FinalClassification.SUSPICIOUS:
        recommended_actions.append("Schedule secondary automated investigation and deep packet inspection.")
        recommended_actions.append("Enable verbose flow-level packet logging for flagged communication endpoints.")
        recommended_actions.append("Monitor destination endpoints for recurring timing periodicity or jitter drift.")
        summary = (
            f"SUSPICIOUS ACTIVITY: Engine metrics exceed baseline variance thresholds (Risk Score: {overall_risk}/10, Confidence: {overall_confidence}%). "
            "Secondary forensic investigation triggered. No definitive malicious confirmation at this stage."
        )
    else:
        recommended_actions.append("No immediate intervention required. Network operating within baseline parameters.")
        summary = (
            f"BENIGN TELEMETRY: All available detection vectors report normal operational metrics "
            f"(Overall Risk: {overall_risk}/10, Confidence: {overall_confidence}%). Network traffic reflects standard authorized behavior."
        )

    scoring_metadata = {
        "input_engine_scores": {eid: eng.risk_score for eid, eng in available_engines.items()},
        "input_engine_confidences": {eid: eng.confidence_score for eid, eng in available_engines.items()},
        "effective_signals": effective_primary_signals,
        "subengine_contributions": subengine_contributions,
        "data_loss_contribution": data_loss_contribution,
        "traffic_rate_contribution": traffic_rate_contribution,
        "multi_host_contribution": multi_host_contribution,
        "applied_weights": {
            "confidence_discount_threshold": cfg.confidence_discount_threshold,
            "independent_corroboration_weight": cfg.independent_corroboration_weight,
            "cross_engine_corroboration_weight": cfg.cross_engine_corroboration_weight,
            "data_loss_max_weight": 2.5,
            "rate_surge_max_weight": 1.5,
        },
        "evidence_considered": evidence_considered,
        "evidence_excluded": evidence_excluded,
        "missing_engines": missing_engines,
        "completeness_factor": round(completeness_factor, 2),
        "confirmed_threat_intel": confirmed_threat_intel,
        "contributing_engines": contributing_engines,
        "aggregation_method": "Credibility-Weighted Corroboration Operator",
        "final_score": overall_risk,
        "final_confidence": overall_confidence,
        "final_classification": final_classification.value,
        "classification_band": classification_band.value,
    }

    return Engine4AggregationOutput(
        overall_risk_score=overall_risk,
        overall_confidence_score=overall_confidence,
        final_classification=final_classification,
        classification_band=classification_band,
        executive_summary=summary,
        correlations=correlations,
        evidence_quality_score=evidence_quality,
        recommended_actions=recommended_actions,
        calculation_explanation=" ".join(calculation_steps),
        contributing_engines=contributing_engines,
        unavailable_engine_count=len(missing_engines),
        scoring_metadata=scoring_metadata,
    )
