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
)


class DecisionCorrelationEngine:
    """
    ENGINE 4: The master forensic synthesizer.
    Evaluates evidence independence, correlates host anomalies across engines,
    and produces defensible cybersecurity classifications without simplistic averaging.
    """

    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        engine_results: Dict[str, PrimaryEngineResult],
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> DecisionReport:
        t0 = time.perf_counter()

        # Step 1: Collect primary scores and findings
        e1 = engine_results.get("ENGINE_1_TEMPORAL")
        e2 = engine_results.get("ENGINE_2_TRAFFIC")
        e3 = engine_results.get("ENGINE_3_CONNECTION")

        s1 = e1.risk_score if e1 else 0.0
        s2 = e2.risk_score if e2 else 0.0
        s3 = e3.risk_score if e3 else 0.0

        # Step 2: Check for Confirmed Threat Intel Match
        # Threat intel match directly escalates to CONFIRMED_INDICATOR_MATCH
        confirmed_threat_intel = False
        threat_match_details = []
        if e3:
            for sub in e3.subengine_results:
                if sub.subengine_id == "E3.4" and sub.evidence.get("confirmed_match"):
                    confirmed_threat_intel = True
                    threat_match_details = sub.evidence.get("matches", [])

        # Step 3: Host-Level Cross-Engine Correlation
        # Correlate suspicious activities originating from or targeting the same host IP
        host_findings: Dict[str, List[str]] = {}
        host_engines: Dict[str, Set[str]] = {}
        host_max_risk: Dict[str, float] = {}

        for eng_key, eng in engine_results.items():
            for sub in eng.subengine_results:
                if sub.risk_score >= 4.5:
                    # Scan evidence for host references
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
            # Evidence independence score is higher when multiple distinct primary engines flag the same host
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

        # Step 4: Evidence Independence & Quality Evaluation
        # If multiple engines trigger independently on different telemetry vectors, confidence is elevated
        multi_engine_concurrence = (s1 >= 5.0) + (s2 >= 5.0) + (s3 >= 5.0)
        base_quality = 70.0
        if multi_engine_concurrence >= 2:
            base_quality += 20.0
        if confirmed_threat_intel:
            base_quality = 98.0
        evidence_quality = min(100.0, base_quality)

        # Step 5: Non-Linear Overall Risk Scoring
        # Cybersecurity heuristic: An acute critical signal on one vector (e.g. s3=9.5) must NOT be diluted
        # by inactivity on an unrelated vector (e.g. s1=1.0).
        max_primary = max(s1, s2, s3)
        secondary_elevated = sum(1 for s in (s1, s2, s3) if s >= 5.0)

        if confirmed_threat_intel:
            overall_risk = max(9.5, max_primary)
            classification = FinalClassification.CONFIRMED_INDICATOR_MATCH
        elif max_primary >= 7.0 or multi_engine_concurrence >= 2:
            # High priority escalation or multi-engine convergence
            escalation_boost = 0.5 * (multi_engine_concurrence - 1) if multi_engine_concurrence > 1 else 0.0
            overall_risk = round(min(10.0, max_primary + escalation_boost), 2)
            classification = FinalClassification.HIGH_RISK
        elif max_primary >= 5.0 or secondary_elevated >= 1:
            overall_risk = round(max_primary, 2)
            classification = FinalClassification.SUSPICIOUS
        else:
            # All engines normal
            overall_risk = round(max_primary, 2)
            classification = FinalClassification.BENIGN

        # Step 6: Formulate Actionable Recommendations & Executive Summary
        recommended_actions = []
        if classification == FinalClassification.CONFIRMED_INDICATOR_MATCH:
            top_threat = threat_match_details[0] if threat_match_details else {}
            threat_ip = top_threat.get("ip", "Flagged Host")
            recommended_actions.append(f"CRITICAL: Isolate host {threat_ip} immediately (simulate containment).")
            recommended_actions.append(f"Block communication to verified {top_threat.get('category', 'C2')} at perimeter.")
            recommended_actions.append("Capture full volatile memory dump and initiate incident response runbook.")
            summary = (
                f"CONFIRMED THREAT MATCH: Host {threat_ip} established communication with verified malicious "
                f"infrastructure ({top_threat.get('category', 'C2')} attributed to '{top_threat.get('threat_actor', 'Unknown')}'). "
                f"Overall Risk Score: {overall_risk}/10. Immediate containment mandated."
            )
        elif classification == FinalClassification.HIGH_RISK:
            top_host = correlations[0].entity_id if correlations else "Target Host"
            recommended_actions.append(f"HIGH: Quarantine affected host {top_host} to containment segment.")
            recommended_actions.append("Inspect outbound encrypted byte streams for unauthorized cryptographic exfiltration.")
            recommended_actions.append("Enforce temporary port and rate limiting on affected switch access ports.")
            summary = (
                f"HIGH RISK ANOMALY DETECTED: Multi-vector telemetry divergence uncovered "
                f"(Convergence across {multi_engine_concurrence} engine(s), peak risk {max_primary}/10). "
                f"Host {top_host} exhibits anomalous traffic/connection behaviors characteristic of active reconnaissance or exfiltration."
            )
        elif classification == FinalClassification.SUSPICIOUS:
            recommended_actions.append("Schedule secondary automated investigation and deep packet inspection.")
            recommended_actions.append("Enable verbose flow-level packet logging for flagged communication endpoints.")
            recommended_actions.append("Monitor destination endpoints for recurring timing periodicity or jitter drift.")
            summary = (
                f"SUSPICIOUS ACTIVITY: Engine metrics exceed baseline variance thresholds (Peak Score: {max_primary}/10). "
                "Secondary forensic investigation triggered. No definitive malicious confirmation at this stage."
            )
        else:
            recommended_actions.append("No immediate intervention required. Network operating within baseline parameters.")
            summary = (
                f"BENIGN TELEMETRY: All primary engines (Temporal, Traffic, Connection) report normal operational metrics "
                f"(Peak Risk: {max_primary}/10). Network traffic reflects standard authorized behavior."
            )

        # Timeline events
        timeline_events = []
        timeline_events.append({
            "stage": "INGESTION_AND_PARSING",
            "status": "COMPLETED",
            "detail": f"Processed {len(flows)} flows across session boundaries.",
        })
        for eng_key, eng in engine_results.items():
            timeline_events.append({
                "stage": eng.name,
                "status": eng.status.value,
                "risk_score": eng.risk_score,
                "escalation": eng.escalation.value,
                "detail": eng.explanation,
            })
        timeline_events.append({
            "stage": "DECISION_AND_CORRELATION",
            "status": classification.value,
            "overall_risk": overall_risk,
            "detail": summary,
        })

        return DecisionReport(
            overall_risk_score=overall_risk,
            final_classification=classification,
            executive_summary=summary,
            engine_results=engine_results,
            correlations=correlations,
            evidence_quality_score=evidence_quality,
            recommended_actions=recommended_actions,
            timeline_events=timeline_events,
        )
