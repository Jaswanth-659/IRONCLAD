"""
Unit tests for ironclad.risk.
"""

from ironclad.config.settings import RiskConfig
from ironclad.core.types import (
    AnomalyScore,
    FlowKey,
    FlowRecord,
    GraphNodeMetrics,
    Protocol,
    RiskSeverity,
)
from ironclad.risk.rules import (
    EncryptedExfiltrationRule,
    FanOutReconRule,
    RuleEngine,
    SynScanRule,
)
from ironclad.risk.scorer import RiskScorer


def test_syn_scan_rule():
    rule = SynScanRule(min_syn_count=5, syn_ack_ratio_threshold=5.0)

    # Benign flow with normal handshake
    normal_flow = FlowRecord(
        key=FlowKey("1.1.1.1", "2.2.2.2", 1234, 80, Protocol.TCP),
        canonical_id="normal",
        start_time=1.0,
        end_time=2.0,
        tcp_flags={"SYN": 1, "ACK": 10, "FIN": 1, "RST": 0, "PSH": 5, "URG": 0},
    )
    assert rule.evaluate_flow(normal_flow) is None

    # Attack flow with high SYN and 0 ACK
    scan_flow = FlowRecord(
        key=FlowKey("1.1.1.1", "2.2.2.2", 1234, 80, Protocol.TCP),
        canonical_id="attack",
        start_time=1.0,
        end_time=2.0,
        tcp_flags={"SYN": 20, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0},
    )
    finding = rule.evaluate_flow(scan_flow)
    assert finding is not None
    assert finding.severity == RiskSeverity.HIGH
    assert "Port Scan" in finding.rule_name


def test_encrypted_exfiltration_rule():
    rule = EncryptedExfiltrationRule(entropy_threshold=7.4, min_bytes=200)

    # Exfiltration on port 9999
    exfil_flow = FlowRecord(
        key=FlowKey("192.168.1.5", "198.51.100.1", 5000, 9999, Protocol.TCP),
        canonical_id="exfil",
        start_time=1.0,
        end_time=2.0,
        byte_count=5000,
        payload_entropies=[7.85, 7.90],
    )
    finding = rule.evaluate_flow(exfil_flow)
    assert finding is not None
    assert finding.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)


def test_fan_out_rule():
    rule = FanOutReconRule(fan_out_threshold=8.0, min_peers=5)
    host_metrics = GraphNodeMetrics(
        ip="10.0.0.99",
        out_degree=20,
        in_degree=1,
        fan_out_ratio=10.0,
        unique_peers=15,
    )
    finding = rule.evaluate_host(host_metrics)
    assert finding is not None
    assert finding.severity == RiskSeverity.HIGH


def test_risk_scorer_flow_and_global():
    scorer = RiskScorer(config=RiskConfig())

    flow = FlowRecord(
        key=FlowKey("10.0.0.1", "10.0.0.2", 4000, 9999, Protocol.TCP),
        canonical_id="test_flow",
        start_time=1.0,
        end_time=2.0,
        byte_count=10000,
        payload_entropies=[7.9],
        tcp_flags={"SYN": 15, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0},
    )

    anom = AnomalyScore(
        detector="Test",
        is_anomaly=True,
        score=0.85,
        confidence=0.9,
        explanation="Abnormal traffic volume",
    )

    risk = scorer.score_flow(flow, anomaly_score=anom)
    assert risk.score > 50.0
    assert risk.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
    assert len(risk.findings) >= 2

    global_risk = scorer.compute_global_risk([risk], [])
    assert global_risk.score > 0.0
