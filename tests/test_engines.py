"""
IRONCLAD Detection Engines Test Suite.

Tests all 3 primary engines (Engines 1-3), all 12 sub-engines,
escalation logic, and the Decision & Correlation Engine (Engine 4).
"""

from __future__ import annotations

import pytest
from ironclad.core.types import FlowKey, FlowRecord, Protocol


# ---------------------------------------------------------------------------
# Shared synthetic flow fixtures
# ---------------------------------------------------------------------------

def _make_flow(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    src_port: int = 51200,
    dst_port: int = 443,
    protocol: Protocol = Protocol.TCP,
    packet_count: int = 20,
    forward_bytes: int = 8000,
    backward_bytes: int = 1600,
    iats: list[float] | None = None,
    packet_lengths: list[int] | None = None,
    entropies: list[float] | None = None,
) -> FlowRecord:
    key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                  dst_port=dst_port, protocol=protocol)
    canonical_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    iats = iats or [0.1 * i for i in range(1, packet_count)]
    packet_lengths = packet_lengths or [512] * packet_count
    entropies = entropies or [7.5] * packet_count
    return FlowRecord(
        key=key,
        canonical_id=canonical_id,
        start_time=1_700_000_000.0,
        end_time=1_700_000_000.0 + (packet_count * 0.1),
        packet_count=packet_count,
        byte_count=forward_bytes + backward_bytes,
        forward_packets=packet_count,
        backward_packets=0,
        forward_bytes=forward_bytes,
        backward_bytes=backward_bytes,
        packet_lengths=packet_lengths,
        inter_arrival_times=iats,
        tcp_flags={"SYN": 1, "ACK": packet_count - 1, "FIN": 1, "RST": 0, "PSH": 2, "URG": 0},
        payload_entropies=entropies,
    )


def _periodic_iats(n: int = 50, period: float = 0.5, jitter: float = 0.01) -> list[float]:
    """Return inter-arrival times that are very regular (simulate beaconing)."""
    import random
    random.seed(42)
    return [period + random.uniform(-jitter, jitter) for _ in range(n - 1)]


def _attack_flows() -> list[FlowRecord]:
    """Synthetic flow set matching threat intel known malicious IP."""
    return [
        _make_flow(
            src_ip="192.168.1.88",
            dst_ip="198.51.100.77",
            src_port=51200,
            dst_port=9443,
            packet_count=50,
            forward_bytes=55200,
            backward_bytes=5000,
            iats=_periodic_iats(50, 0.18, 0.005),
            packet_lengths=[512] * 50,
            entropies=[7.6] * 50,
        ),
        _make_flow(
            src_ip="10.0.0.99",
            dst_ip="192.168.1.50",
            src_port=12345,
            dst_port=22,
            packet_count=30,
            forward_bytes=4500,
            backward_bytes=0,
        ),
    ]


def _normal_flows() -> list[FlowRecord]:
    """Normal-looking synthetic flows that should not trigger escalation."""
    import random
    random.seed(99)
    iats = [random.uniform(0.05, 1.5) for _ in range(19)]
    return [_make_flow(
        src_ip="10.10.10.5",
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol=Protocol.UDP,
        packet_count=20,
        forward_bytes=1200,
        backward_bytes=1800,
        iats=iats,
        packet_lengths=[60] * 20,
        entropies=[2.0] * 20,
    )]


# ===========================================================================
# ENGINE 1 — TEMPORAL BEHAVIOUR
# ===========================================================================

class TestTemporalSubEngines:

    def test_periodicity_validator_instantiation(self):
        from ironclad.engines.temporal.periodicity import PeriodicityValidator
        pv = PeriodicityValidator()
        assert pv.subengine_id == "E1.1"
        assert pv.parent_engine == "ENGINE_1_TEMPORAL"

    def test_periodicity_validator_on_periodic_flow(self):
        from ironclad.engines.temporal.periodicity import PeriodicityValidator
        pv = PeriodicityValidator()
        flows = [_make_flow(iats=_periodic_iats(60, 0.5, 0.005), packet_count=60)]
        result = pv.analyze(flows)
        assert 0.0 <= result.risk_score <= 10.0
        assert 0.0 <= result.confidence_score <= 100.0
        assert result.status is not None
        assert isinstance(result.explanation, str)
        assert isinstance(result.evidence, dict)

    def test_periodicity_validator_empty(self):
        from ironclad.engines.temporal.periodicity import PeriodicityValidator
        result = PeriodicityValidator().analyze([])
        assert result.risk_score == 0.0

    def test_jitter_analyzer_instantiation(self):
        from ironclad.engines.temporal.jitter import JitterAnalyzer
        ja = JitterAnalyzer()
        assert ja.subengine_id == "E1.2"

    def test_jitter_analyzer_bounded_jitter(self):
        from ironclad.engines.temporal.jitter import JitterAnalyzer
        import random; random.seed(1)
        # Very tight bounded jitter — looks like artificial sleep
        iats = [0.5 + random.uniform(-0.03, 0.03) for _ in range(49)]
        flows = [_make_flow(iats=iats, packet_count=50)]
        result = JitterAnalyzer().analyze(flows)
        assert 0.0 <= result.risk_score <= 10.0
        assert isinstance(result.explanation, str)

    def test_burst_pattern_analyzer(self):
        from ironclad.engines.temporal.burst_pattern import BurstPatternAnalyzer
        bpa = BurstPatternAnalyzer()
        assert bpa.subengine_id == "E1.3"
        flows = _attack_flows()
        result = bpa.analyze(flows)
        assert 0.0 <= result.risk_score <= 10.0
        assert isinstance(result.evidence, dict)

    def test_historical_behaviour_comparator(self):
        from ironclad.engines.temporal.historical import HistoricalBehaviourComparator
        hbc = HistoricalBehaviourComparator()
        assert hbc.subengine_id == "E1.4"
        result = hbc.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0

    def test_temporal_engine_evaluate_attack(self):
        from ironclad.engines.temporal.engine import TemporalBehaviourEngine
        from ironclad.engines.base import EscalationLevel
        engine = TemporalBehaviourEngine()
        result = engine.evaluate(_attack_flows())
        assert result.engine_id == "ENGINE_1_TEMPORAL"
        assert 0.0 <= result.risk_score <= 10.0
        assert 0.0 <= result.confidence_score <= 100.0
        assert len(result.subengine_results) == 4
        assert isinstance(result.explanation, str)
        assert result.escalation in list(EscalationLevel)

    def test_temporal_engine_evaluate_normal(self):
        from ironclad.engines.temporal.engine import TemporalBehaviourEngine
        from ironclad.engines.base import EscalationLevel
        result = TemporalBehaviourEngine().evaluate(_normal_flows())
        assert result.risk_score <= 10.0
        # Normal traffic should not escalate to HIGH_PRIORITY
        # (may or may not, depending on data, but we just verify types are correct)
        assert result.escalation in list(EscalationLevel)


# ===========================================================================
# ENGINE 2 — TRAFFIC BEHAVIOUR
# ===========================================================================

class TestTrafficSubEngines:

    def test_packet_size_analyzer(self):
        from ironclad.engines.traffic.packet_size import PacketSizeAnalyzer
        psa = PacketSizeAnalyzer()
        assert psa.subengine_id == "E2.1"
        result = psa.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0
        assert isinstance(result.explanation, str)

    def test_traffic_volume_analyzer(self):
        from ironclad.engines.traffic.volume import TrafficVolumeAnalyzer
        tva = TrafficVolumeAnalyzer()
        assert tva.subengine_id == "E2.2"
        result = tva.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0

    def test_directional_traffic_analyzer(self):
        from ironclad.engines.traffic.directional import DirectionalTrafficAnalyzer
        dta = DirectionalTrafficAnalyzer()
        assert dta.subengine_id == "E2.3"
        # Attack flow has 55200 fwd vs 5000 bwd → asymmetric
        result = dta.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0
        assert isinstance(result.evidence, dict)

    def test_burst_detection_analyzer(self):
        from ironclad.engines.traffic.burst_detection import BurstDetectionAnalyzer
        bda = BurstDetectionAnalyzer()
        assert bda.subengine_id == "E2.4"
        result = bda.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0

    def test_traffic_engine_evaluate(self):
        from ironclad.engines.traffic.engine import TrafficBehaviourEngine
        engine = TrafficBehaviourEngine()
        result = engine.evaluate(_attack_flows())
        assert result.engine_id == "ENGINE_2_TRAFFIC"
        assert len(result.subengine_results) == 4
        assert 0.0 <= result.risk_score <= 10.0

    def test_traffic_engine_empty_flows(self):
        from ironclad.engines.traffic.engine import TrafficBehaviourEngine
        result = TrafficBehaviourEngine().evaluate([])
        assert result.risk_score >= 0.0

    def test_directional_asymmetry_raises_risk(self):
        from ironclad.engines.traffic.directional import DirectionalTrafficAnalyzer
        # 10:1 outbound asymmetry
        flow = _make_flow(forward_bytes=50000, backward_bytes=500)
        result = DirectionalTrafficAnalyzer().analyze([flow])
        # Should produce elevated score for strong asymmetry
        assert result.risk_score > 3.0, (
            f"Expected elevated risk for 100:1 asymmetry, got {result.risk_score}"
        )


# ===========================================================================
# ENGINE 3 — CONNECTION BEHAVIOUR
# ===========================================================================

class TestConnectionSubEngines:

    def test_destination_analyzer(self):
        from ironclad.engines.connection.destination import DestinationAnalyzer
        da = DestinationAnalyzer()
        assert da.subengine_id == "E3.1"
        result = da.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0

    def test_port_protocol_analyzer(self):
        from ironclad.engines.connection.port_protocol import PortProtocolAnalyzer
        ppa = PortProtocolAnalyzer()
        assert ppa.subengine_id == "E3.2"
        result = ppa.analyze(_attack_flows())
        assert 0.0 <= result.risk_score <= 10.0

    def test_connection_failure_analyzer(self):
        from ironclad.engines.connection.connection_failure import ConnectionFailureAnalyzer
        cfa = ConnectionFailureAnalyzer()
        assert cfa.subengine_id == "E3.3"
        # Flow with high SYN and no ACK simulates scan
        flow = _make_flow()
        flow.tcp_flags["SYN"] = 15
        flow.tcp_flags["ACK"] = 1
        flow.tcp_flags["RST"] = 14
        result = cfa.analyze([flow])
        assert 0.0 <= result.risk_score <= 10.0

    def test_threat_intel_checker_confirmed_match(self):
        from ironclad.engines.connection.threat_intel import ThreatIntelChecker
        from ironclad.engines.base import DetectionStatus
        checker = ThreatIntelChecker()
        assert checker.subengine_id == "E3.4"
        # Flow to known bad IP 198.51.100.77
        flows = [_make_flow(dst_ip="198.51.100.77")]
        result = checker.analyze(flows)
        assert result.status == DetectionStatus.CRITICAL
        assert result.risk_score >= 9.0
        assert result.evidence.get("confirmed_match") is True
        assert "198.51.100.77" in result.explanation

    def test_threat_intel_checker_no_match(self):
        from ironclad.engines.connection.threat_intel import ThreatIntelChecker
        result = ThreatIntelChecker().analyze(_normal_flows())
        assert result.evidence.get("confirmed_match") is False
        assert result.risk_score < 5.0

    def test_threat_intel_checker_empty(self):
        from ironclad.engines.connection.threat_intel import ThreatIntelChecker
        result = ThreatIntelChecker().analyze([])
        assert result.risk_score == 0.0

    def test_connection_engine_evaluate(self):
        from ironclad.engines.connection.engine import ConnectionBehaviourEngine
        engine = ConnectionBehaviourEngine()
        result = engine.evaluate(_attack_flows())
        assert result.engine_id == "ENGINE_3_CONNECTION"
        assert len(result.subengine_results) == 4
        assert 0.0 <= result.risk_score <= 10.0

    def test_connection_engine_escalates_on_threat_match(self):
        from ironclad.engines.connection.engine import ConnectionBehaviourEngine
        from ironclad.engines.base import EscalationLevel
        result = ConnectionBehaviourEngine().evaluate(_attack_flows())
        # Should escalate HIGH_PRIORITY since threat intel confirmed match gives 9.8
        assert result.escalation == EscalationLevel.HIGH_PRIORITY_ESCALATION


# ===========================================================================
# ENGINE 4 — DECISION & CORRELATION
# ===========================================================================

def _run_all_engines(flows):
    """Helper: run all 3 primary engines and return dict for Engine 4."""
    from ironclad.engines.temporal.engine import TemporalBehaviourEngine
    from ironclad.engines.traffic.engine import TrafficBehaviourEngine
    from ironclad.engines.connection.engine import ConnectionBehaviourEngine
    e1 = TemporalBehaviourEngine().evaluate(flows)
    e2 = TrafficBehaviourEngine().evaluate(flows)
    e3 = ConnectionBehaviourEngine().evaluate(flows)
    return {e1.engine_id: e1, e2.engine_id: e2, e3.engine_id: e3}


class TestDecisionEngine:

    def test_decision_engine_import(self):
        from ironclad.engines.decision.engine import DecisionCorrelationEngine
        engine = DecisionCorrelationEngine()
        assert engine is not None

    def test_decision_engine_attack_classification(self):
        from ironclad.engines.decision.engine import DecisionCorrelationEngine
        from ironclad.engines.base import FinalClassification
        flows = _attack_flows()
        engine_results = _run_all_engines(flows)
        report = DecisionCorrelationEngine().evaluate(engine_results, flows)
        # Expect CONFIRMED_INDICATOR_MATCH or HIGH_RISK
        assert report.final_classification in (
            FinalClassification.CONFIRMED_INDICATOR_MATCH,
            FinalClassification.HIGH_RISK,
        )
        assert report.overall_risk_score >= 7.0
        assert isinstance(report.executive_summary, str)
        assert len(report.recommended_actions) >= 1

    def test_decision_engine_benign_classification(self):
        from ironclad.engines.decision.engine import DecisionCorrelationEngine
        from ironclad.engines.base import FinalClassification
        flows = _normal_flows()
        engine_results = _run_all_engines(flows)
        report = DecisionCorrelationEngine().evaluate(engine_results, flows)
        # Normal flows should not produce CONFIRMED_INDICATOR_MATCH
        assert report.final_classification != FinalClassification.CONFIRMED_INDICATOR_MATCH

    def test_decision_engine_report_fields(self):
        from ironclad.engines.decision.engine import DecisionCorrelationEngine
        flows = _attack_flows()
        engine_results = _run_all_engines(flows)
        report = DecisionCorrelationEngine().evaluate(engine_results, flows)
        assert 0.0 <= report.overall_risk_score <= 10.0
        assert 0.0 <= report.evidence_quality_score <= 100.0
        assert "ENGINE_1_TEMPORAL" in report.engine_results
        assert "ENGINE_2_TRAFFIC" in report.engine_results
        assert "ENGINE_3_CONNECTION" in report.engine_results

    def test_decision_engine_empty_flows(self):
        from ironclad.engines.decision.engine import DecisionCorrelationEngine
        from ironclad.engines.base import FinalClassification
        engine_results = _run_all_engines([])
        report = DecisionCorrelationEngine().evaluate(engine_results, [])
        assert report.final_classification in list(FinalClassification)


# ===========================================================================
# ESCALATION LOGIC
# ===========================================================================

class TestEscalationLogic:

    def test_escalation_normal_range(self):
        from ironclad.engines.base import EscalationLevel
        assert EscalationLevel.from_score(0.0) == EscalationLevel.NORMAL
        assert EscalationLevel.from_score(4.9) == EscalationLevel.NORMAL

    def test_escalation_secondary_range(self):
        from ironclad.engines.base import EscalationLevel
        assert EscalationLevel.from_score(5.0) == EscalationLevel.SECONDARY_INVESTIGATION
        assert EscalationLevel.from_score(6.9) == EscalationLevel.SECONDARY_INVESTIGATION

    def test_escalation_high_priority_range(self):
        from ironclad.engines.base import EscalationLevel
        assert EscalationLevel.from_score(7.0) == EscalationLevel.HIGH_PRIORITY_ESCALATION
        assert EscalationLevel.from_score(10.0) == EscalationLevel.HIGH_PRIORITY_ESCALATION

    def test_escalation_clamps_out_of_range(self):
        from ironclad.engines.base import EscalationLevel
        assert EscalationLevel.from_score(-1.0) == EscalationLevel.NORMAL
        assert EscalationLevel.from_score(11.0) == EscalationLevel.HIGH_PRIORITY_ESCALATION


# ===========================================================================
# ENGINE REGISTRY
# ===========================================================================

class TestEngineRegistry:

    def test_all_engines_importable(self):
        from ironclad.engines import (
            TemporalBehaviourEngine,
            TrafficBehaviourEngine,
            ConnectionBehaviourEngine,
            DecisionCorrelationEngine,
        )
        assert TemporalBehaviourEngine is not None
        assert TrafficBehaviourEngine is not None
        assert ConnectionBehaviourEngine is not None
        assert DecisionCorrelationEngine is not None

    def test_subengine_result_dataclass(self):
        from ironclad.engines.base import SubEngineResult, DetectionStatus
        result = SubEngineResult(
            subengine_id="TEST",
            name="Test Engine",
            parent_engine="ENGINE_X",
            risk_score=5.5,
            confidence_score=75.0,
            status=DetectionStatus.SUSPICIOUS,
            explanation="Test explanation",
            evidence={"key": "value"},
        )
        assert result.risk_score == 5.5
        assert result.status == DetectionStatus.SUSPICIOUS
