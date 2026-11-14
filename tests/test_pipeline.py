"""
End-to-End Pipeline integration tests for IRONCLAD.
"""

from pathlib import Path
from ironclad.config.settings import EngineConfig
from ironclad.pipeline import IroncladEngine
from scripts.generate_synthetic_pcap import generate_test_pcap


def test_ironclad_engine_end_to_end(tmp_path: Path):
    pcap_file = tmp_path / "test_pipeline.pcap"
    generate_test_pcap(output_path=str(pcap_file))

    config = EngineConfig.default()
    # Disable console spam during testing
    config.logging.enable_console = False

    engine = IroncladEngine(config=config)
    report = engine.analyze_pcap(pcap_file)

    assert report.total_packets > 0
    assert report.total_bytes > 0
    assert report.flow_count > 0
    assert report.unique_hosts > 0
    assert report.execution_time_seconds > 0.0

    # Ensure anomalous / attack findings were uncovered
    assert report.global_risk.score > 0.0
    assert len(report.global_risk.findings) > 0

    # Check that high risk was detected (attacker scanning or exfiltrating)
    severities = [f.severity.value for f in report.global_risk.findings]
    assert "HIGH" in severities or "CRITICAL" in severities
