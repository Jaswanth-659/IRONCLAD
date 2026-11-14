"""
IRONCLAD Engine CLI Runner.

Executes end-to-end network telemetry inspection and risk scoring on PCAP files.
Usage:
    python scripts/run_engine.py --pcap data/sample_traffic.pcap
    python scripts/run_engine.py --generate-synthetic
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ironclad.config.settings import EngineConfig
from ironclad.pipeline import IroncladEngine
from scripts.generate_synthetic_pcap import generate_test_pcap


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable representation."""
    val = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if val < 1024.0:
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IRONCLAD: Intelligent Network Telemetry & Cryptographic Defence Engine"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Path to PCAP/PCAPNG capture file to analyze",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to custom YAML configuration file",
    )
    parser.add_argument(
        "--generate-synthetic",
        action="store_true",
        help="Generate a synthetic test PCAP before running",
    )
    args = parser.parse_args()

    # Load configuration
    if args.config:
        config = EngineConfig.from_yaml(args.config)
    else:
        config = EngineConfig.default()

    # Determine PCAP target
    target_pcap = args.pcap
    if args.generate_synthetic or not target_pcap:
        synthetic_path = Path("data/sample_traffic.pcap")
        print(f"[*] Generating synthetic test PCAP at: {synthetic_path}")
        target_pcap = generate_test_pcap(str(synthetic_path))

    pcap_path = Path(target_pcap)
    if not pcap_path.exists():
        print(f"[!] Error: Target PCAP does not exist: {pcap_path}")
        sys.exit(1)

    print("=" * 78)
    print("  IRONCLAD Engine - Phase 1 Telemetry & Cryptographic Audit")
    print("=" * 78)
    print(f"Target Capture: {pcap_path.resolve()}")
    print(f"File Size     : {format_bytes(pcap_path.stat().st_size)}")
    print("-" * 78)

    engine = IroncladEngine(config=config)
    report = engine.analyze_pcap(pcap_path)

    print("\n[+] TELEMETRY SUMMARY:")
    print(f"    - Total Packets Processed : {report.total_packets}")
    print(f"    - Total Bytes Dissected   : {format_bytes(report.total_bytes)}")
    print(f"    - Capture Span Duration   : {report.capture_duration:.3f} seconds")
    print(f"    - Unique Communication IP : {report.unique_hosts} hosts")
    print(f"    - Aggregated Flows (5-Tup): {report.flow_count} flows")
    print(f"    - Engine Execution Time   : {report.execution_time_seconds:.3f} seconds")

    print("\n[+] NETWORK TOPOLOGY METRICS (Host Centralities):")
    for ip, m in list(report.host_metrics.items())[:5]:
        print(
            f"    - Host {ip:<15} | Degree: {m.degree:<3} (In:{m.in_degree} Out:{m.out_degree}) "
            f"| Fan-Out: {m.fan_out_ratio:<5.2f} | PageRank: {m.pagerank:.4f}"
        )

    print("\n[+] RISK ASSESSMENT:")
    sev = report.global_risk.severity.value
    print(f"    - Global Capture Risk Score: {report.global_risk.score:.1f} / 100.0 [{sev}]")
    print(f"    - Detected Findings Count  : {len(report.global_risk.findings)}")

    if report.global_risk.findings:
        print("\n[!] SECURITY FINDINGS & ANOMALIES:")
        for idx, finding in enumerate(report.global_risk.findings, start=1):
            print(f"    [{idx}] {finding.severity.value:<8} | {finding.rule_name}")
            print(f"        Target Entity: {finding.target_entity}")
            print(f"        Description  : {finding.description}")
            if finding.evidence:
                print(f"        Evidence     : {finding.evidence}")

    print("=" * 78)
    print("  Audit Complete.")
    print("=" * 78)


if __name__ == "__main__":
    main()
