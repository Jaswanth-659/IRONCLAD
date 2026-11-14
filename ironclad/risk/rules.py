"""
IRONCLAD Security Heuristic Rule Engine.

Implements deterministic cybersecurity detection rules for port scanning,
TCP flag anomalies, high-entropy cryptographic exfiltration, and beaconing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics, RiskFinding, RiskSeverity
from ironclad.parsing.protocols import WELL_KNOWN_PORTS


class BaseSecurityRule(ABC):
    """Abstract base class for deterministic cybersecurity detection heuristics."""

    def __init__(self, rule_id: str, name: str, default_severity: RiskSeverity) -> None:
        self.rule_id = rule_id
        self.name = name
        self.default_severity = default_severity

    @abstractmethod
    def evaluate_flow(self, flow: FlowRecord) -> Optional[RiskFinding]:
        """Evaluate rule against a single network flow."""
        pass

    def evaluate_host(self, host_metrics: GraphNodeMetrics) -> Optional[RiskFinding]:
        """Evaluate rule against host topological metrics (optional default None)."""
        return None


class SynScanRule(BaseSecurityRule):
    """
    Detects half-open TCP SYN port scans and SYN floods.
    Flags flows where SYN count is disproportionately high with missing ACK completions.
    """

    def __init__(self, min_syn_count: int = 5, syn_ack_ratio_threshold: float = 5.0) -> None:
        super().__init__(
            rule_id="RULE-SEC-001",
            name="TCP SYN Port Scan / Flood",
            default_severity=RiskSeverity.HIGH,
        )
        self.min_syn_count = min_syn_count
        self.ratio_threshold = syn_ack_ratio_threshold

    def evaluate_flow(self, flow: FlowRecord) -> Optional[RiskFinding]:
        syn = flow.tcp_flags.get("SYN", 0)
        ack = flow.tcp_flags.get("ACK", 0)

        if syn >= self.min_syn_count:
            ratio = syn / (ack + 1)
            if ratio >= self.ratio_threshold:
                return RiskFinding(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.default_severity,
                    score_impact=35.0,
                    description=(
                        f"Unanswered TCP SYN requests detected ({syn} SYNs vs {ack} ACKs, "
                        f"ratio {ratio:.1f}). Characteristic of reconnaissance port scanning."
                    ),
                    target_entity=flow.canonical_id,
                    evidence={"syn_count": syn, "ack_count": ack, "ratio": round(ratio, 2)},
                )
        return None


class EncryptedExfiltrationRule(BaseSecurityRule):
    """
    Detects potential encrypted command-and-control (C2) or exfiltration channels.
    Flags high-entropy byte streams (> 7.4) occurring on non-standard encryption ports.
    """

    STANDARD_ENCRYPTED_PORTS = {443, 8443, 22, 993, 995, 465, 5061}

    def __init__(self, entropy_threshold: float = 7.4, min_bytes: int = 200) -> None:
        super().__init__(
            rule_id="RULE-SEC-002",
            name="High-Entropy Non-Standard Port Exfiltration",
            default_severity=RiskSeverity.HIGH,
        )
        self.entropy_threshold = entropy_threshold
        self.min_bytes = min_bytes

    def evaluate_flow(self, flow: FlowRecord) -> Optional[RiskFinding]:
        port = flow.key.dst_port
        entropy = flow.mean_payload_entropy

        if (
            port not in self.STANDARD_ENCRYPTED_PORTS
            and entropy >= self.entropy_threshold
            and flow.byte_count >= self.min_bytes
        ):
            sev = RiskSeverity.CRITICAL if flow.byte_count > 50000 else RiskSeverity.HIGH
            return RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=sev,
                score_impact=45.0 if sev == RiskSeverity.CRITICAL else 30.0,
                description=(
                    f"Cryptographic payload entropy ({entropy:.2f}/8.0) observed on "
                    f"non-standard port {port}. Potential encrypted tunnel or exfiltration."
                ),
                target_entity=flow.canonical_id,
                evidence={
                    "dst_port": port,
                    "payload_entropy": round(entropy, 3),
                    "byte_count": flow.byte_count,
                },
            )
        return None


class FanOutReconRule(BaseSecurityRule):
    """
    Detects horizontal network sweeps and lateral movement.
    Flags hosts exhibiting anomalous fan-out ratios contacting multiple distinct peers.
    """

    def __init__(self, fan_out_threshold: float = 8.0, min_peers: int = 4) -> None:
        super().__init__(
            rule_id="RULE-SEC-003",
            name="Horizontal Network Sweep / Fan-Out",
            default_severity=RiskSeverity.HIGH,
        )
        self.fan_out_threshold = fan_out_threshold
        self.min_peers = min_peers

    def evaluate_flow(self, flow: FlowRecord) -> Optional[RiskFinding]:
        return None

    def evaluate_host(self, host: GraphNodeMetrics) -> Optional[RiskFinding]:
        if host.fan_out_ratio >= self.fan_out_threshold and host.unique_peers >= self.min_peers:
            return RiskFinding(
                rule_id=self.rule_id,
                rule_name=self.name,
                severity=self.default_severity,
                score_impact=35.0,
                description=(
                    f"Host {host.ip} established asymmetric fan-out connections to "
                    f"{host.unique_peers} distinct peers (fan-out ratio: {host.fan_out_ratio:.2f})."
                ),
                target_entity=host.ip,
                evidence={
                    "fan_out_ratio": host.fan_out_ratio,
                    "unique_peers": host.unique_peers,
                    "out_degree": host.out_degree,
                    "in_degree": host.in_degree,
                },
            )
        return None


class RuleEngine:
    """
    Evaluator orchestrating all heuristic cybersecurity detection rules.
    """

    def __init__(self, rules: Optional[List[BaseSecurityRule]] = None) -> None:
        self.rules = rules or [
            SynScanRule(),
            EncryptedExfiltrationRule(),
            FanOutReconRule(),
        ]

    def evaluate_flows(self, flows: List[FlowRecord]) -> List[RiskFinding]:
        findings = []
        for flow in flows:
            for rule in self.rules:
                finding = rule.evaluate_flow(flow)
                if finding is not None:
                    findings.append(finding)
        return findings

    def evaluate_hosts(self, hosts: Dict[str, GraphNodeMetrics]) -> List[RiskFinding]:
        findings = []
        for host in hosts.values():
            for rule in self.rules:
                finding = rule.evaluate_host(host)
                if finding is not None:
                    findings.append(finding)
        return findings
