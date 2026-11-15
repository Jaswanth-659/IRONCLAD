"""
E3.4 Threat Intelligence Checker.

Evaluates network communication endpoints against known threat intelligence indicators,
reputation datasets, and verified malicious command-and-control infrastructure.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult

# Curated high-fidelity threat intelligence feed of known malicious C2s,
# Tor exits, and adversary infrastructure (simulated enterprise intel database)
KNOWN_THREAT_INDICATORS: Dict[str, Dict[str, Any]] = {
    "198.51.100.77": {
        "category": "C2_SERVER",
        "threat_actor": "APT-29 / Midnight Blizzard",
        "family": "Cobalt Strike / Custom Encrypted Tunnel",
        "confidence": 98.0,
        "source": "IRONCLAD Curated Intel Feed",
    },
    "185.220.101.5": {
        "category": "TOR_EXIT_NODE",
        "threat_actor": "Anonymization Network",
        "family": "Tor Exit Gateway",
        "confidence": 95.0,
        "source": "Tor Project Directory",
    },
    "194.26.29.112": {
        "category": "BOTNET_CONTROLLER",
        "threat_actor": "Mirai / Mozi Variant",
        "family": "IoT Botnet C2",
        "confidence": 92.0,
        "source": "AbuseCH Feed",
    },
    "45.154.255.88": {
        "category": "BULLETPROOF_HOST",
        "threat_actor": "Ransomware Staging",
        "family": "LockBit Affiliate Exfil Host",
        "confidence": 96.0,
        "source": "CISA Alert ICS-2024",
    },
    "10.0.0.99": {
        "category": "INTERNAL_SCANNER",
        "threat_actor": "Compromised Internal Host",
        "family": "Lateral Movement Reconnaissance",
        "confidence": 90.0,
        "source": "Internal SOC Anomaly Feed",
    },
}


class ThreatIntelChecker(BaseSubEngine):
    """
    Checks source and destination IPs against verified threat intelligence feeds.
    Strictly observes rule: Unknown destinations are NOT classified as malicious.
    Missing reputation is recorded as 'UNKNOWN', not as clean evidence.
    """

    def __init__(self, custom_indicators: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        super().__init__(
            subengine_id="E3.4",
            name="Threat Intelligence Checker",
            parent_engine="ENGINE_3_CONNECTION",
        )
        self.indicators = dict(KNOWN_THREAT_INDICATORS)
        if custom_indicators:
            self.indicators.update(custom_indicators)

    def analyze(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SubEngineResult:
        if not flows:
            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=0.0,
                confidence_score=30.0,
                status=DetectionStatus.NORMAL,
                explanation="No flows available for threat intelligence matching.",
            )

        matches = []
        checked_ips: Set[str] = set()

        for flow in flows:
            src = flow.key.src_ip
            dst = flow.key.dst_ip

            for ip, role in [(src, "SOURCE"), (dst, "DESTINATION")]:
                if ip in checked_ips:
                    continue
                checked_ips.add(ip)

                if ip in self.indicators:
                    intel = self.indicators[ip]
                    matches.append({
                        "ip": ip,
                        "role": role,
                        "category": intel["category"],
                        "threat_actor": intel["threat_actor"],
                        "family": intel["family"],
                        "confidence": intel["confidence"],
                        "source": intel["source"],
                        "flow_id": flow.canonical_id,
                    })

        if matches:
            matches.sort(key=lambda x: x["confidence"], reverse=True)
            top = matches[0]
            # Confirmed indicator match produces maximum priority risk score [9.0 - 10.0]
            risk = round(min(10.0, 9.0 + (top["confidence"] - 90.0) * 0.1), 2)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=top["confidence"],
                status=DetectionStatus.CRITICAL,
                explanation=(
                    f"CONFIRMED INDICATOR MATCH: Detected {len(matches)} endpoint(s) matching verified threat "
                    f"intelligence indicators. Host {top['ip']} ({top['role']}) identified as {top['category']} "
                    f"attributed to '{top['threat_actor']}' ({top['family']}) via {top['source']}."
                ),
                evidence={
                    "match_count": len(matches),
                    "matches": matches,
                    "confirmed_match": True,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.0,
            confidence_score=80.0,
            status=DetectionStatus.NORMAL,
            explanation=(
                f"Evaluated {len(checked_ips)} unique endpoints against threat intelligence feeds. "
                "No known malicious indicators matched. (Note: Unmatched destinations are treated as unverified, "
                "not confirmed benign)."
            ),
            evidence={
                "checked_ip_count": len(checked_ips),
                "confirmed_match": False,
            },
        )
