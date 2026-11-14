"""
IRONCLAD - Intelligent Network Telemetry and Cryptographic Defence Engine.

Phase 1 Core Python Network Analysis Engine.
"""

from ironclad.config.settings import EngineConfig
from ironclad.core.exceptions import IroncladError
from ironclad.core.types import AnalysisReport, FlowRecord, PacketSummary, RiskScore, RiskSeverity
from ironclad.pipeline import IroncladEngine

__version__ = "1.0.0"
__author__ = "IRONCLAD Engineering Team"

__all__ = [
    "IroncladEngine",
    "EngineConfig",
    "IroncladError",
    "AnalysisReport",
    "FlowRecord",
    "PacketSummary",
    "RiskScore",
    "RiskSeverity",
]
