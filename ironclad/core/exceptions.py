"""
IRONCLAD Core Exceptions.

Defines a strict exception hierarchy for the network telemetry and
cryptographic defence engine.
"""

from typing import Optional


class IroncladError(Exception):
    """Base exception for all IRONCLAD engine errors."""

    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class ConfigurationError(IroncladError):
    """Raised when engine configuration is invalid, missing, or unparseable."""
    pass


class PCAPIngestionError(IroncladError):
    """Raised when a PCAP/PCAPNG file cannot be read, does not exist, or is corrupted."""
    pass


class PacketParsingError(IroncladError):
    """Raised when packet dissection fails or encounters unrecoverable malformed frames."""
    pass


class FeatureExtractionError(IroncladError):
    """Raised when feature computation or flow aggregation fails."""
    pass


class StatisticalAnalysisError(IroncladError):
    """Raised when mathematical or statistical evaluation fails (e.g. singular matrix, insufficient samples)."""
    pass


class AnomalyDetectionError(IroncladError):
    """Raised when an anomaly detector model fails to train, predict, or evaluate."""
    pass


class GraphConstructionError(IroncladError):
    """Raised when topology construction or graph metric calculation fails."""
    pass


class RiskScoringError(IroncladError):
    """Raised when risk aggregation or heuristic scoring encounters an invalid state."""
    pass
