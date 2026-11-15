"""
IRONCLAD Detection Engine Base Interfaces and Data Models.

Defines standardized contracts for the 3 primary engines, 12 sub-engines,
and the final decision & correlation engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics


class EscalationLevel(str, Enum):
    """Automatic Engine Escalation Threshold Levels."""
    NORMAL = "NORMAL"                                     # Score 0.0 - 4.9
    SECONDARY_INVESTIGATION = "SECONDARY_INVESTIGATION"   # Score 5.0 - 6.9
    HIGH_PRIORITY_ESCALATION = "HIGH_PRIORITY_ESCALATION" # Score 7.0 - 10.0

    @classmethod
    def from_score(cls, score: float) -> EscalationLevel:
        clamped = max(0.0, min(10.0, score))
        if clamped >= 7.0:
            return cls.HIGH_PRIORITY_ESCALATION
        elif clamped >= 5.0:
            return cls.SECONDARY_INVESTIGATION
        return cls.NORMAL


class RiskClassificationBand(str, Enum):
    """
    Standardized operational risk classification bands:
    - 0.0–2.9: NORMAL
    - 3.0–4.9: LOW RISK
    - 5.0–6.9: SUSPICIOUS
    - 7.0–8.9: HIGH RISK
    - 9.0–10.0: CRITICAL
    """
    NORMAL = "NORMAL"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class DetectionStatus(str, Enum):
    """Detection outcome status."""
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class FinalClassification(str, Enum):
    """Final Decision Engine Classifications."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CONFIRMED_INDICATOR_MATCH = "CONFIRMED_INDICATOR_MATCH"


@dataclass
class SubEngineResult:
    """Standardized output from an individual sub-engine."""
    subengine_id: str
    name: str
    parent_engine: str
    risk_score: float         # Normalized [0.0 - 10.0]
    confidence_score: float   # Percentage [0.0 - 100.0]
    status: DetectionStatus
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0


@dataclass
class PrimaryEngineResult:
    """Standardized output from an independent primary detection engine."""
    engine_id: str
    name: str
    risk_score: float                 # Normalized [0.0 - 10.0]
    confidence_score: float           # Percentage [0.0 - 100.0]
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    status: DetectionStatus = DetectionStatus.NORMAL
    escalation: EscalationLevel = EscalationLevel.NORMAL
    subengine_results: List[SubEngineResult] = field(default_factory=list)
    secondary_investigation_triggered: bool = False
    execution_time_ms: float = 0.0
    # Enhanced scoring metadata & transparency fields:
    classification: RiskClassificationBand = RiskClassificationBand.NORMAL
    contributing_subengines: List[str] = field(default_factory=list)
    valid_subengine_count: int = 0
    unavailable_subengine_count: int = 0
    calculation_explanation: str = ""
    scoring_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationItem:
    """Entity-level correlation element from multiple engines."""
    entity_id: str
    entity_type: str                  # "HOST" or "FLOW"
    contributing_engines: List[str]
    max_risk_score: float
    correlated_findings: List[str]
    evidence_independence_score: float # Quality metric [0.0 - 1.0]


@dataclass
class DecisionReport:
    """Comprehensive verdict from ENGINE 4 (Decision and Correlation Engine)."""
    overall_risk_score: float          # Normalized [0.0 - 10.0]
    final_classification: FinalClassification
    executive_summary: str
    engine_results: Dict[str, PrimaryEngineResult]
    correlations: List[CorrelationItem]
    evidence_quality_score: float      # [0.0 - 100.0%]
    recommended_actions: List[str]
    timeline_events: List[Dict[str, Any]] = field(default_factory=list)
    # Enhanced scoring metadata & transparency fields:
    overall_confidence_score: float = 0.0
    classification_band: RiskClassificationBand = RiskClassificationBand.NORMAL
    contributing_engines: List[str] = field(default_factory=list)
    unavailable_engine_count: int = 0
    calculation_explanation: str = ""
    scoring_metadata: Dict[str, Any] = field(default_factory=dict)


class BaseSubEngine(ABC):
    """Abstract contract for secondary investigation sub-engines."""

    def __init__(self, subengine_id: str, name: str, parent_engine: str) -> None:
        self.subengine_id = subengine_id
        self.name = name
        self.parent_engine = parent_engine

    @abstractmethod
    def analyze(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SubEngineResult:
        """Execute genuine cybersecurity analysis logic."""
        pass


class BasePrimaryEngine(ABC):
    """Abstract contract for primary detection engines."""

    def __init__(self, engine_id: str, name: str) -> None:
        self.engine_id = engine_id
        self.name = name
        self.subengines: List[BaseSubEngine] = []

    def register_subengine(self, subengine: BaseSubEngine) -> None:
        self.subengines.append(subengine)

    @abstractmethod
    def evaluate(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PrimaryEngineResult:
        """Run primary detection and automatic escalation."""
        pass
