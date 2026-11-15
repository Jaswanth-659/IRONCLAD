"""
IRONCLAD Detection Engines Module.

Includes:
- Engine 1: Temporal Behaviour Engine (E1.1 - E1.4)
- Engine 2: Traffic Behaviour Engine (E2.1 - E2.4)
- Engine 3: Connection Behaviour Engine (E3.1 - E3.4)
- Engine 4: Final Decision & Correlation Engine
"""

from ironclad.engines.base import (
    BasePrimaryEngine,
    BaseSubEngine,
    CorrelationItem,
    DecisionReport,
    DetectionStatus,
    EscalationLevel,
    FinalClassification,
    PrimaryEngineResult,
    RiskClassificationBand,
    SubEngineResult,
)
from ironclad.engines.connection import ConnectionBehaviourEngine
from ironclad.engines.decision import DecisionCorrelationEngine
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_engine4_final_decision,
    aggregate_primary_engine_scores,
    audit_subengine_results,
)
from ironclad.engines.temporal import TemporalBehaviourEngine
from ironclad.engines.traffic import TrafficBehaviourEngine

__all__ = [
    "EscalationLevel",
    "DetectionStatus",
    "FinalClassification",
    "RiskClassificationBand",
    "SubEngineResult",
    "PrimaryEngineResult",
    "CorrelationItem",
    "DecisionReport",
    "BaseSubEngine",
    "BasePrimaryEngine",
    "TemporalBehaviourEngine",
    "TrafficBehaviourEngine",
    "ConnectionBehaviourEngine",
    "DecisionCorrelationEngine",
    "ScoringConfig",
    "DEFAULT_SCORING_CONFIG",
    "aggregate_primary_engine_scores",
    "aggregate_engine4_final_decision",
    "audit_subengine_results",
]
