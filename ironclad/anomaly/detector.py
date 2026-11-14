"""
IRONCLAD Anomaly Detection Interfaces and Hybrid Ensemble.

Defines the abstract base contract and hybrid orchestrator that fuses
unsupervised machine learning (Isolation Forest) with parametric statistical bounds.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union

import numpy as np
import pandas as pd

from ironclad.core.exceptions import AnomalyDetectionError
from ironclad.core.logging import get_logger
from ironclad.core.types import AnomalyScore

logger = get_logger("anomaly.detector")


class BaseAnomalyDetector(ABC):
    """Abstract base class for all IRONCLAD anomaly detection models."""

    @abstractmethod
    def fit(self, data: Union[pd.DataFrame, np.ndarray]) -> BaseAnomalyDetector:
        """Fit or calibrate the detector on baseline observations."""
        pass

    @abstractmethod
    def predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        """Evaluate observations and return anomaly scores."""
        pass

    def fit_predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        """Convenience method to fit and predict on the same dataset."""
        return self.fit(data).predict(data)


class HybridAnomalyDetector(BaseAnomalyDetector):
    """
    Ensemble anomaly detector fusing machine learning (Isolation Forest)
    with statistical heuristic bounds (Z-Score & IQR fences).
    """

    def __init__(
        self,
        detectors: Optional[List[BaseAnomalyDetector]] = None,
        weights: Optional[List[float]] = None,
    ) -> None:
        self.detectors = detectors or []
        self.weights = weights or ([1.0 / len(self.detectors)] * len(self.detectors) if self.detectors else [])
        if self.detectors and len(self.detectors) != len(self.weights):
            raise AnomalyDetectionError("Length of detectors and weights must match.")

    def add_detector(self, detector: BaseAnomalyDetector, weight: float = 1.0) -> None:
        self.detectors.append(detector)
        self.weights.append(weight)
        # Re-normalize weights
        total = sum(self.weights)
        if total > 0:
            self.weights = [w / total for w in self.weights]

    def fit(self, data: Union[pd.DataFrame, np.ndarray]) -> HybridAnomalyDetector:
        if not self.detectors:
            logger.warning("No sub-detectors registered in HybridAnomalyDetector.")
            return self

        for det in self.detectors:
            det.fit(data)
        return self

    def predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        if not self.detectors:
            return []

        all_results = [det.predict(data) for det in self.detectors]
        n_samples = len(all_results[0])
        ensemble_scores: List[AnomalyScore] = []

        for i in range(n_samples):
            fused_score = 0.0
            is_anomaly_votes = 0
            explanations = []

            for det_idx, res_list in enumerate(all_results):
                res = res_list[i]
                weight = self.weights[det_idx]
                fused_score += res.score * weight
                if res.is_anomaly:
                    is_anomaly_votes += 1
                if res.explanation:
                    explanations.append(f"[{res.detector}] {res.explanation}")

            # Flagged as anomaly if majority or significant severity > 0.65
            is_anomaly = (is_anomaly_votes >= (len(self.detectors) / 2.0)) or (fused_score >= 0.65)
            confidence = float(min(1.0, sum(res_list[i].confidence for res_list in all_results) / len(self.detectors)))

            ensemble_scores.append(
                AnomalyScore(
                    detector="HybridEnsemble",
                    is_anomaly=is_anomaly,
                    score=float(round(min(1.0, max(0.0, fused_score)), 4)),
                    confidence=round(confidence, 4),
                    explanation="; ".join(explanations) if explanations else "Normal telemetry behavior",
                )
            )

        return ensemble_scores
