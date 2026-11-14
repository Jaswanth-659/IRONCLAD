"""
IRONCLAD Machine Learning Anomaly Detector (Isolation Forest).

Leverages Scikit-Learn's Isolation Forest algorithm to detect multi-dimensional
outliers in network flow feature spaces without requiring labelled attack signatures.
"""

from __future__ import annotations

from typing import List, Optional, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ironclad.anomaly.detector import BaseAnomalyDetector
from ironclad.core.exceptions import AnomalyDetectionError
from ironclad.core.logging import get_logger
from ironclad.core.types import AnomalyScore

logger = get_logger("anomaly.isolation_forest")

FEATURE_SUBSET = [
    "packet_count",
    "byte_count",
    "forward_bytes",
    "backward_bytes",
    "packet_length_mean",
    "packet_length_std",
    "iat_mean",
    "iat_std",
    "pps",
    "bps",
    "syn_ack_ratio",
    "mean_payload_entropy",
    "burstiness",
    "jitter",
]


class IsolationForestDetector(BaseAnomalyDetector):
    """
    Unsupervised tree-based anomaly detector isolating aberrant network flows.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
        feature_columns: Optional[List[str]] = None,
    ) -> None:
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.feature_columns = feature_columns or FEATURE_SUBSET

        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.fitted_columns: List[str] = []
        self._is_fitted = False

    def _prepare_matrix(self, data: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        if isinstance(data, pd.DataFrame):
            available_cols = [c for c in self.feature_columns if c in data.columns]
            if not available_cols:
                raise AnomalyDetectionError(
                    f"No expected feature columns found in DataFrame. Expected subset of: {self.feature_columns}"
                )
            self.fitted_columns = available_cols
            matrix = data[available_cols].to_numpy(dtype=np.float64)
        else:
            matrix = np.asarray(data, dtype=np.float64)
            if matrix.ndim == 1:
                matrix = matrix.reshape(-1, 1)
            self.fitted_columns = [f"feat_{i}" for i in range(matrix.shape[1])]

        # Sanitize NaNs and Infs
        matrix = np.nan_to_num(matrix, nan=0.0, posinf=1e9, neginf=-1e9)
        return matrix

    def fit(self, data: Union[pd.DataFrame, np.ndarray]) -> IsolationForestDetector:
        matrix = self._prepare_matrix(data)
        if matrix.shape[0] < 2:
            raise AnomalyDetectionError(
                f"IsolationForest requires at least 2 samples to fit. Given: {matrix.shape[0]}"
            )

        scaled_matrix = self.scaler.fit_transform(matrix)

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(scaled_matrix)
        self._is_fitted = True
        logger.info(
            "IsolationForest fitted successfully (samples=%d, features=%d)",
            matrix.shape[0],
            matrix.shape[1],
        )
        return self

    def predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        if not self._is_fitted or self.model is None:
            raise AnomalyDetectionError("IsolationForestDetector must be fitted before predict.")

        matrix = self._prepare_matrix(data)
        scaled_matrix = self.scaler.transform(matrix)

        # Scikit-learn outputs: -1 for anomalies, 1 for inliers
        predictions = self.model.predict(scaled_matrix)
        # Decision function: lower values mean more anomalous (typically in range -0.5 to 0.5)
        decision_scores = self.model.decision_function(scaled_matrix)

        scores: List[AnomalyScore] = []
        for i in range(matrix.shape[0]):
            is_anomaly = bool(predictions[i] == -1)
            raw_decision = float(decision_scores[i])

            # Invert and normalize decision score to [0.0, 1.0]:
            # Raw decision < 0 is anomalous; raw decision > 0 is normal.
            # Using sigmoid: norm_score = 1 / (1 + exp(5 * raw_decision))
            norm_score = float(round(1.0 / (1.0 + np.exp(6.0 * raw_decision)), 4))

            explanation = (
                f"IsolationForest flagged outlier (decision={raw_decision:.3f})"
                if is_anomaly
                else f"Normal flow profile (decision={raw_decision:.3f})"
            )

            scores.append(
                AnomalyScore(
                    detector="IsolationForest",
                    is_anomaly=is_anomaly,
                    score=norm_score,
                    confidence=0.90,
                    explanation=explanation,
                    metrics={"raw_decision_score": round(raw_decision, 4)},
                )
            )

        return scores
