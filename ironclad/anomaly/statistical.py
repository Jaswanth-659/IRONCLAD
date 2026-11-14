"""
IRONCLAD Statistical Anomaly Detectors.

Implements univariate and multivariate Z-score and Tukey IQR fence detectors
for continuous network telemetry flow distributions.
"""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Union

import numpy as np
import pandas as pd

from ironclad.anomaly.detector import BaseAnomalyDetector
from ironclad.core.exceptions import AnomalyDetectionError
from ironclad.core.logging import get_logger
from ironclad.core.types import AnomalyScore

logger = get_logger("anomaly.statistical")

DEFAULT_EVAL_COLUMNS = [
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "syn_ack_ratio",
    "mean_payload_entropy",
    "burstiness",
    "jitter",
]


class ZScoreDetector(BaseAnomalyDetector):
    """
    Parametric anomaly detector based on Gaussian standard score distance.
    Flags records with $|z| > \\text{threshold}$ on any evaluated feature.
    """

    def __init__(
        self,
        threshold: float = 3.0,
        feature_columns: Optional[List[str]] = None,
    ) -> None:
        self.threshold = max(0.1, threshold)
        self.feature_columns = feature_columns or DEFAULT_EVAL_COLUMNS
        self.means: np.ndarray = np.array([])
        self.stds: np.ndarray = np.array([])
        self.fitted_columns: List[str] = []

    def _extract_matrix(self, data: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        if isinstance(data, pd.DataFrame):
            available_cols = [c for c in self.feature_columns if c in data.columns]
            if not available_cols:
                raise AnomalyDetectionError(
                    f"None of the target feature columns {self.feature_columns} exist in DataFrame."
                )
            self.fitted_columns = available_cols
            return data[available_cols].to_numpy(dtype=np.float64)
        else:
            arr = np.asarray(data, dtype=np.float64)
            if arr.ndim == 1:
                arr = arr.reshape(-1, 1)
            self.fitted_columns = [f"feat_{i}" for i in range(arr.shape[1])]
            return arr

    def fit(self, data: Union[pd.DataFrame, np.ndarray]) -> ZScoreDetector:
        matrix = self._extract_matrix(data)
        if matrix.shape[0] == 0:
            raise AnomalyDetectionError("Cannot fit ZScoreDetector on empty data matrix.")

        self.means = np.nanmean(matrix, axis=0)
        self.stds = np.nanstd(matrix, axis=0)
        # Avoid division by zero
        self.stds = np.where(self.stds < 1e-9, 1.0, self.stds)
        logger.info("ZScoreDetector fitted across %d features", matrix.shape[1])
        return self

    def predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        if self.means.size == 0 or self.stds.size == 0:
            raise AnomalyDetectionError("ZScoreDetector must be fitted prior to predict.")

        matrix = self._extract_matrix(data)
        # Compute z matrix
        z_matrix = np.abs((matrix - self.means) / self.stds)
        # Replace NaNs with 0
        z_matrix = np.nan_to_num(z_matrix, nan=0.0)

        scores: List[AnomalyScore] = []
        for i in range(z_matrix.shape[0]):
            row_z = z_matrix[i]
            max_z = float(np.max(row_z))
            is_anom = bool(max_z > self.threshold)

            # Normalized score [0.0, 1.0] using logistic saturation
            norm_score = float(round(1.0 / (1.0 + math.exp(-0.8 * (max_z - self.threshold))), 4))

            # Identify offending feature
            offending_idx = int(np.argmax(row_z))
            offending_feat = (
                self.fitted_columns[offending_idx]
                if offending_idx < len(self.fitted_columns)
                else f"col_{offending_idx}"
            )

            explanation = (
                f"Z-Score exceeded threshold ({max_z:.2f} > {self.threshold}) on {offending_feat}"
                if is_anom
                else f"Normal (max Z-Score: {max_z:.2f})"
            )

            scores.append(
                AnomalyScore(
                    detector="ZScoreDetector",
                    is_anomaly=is_anom,
                    score=norm_score,
                    confidence=0.85,
                    explanation=explanation,
                    metrics={"max_z": round(max_z, 3)},
                )
            )

        return scores


class IQRDetector(BaseAnomalyDetector):
    """
    Non-parametric outlier detector using Tukey's interquartile fences.
    Robust to skewed non-Gaussian distributions (e.g. packet lengths, burst rates).
    """

    def __init__(
        self,
        multiplier: float = 1.5,
        feature_columns: Optional[List[str]] = None,
    ) -> None:
        self.multiplier = max(0.1, multiplier)
        self.feature_columns = feature_columns or DEFAULT_EVAL_COLUMNS
        self.lower_bounds: np.ndarray = np.array([])
        self.upper_bounds: np.ndarray = np.array([])
        self.fitted_columns: List[str] = []

    def _extract_matrix(self, data: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        if isinstance(data, pd.DataFrame):
            available_cols = [c for c in self.feature_columns if c in data.columns]
            self.fitted_columns = available_cols
            return data[available_cols].to_numpy(dtype=np.float64)
        else:
            arr = np.asarray(data, dtype=np.float64)
            if arr.ndim == 1:
                arr = arr.reshape(-1, 1)
            self.fitted_columns = [f"feat_{i}" for i in range(arr.shape[1])]
            return arr

    def fit(self, data: Union[pd.DataFrame, np.ndarray]) -> IQRDetector:
        matrix = self._extract_matrix(data)
        if matrix.shape[0] == 0:
            raise AnomalyDetectionError("Cannot fit IQRDetector on empty data matrix.")

        q25 = np.nanpercentile(matrix, 25, axis=0)
        q75 = np.nanpercentile(matrix, 75, axis=0)
        iqr = q75 - q25

        self.lower_bounds = q25 - self.multiplier * iqr
        self.upper_bounds = q75 + self.multiplier * iqr
        logger.info("IQRDetector fitted across %d features", matrix.shape[1])
        return self

    def predict(self, data: Union[pd.DataFrame, np.ndarray]) -> List[AnomalyScore]:
        if self.lower_bounds.size == 0:
            raise AnomalyDetectionError("IQRDetector must be fitted prior to predict.")

        matrix = self._extract_matrix(data)
        scores: List[AnomalyScore] = []

        for i in range(matrix.shape[0]):
            row = matrix[i]
            below = row < self.lower_bounds
            above = row > self.upper_bounds
            outlier_mask = below | above

            num_outliers = int(np.sum(outlier_mask))
            is_anom = num_outliers > 0

            # Score proportional to fraction of violating features
            score = min(1.0, (num_outliers / len(row)) * 1.5)

            explanation = (
                f"Violated IQR bounds on {num_outliers} features"
                if is_anom
                else "Within IQR bounds"
            )

            scores.append(
                AnomalyScore(
                    detector="IQRDetector",
                    is_anomaly=is_anom,
                    score=float(round(score, 4)),
                    confidence=0.80,
                    explanation=explanation,
                    metrics={"outlier_feature_count": float(num_outliers)},
                )
            )

        return scores
