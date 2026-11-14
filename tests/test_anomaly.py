"""
Unit tests for ironclad.anomaly.
"""

import numpy as np
import pandas as pd
import pytest

from ironclad.anomaly.detector import HybridAnomalyDetector
from ironclad.anomaly.isolation_forest import IsolationForestDetector
from ironclad.anomaly.statistical import IQRDetector, ZScoreDetector


@pytest.fixture
def sample_feature_dataframe():
    """Create a DataFrame of 20 normal flows and 2 extreme outlier flows."""
    rows = []
    # 20 normal benign flows
    for _ in range(20):
        rows.append({
            "packet_count": np.random.randint(10, 30),
            "byte_count": np.random.randint(1000, 3000),
            "forward_bytes": 1000,
            "backward_bytes": 1000,
            "packet_length_mean": 100.0,
            "packet_length_std": 10.0,
            "iat_mean": 0.05,
            "iat_std": 0.01,
            "pps": 20.0,
            "bps": 2000.0,
            "syn_ack_ratio": 1.0,
            "mean_payload_entropy": 4.2,
            "burstiness": 0.0,
            "jitter": 0.005,
        })

    # Outlier 1: SYN flood / port scan profile
    rows.append({
        "packet_count": 500,
        "byte_count": 25000,
        "forward_bytes": 25000,
        "backward_bytes": 0,
        "packet_length_mean": 50.0,
        "packet_length_std": 0.0,
        "iat_mean": 0.001,
        "iat_std": 0.0001,
        "pps": 1000.0,
        "bps": 50000.0,
        "syn_ack_ratio": 50.0,
        "mean_payload_entropy": 0.0,
        "burstiness": 0.9,
        "jitter": 0.0001,
    })

    # Outlier 2: High entropy exfiltration
    rows.append({
        "packet_count": 100,
        "byte_count": 150000,
        "forward_bytes": 150000,
        "backward_bytes": 50,
        "packet_length_mean": 1400.0,
        "packet_length_std": 20.0,
        "iat_mean": 0.01,
        "iat_std": 0.002,
        "pps": 100.0,
        "bps": 150000.0,
        "syn_ack_ratio": 0.5,
        "mean_payload_entropy": 7.95,
        "burstiness": 0.3,
        "jitter": 0.001,
    })

    return pd.DataFrame(rows)


def test_z_score_detector(sample_feature_dataframe):
    detector = ZScoreDetector(threshold=2.5)
    scores = detector.fit_predict(sample_feature_dataframe)
    assert len(scores) == 22
    # At least one of the outliers should have high anomaly score or is_anomaly
    outlier_scores = scores[20:]
    assert any(s.score > 0.6 for s in outlier_scores)


def test_iqr_detector(sample_feature_dataframe):
    detector = IQRDetector(multiplier=1.5)
    scores = detector.fit_predict(sample_feature_dataframe)
    assert len(scores) == 22
    outlier_scores = scores[20:]
    assert any(s.is_anomaly for s in outlier_scores)


def test_isolation_forest_detector(sample_feature_dataframe):
    detector = IsolationForestDetector(contamination=0.1, random_state=42)
    scores = detector.fit_predict(sample_feature_dataframe)
    assert len(scores) == 22
    for s in scores:
        assert 0.0 <= s.score <= 1.0


def test_hybrid_anomaly_detector(sample_feature_dataframe):
    ensemble = HybridAnomalyDetector()
    ensemble.add_detector(ZScoreDetector(threshold=2.5), weight=0.5)
    ensemble.add_detector(IsolationForestDetector(contamination=0.1, random_state=42), weight=0.5)

    scores = ensemble.fit_predict(sample_feature_dataframe)
    assert len(scores) == 22
    assert scores[0].detector == "HybridEnsemble"
