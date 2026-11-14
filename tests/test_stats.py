"""
Unit tests for ironclad.stats.
"""

import numpy as np
import pytest

from ironclad.stats.baseline import TrafficBaseline
from ironclad.stats.distribution import (
    compute_distribution_summary,
    compute_iqr_bounds,
    compute_z_scores,
    evaluate_distribution_shift,
)


def test_compute_distribution_summary():
    data = [10.0, 12.0, 15.0, 18.0, 20.0, 22.0, 25.0]
    summary = compute_distribution_summary(data)
    assert summary["count"] == 7.0
    assert summary["mean"] > 0.0
    assert summary["std"] > 0.0
    assert summary["iqr"] > 0.0


def test_compute_z_scores():
    data = [10.0, 10.0, 10.0, 10.0]
    # Zero standard deviation should not fail
    z = compute_z_scores(data)
    assert np.all(z == 0.0)

    varied = [1.0, 2.0, 3.0, 4.0, 5.0]
    z_var = compute_z_scores(varied)
    assert abs(np.mean(z_var)) < 1e-6
    assert abs(np.std(z_var) - 1.0) < 1e-6


def test_compute_iqr_bounds():
    data = list(range(100))
    lower, upper = compute_iqr_bounds(data, multiplier=1.5)
    assert lower < 25
    assert upper > 75


def test_distribution_shift_ks():
    sample1 = np.random.normal(loc=10.0, scale=1.0, size=50)
    sample2 = np.random.normal(loc=10.0, scale=1.0, size=50)
    shift_no = evaluate_distribution_shift(sample1, sample2)
    assert shift_no["is_shifted"] is False

    sample3 = np.random.normal(loc=50.0, scale=1.0, size=50)
    shift_yes = evaluate_distribution_shift(sample1, sample3)
    assert shift_yes["is_shifted"] is True


def test_traffic_baseline(tmp_path):
    baseline = TrafficBaseline(name="test_profile")
    samples = [100.0, 102.0, 98.0, 105.0, 95.0, 101.0]
    baseline.fit_metric("packet_length", samples)

    check = baseline.check_anomaly("packet_length", [99.0, 101.0, 100.0, 102.0, 98.0])
    assert check["metric"] == "packet_length"
    assert check["is_shifted"] is False

    # Persistence
    save_file = tmp_path / "baseline.json"
    baseline.save(save_file)
    assert save_file.exists()

    loaded = TrafficBaseline.load(save_file)
    assert loaded.name == "test_profile"
    assert "packet_length" in loaded.metric_summaries
