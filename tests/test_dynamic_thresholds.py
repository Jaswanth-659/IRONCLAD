"""
Unit tests for IRONCLAD Adaptive Dynamic Threshold Management and Baseline Engine.
"""

import pytest
from ironclad.stats.dynamic_thresholds import (
    AnomalyCategory,
    DynamicAnomalyFlag,
    DynamicThresholdManager,
    FlagSeverity,
    StatisticalBaseline,
)


class TestDynamicThresholds:
    """Test statistical baselines, contamination filtering, and adaptive thresholds."""

    def test_statistical_baseline_calculation(self):
        manager = DynamicThresholdManager()
        samples = [10.0, 11.0, 12.0, 10.5, 9.5, 11.2, 10.8, 10.1, 11.5, 10.3]
        for s in samples:
            manager.record_observation(AnomalyCategory.PACKET_RATE, s)

        baseline = manager.calculate_baseline(AnomalyCategory.PACKET_RATE)

        assert baseline.sample_count == 10
        assert 10.0 <= baseline.mean <= 11.5
        assert 10.0 <= baseline.median <= 11.5
        assert baseline.std_dev >= 0.0
        assert baseline.p25 <= baseline.median <= baseline.p75
        assert baseline.iqr >= 0.0
        assert baseline.coefficient_of_variation >= 0.0

    def test_contamination_protection(self):
        """
        Verify that extreme attack/anomaly bursts are filtered during baseline calculation
        so malicious traffic cannot intentionally contaminate or raise normal baselines.
        """
        manager = DynamicThresholdManager()
        # Normal steady traffic around 100 pps
        normal_samples = [98.0, 102.0, 99.0, 101.0, 100.0, 97.0, 103.0, 99.5, 100.5, 98.5]
        for s in normal_samples:
            manager.record_observation(AnomalyCategory.PACKET_RATE, s)

        # Baseline before attack
        base_before = manager.calculate_baseline(AnomalyCategory.PACKET_RATE)
        assert 98.0 <= base_before.mean <= 102.0

        # Attempt to inject severe attack spike (10,000 pps) marked as suspicious
        attack_burst = [10000.0, 15000.0, 12000.0]
        for a in attack_burst:
            manager.record_observation(AnomalyCategory.PACKET_RATE, a, is_clean=False)

        # Baseline must NOT be contaminated by the attack burst
        base_after = manager.calculate_baseline(AnomalyCategory.PACKET_RATE)
        assert base_after.mean <= 105.0, f"Baseline was contaminated: {base_after.mean}"

    def test_dynamic_threshold_evaluation_and_flags(self):
        manager = DynamicThresholdManager()
        # Seed baseline at 50 units
        for s in [48.0, 52.0, 50.0, 49.0, 51.0] * 5:
            manager.record_observation(AnomalyCategory.PACKET_RATE, s)

        # Normal value within baseline
        flag_normal = manager.evaluate_value(
            AnomalyCategory.PACKET_RATE,
            observed_value=51.0,
            host="192.168.1.51",
            timestamp=100.0,
        )
        assert flag_normal.severity == FlagSeverity.NORMAL

        # Moderate anomaly (e.g. 200 units = surge)
        flag_high = manager.evaluate_value(
            AnomalyCategory.PACKET_RATE,
            observed_value=200.0,
            host="192.168.1.52",
            timestamp=105.0,
        )
        assert flag_high.severity in (FlagSeverity.HIGH, FlagSeverity.CRITICAL)
        assert flag_high.deviation_percentage > 50.0

    def test_all_12_anomaly_categories_supported(self):
        expected_categories = [
            AnomalyCategory.PACKET_RATE,
            AnomalyCategory.TRAFFIC_VOLUME,
            AnomalyCategory.PACKET_SIZE,
            AnomalyCategory.INTER_ARRIVAL_TIME,
            AnomalyCategory.PERIODICITY,
            AnomalyCategory.JITTER,
            AnomalyCategory.BURST_TRAFFIC,
            AnomalyCategory.DIRECTIONAL_IMBALANCE,
            AnomalyCategory.CONNECTION_FAILURES,
            AnomalyCategory.DESTINATION_DIVERSITY,
            AnomalyCategory.PROTOCOL_ANOMALY,
            AnomalyCategory.DATA_LOSS,
        ]
        assert len(expected_categories) == 12
        manager = DynamicThresholdManager()
        for cat in expected_categories:
            thresh = manager.get_thresholds(cat)
            assert "LOW" in thresh and "CRITICAL" in thresh
            cfg = manager.configs[cat]
            if cfg.direction == "lower":
                assert thresh["CRITICAL"] <= thresh["LOW"]
            else:
                assert thresh["LOW"] <= thresh["CRITICAL"]

    def test_multi_anomaly_correlation_without_double_counting(self):
        manager = DynamicThresholdManager()
        # Evaluate multiple flags for same host
        f1 = DynamicAnomalyFlag(
            anomaly_category=AnomalyCategory.PACKET_RATE.value,
            observed_value=250.0,
            expected_baseline=50.0,
            current_threshold=100.0,
            deviation_percentage=400.0,
            severity=FlagSeverity.CRITICAL,
            confidence=95.0,
            detection_explanation="Rate spike",
            associated_host="192.168.1.52",
            timestamp=100.0,
        )
        f2 = DynamicAnomalyFlag(
            anomaly_category=AnomalyCategory.TRAFFIC_VOLUME.value,
            observed_value=50000.0,
            expected_baseline=1000.0,
            current_threshold=5000.0,
            deviation_percentage=4900.0,
            severity=FlagSeverity.CRITICAL,
            confidence=95.0,
            detection_explanation="Byte surge",
            associated_host="192.168.1.52",
            timestamp=100.0,
        )

        corr = manager.correlate_flags([f1, f2])
        assert "host_assessments" in corr
        hosts = [h["host"] for h in corr["host_assessments"]]
        assert "192.168.1.52" in hosts
        host_corr = next(h for h in corr["host_assessments"] if h["host"] == "192.168.1.52")
        assert host_corr["flag_count"] == 2
        # Composite score must be bounded and not linearly double-counted
        assert host_corr["composite_score"] <= 10.0
