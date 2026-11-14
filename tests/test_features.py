"""
Unit tests for ironclad.features.
"""

import os
from ironclad.core.types import PacketSummary, Protocol
from ironclad.features.entropy import (
    analyze_payload_cryptography,
    block_entropy,
    chi_squared_uniformity,
    shannon_entropy,
)
from ironclad.features.flow_aggregator import FlowAggregator
from ironclad.features.temporal import (
    calculate_burstiness,
    calculate_inter_arrival_times,
    calculate_jitter,
    extract_temporal_metrics,
)


def test_entropy_calculations():
    # Maximum entropy data (~8.0)
    random_bytes = os.urandom(1024)
    ent, chi, is_enc = analyze_payload_cryptography(random_bytes)
    assert ent > 7.4
    assert is_enc is True

    # Low entropy data
    text = b"AAAAABBBBBCCCCCDDDDD" * 10
    ent_low, _, is_enc_low = analyze_payload_cryptography(text)
    assert ent_low < 4.0
    assert is_enc_low is False

    # Block entropy
    blocks = block_entropy(random_bytes, block_size=256)
    assert len(blocks) == 4
    for b_ent in blocks:
        assert b_ent > 6.5


def test_temporal_metrics():
    timestamps = [10.0, 10.1, 10.3, 10.6, 11.0]
    iats = calculate_inter_arrival_times(timestamps)
    assert len(iats) == 4
    assert round(iats[0], 2) == 0.10
    assert round(iats[1], 2) == 0.20

    jitter = calculate_jitter(iats)
    assert jitter >= 0.0

    burst = calculate_burstiness(mean_val=0.25, std_val=0.10)
    assert -1.0 <= burst <= 1.0

    metrics = extract_temporal_metrics(timestamps)
    assert metrics["duration"] == 1.0
    assert metrics["iat_min"] == 0.10


def test_flow_aggregator(sample_packet_summaries):
    aggregator = FlowAggregator(bidirectional=True)
    flows = aggregator.aggregate_stream(sample_packet_summaries)

    # Since packets are between the same 2 endpoints in opposite directions,
    # bidirectional aggregation must merge them into 1 flow
    assert len(flows) == 1
    f = flows[0]
    assert f.packet_count == 2
    assert f.forward_packets == 1
    assert f.backward_packets == 1
    assert f.byte_count == 200

    df = aggregator.to_dataframe()
    assert len(df) == 1
    assert "pps" in df.columns
    assert "mean_payload_entropy" in df.columns
