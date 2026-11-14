"""
Unit tests for ironclad.graph.
"""

from ironclad.core.types import FlowKey, FlowRecord, PacketSummary, Protocol
from ironclad.graph.metrics import GraphMetricAnalyzer
from ironclad.graph.topology import NetworkGraphBuilder


def test_network_graph_builder_and_metrics():
    builder = NetworkGraphBuilder()

    # Create a star topology representing a scanner (192.168.1.100 -> 10 targets)
    packets = []
    scanner_ip = "192.168.1.100"
    for i in range(10):
        target_ip = f"10.0.0.{i+1}"
        pkt = PacketSummary(
            timestamp=100.0 + i,
            length=64,
            src_ip=scanner_ip,
            dst_ip=target_ip,
            src_port=50000 + i,
            dst_port=80,
            protocol=Protocol.TCP,
            protocol_name="TCP",
        )
        builder.add_packet(pkt)

    graph = builder.get_graph()
    assert graph.number_of_nodes() == 11
    assert graph.number_of_edges() == 10

    analyzer = GraphMetricAnalyzer(fanout_threshold=5.0)
    metrics = analyzer.analyze(graph)

    assert scanner_ip in metrics
    scanner_metrics = metrics[scanner_ip]
    assert scanner_metrics.out_degree == 10
    assert scanner_metrics.in_degree == 0
    assert scanner_metrics.fan_out_ratio == 10.0  # 10 / (0 + 1)
    assert scanner_metrics.unique_peers == 10

    scanners = analyzer.identify_scanners(metrics)
    assert scanner_ip in scanners
