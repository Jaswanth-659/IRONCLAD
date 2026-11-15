"""
IRONCLAD Network Topology Graph Construction.

Builds directed, weighted communication graphs using NetworkX from packet streams
and aggregated flow records.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

import networkx as nx

from ironclad.core.exceptions import GraphConstructionError
from ironclad.core.ip_validation import validate_ipv4
from ironclad.core.logging import get_logger
from ironclad.core.types import FlowRecord, PacketSummary

logger = get_logger("graph.topology")


class NetworkGraphBuilder:
    """
    Constructs a directed graph $G = (V, E)$ where vertices $V$ represent host IP addresses
    and directed edges $E$ represent network communication channels with traffic weights.
    """

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()

    def add_packet(self, pkt: PacketSummary) -> None:
        """Add an individual packet's communication edge to the graph."""
        src = pkt.src_ip
        dst = pkt.dst_ip

        if not src or not dst:
            return

        # Ensure nodes exist and are valid IPv4 addresses
        if not self._ensure_node(src) or not self._ensure_node(dst):
            return

        # Update node byte/packet counters
        self.graph.nodes[src]["bytes_sent"] += pkt.length
        self.graph.nodes[src]["packets_sent"] += 1
        self.graph.nodes[dst]["bytes_recv"] += pkt.length
        self.graph.nodes[dst]["packets_recv"] += 1

        # Update or create directed edge
        if self.graph.has_edge(src, dst):
            edge_data = self.graph[src][dst]
            edge_data["weight"] += pkt.length
            edge_data["packet_count"] += 1
            if pkt.dst_port:
                edge_data["ports"].add(pkt.dst_port)
            edge_data["protocols"].add(pkt.protocol_name)
        else:
            ports = {pkt.dst_port} if pkt.dst_port else set()
            self.graph.add_edge(
                src,
                dst,
                weight=pkt.length,
                packet_count=1,
                ports=ports,
                protocols={pkt.protocol_name},
            )

    def add_flow(self, flow: FlowRecord) -> None:
        """Incorporate an aggregated FlowRecord into the graph."""
        src = flow.key.src_ip
        dst = flow.key.dst_ip

        if not self._ensure_node(src) or not self._ensure_node(dst):
            return

        self.graph.nodes[src]["bytes_sent"] += flow.forward_bytes
        self.graph.nodes[src]["packets_sent"] += flow.forward_packets
        self.graph.nodes[dst]["bytes_recv"] += flow.forward_bytes
        self.graph.nodes[dst]["packets_recv"] += flow.forward_packets

        if self.graph.has_edge(src, dst):
            edge_data = self.graph[src][dst]
            edge_data["weight"] += flow.forward_bytes
            edge_data["packet_count"] += flow.forward_packets
            if flow.key.dst_port:
                edge_data["ports"].add(flow.key.dst_port)
            edge_data["protocols"].add(flow.key.protocol.name)
        else:
            ports = {flow.key.dst_port} if flow.key.dst_port else set()
            self.graph.add_edge(
                src,
                dst,
                weight=flow.forward_bytes,
                packet_count=flow.forward_packets,
                ports=ports,
                protocols={flow.key.protocol.name},
            )

        # If backward traffic exists, add reverse edge
        if flow.backward_packets > 0:
            self._ensure_node(dst)
            self._ensure_node(src)
            self.graph.nodes[dst]["bytes_sent"] += flow.backward_bytes
            self.graph.nodes[dst]["packets_sent"] += flow.backward_packets
            self.graph.nodes[src]["bytes_recv"] += flow.backward_bytes
            self.graph.nodes[src]["packets_recv"] += flow.backward_packets

            if self.graph.has_edge(dst, src):
                edge_data = self.graph[dst][src]
                edge_data["weight"] += flow.backward_bytes
                edge_data["packet_count"] += flow.backward_packets
                if flow.key.src_port:
                    edge_data["ports"].add(flow.key.src_port)
                edge_data["protocols"].add(flow.key.protocol.name)
            else:
                rev_ports = {flow.key.src_port} if flow.key.src_port else set()
                self.graph.add_edge(
                    dst,
                    src,
                    weight=flow.backward_bytes,
                    packet_count=flow.backward_packets,
                    ports=rev_ports,
                    protocols={flow.key.protocol.name},
                )

    def _ensure_node(self, ip: str) -> bool:
        val = validate_ipv4(ip)
        if not val.is_valid:
            return False
        norm = val.normalized_ip or ip
        if not self.graph.has_node(norm):
            self.graph.add_node(
                norm,
                bytes_sent=0,
                bytes_recv=0,
                packets_sent=0,
                packets_recv=0,
            )
        return True

    def build_from_flows(self, flows: Iterable[FlowRecord]) -> nx.DiGraph:
        """Populate graph from an iterable of flow records."""
        for f in flows:
            self.add_flow(f)
        logger.info(
            "Constructed network topology: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )
        return self.graph

    def build_from_packets(self, packets: Iterable[PacketSummary]) -> nx.DiGraph:
        """Populate graph from an iterable of packet summaries."""
        for p in packets:
            self.add_packet(p)
        logger.info(
            "Constructed network topology: %d nodes, %d edges",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
        )
        return self.graph

    def get_graph(self) -> nx.DiGraph:
        """Retrieve the underlying NetworkX DiGraph instance."""
        return self.graph
