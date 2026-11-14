"""
IRONCLAD Graph Metric Analyzer.

Computes topological metrics on network communication graphs including PageRank,
degree centralities, clustering coefficients, and fan-out anomaly ratios.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import networkx as nx

from ironclad.core.exceptions import GraphConstructionError
from ironclad.core.logging import get_logger
from ironclad.core.types import GraphNodeMetrics

logger = get_logger("graph.metrics")


class GraphMetricAnalyzer:
    """
    Analyzes topological characteristics of network communication graphs.
    Identifies high-centrality command servers, scanning nodes, and peripheral beacons.
    """

    def __init__(
        self,
        calculate_pagerank: bool = True,
        calculate_clustering: bool = True,
        fanout_threshold: float = 10.0,
    ) -> None:
        self.calculate_pagerank = calculate_pagerank
        self.calculate_clustering = calculate_clustering
        self.fanout_threshold = fanout_threshold

    def analyze(self, graph: nx.DiGraph) -> Dict[str, GraphNodeMetrics]:
        """
        Compute graph metrics for all active nodes in the network topology.

        Args:
            graph: NetworkX directed graph of host communications.

        Returns:
            Dictionary mapping IP addresses to GraphNodeMetrics.
        """
        if graph.number_of_nodes() == 0:
            return {}

        n_nodes = graph.number_of_nodes()

        # Compute centralities
        deg_centrality = nx.degree_centrality(graph)
        in_deg_centrality = nx.in_degree_centrality(graph)
        out_deg_centrality = nx.out_degree_centrality(graph)

        # PageRank computation
        pagerank_dict: Dict[str, float] = {}
        if self.calculate_pagerank and n_nodes > 1:
            try:
                pagerank_dict = nx.pagerank(graph, alpha=0.85, max_iter=200)
            except Exception as e:
                logger.warning("PageRank calculation failed or did not converge: %s", e)
                pagerank_dict = {node: 1.0 / n_nodes for node in graph.nodes()}
        else:
            pagerank_dict = {node: 1.0 / max(1, n_nodes) for node in graph.nodes()}

        # Local clustering coefficient (on undirected view)
        clustering_dict: Dict[str, float] = {}
        if self.calculate_clustering and n_nodes > 2:
            try:
                undirected_view = graph.to_undirected()
                clustering_dict = nx.clustering(undirected_view)
            except Exception as e:
                logger.warning("Clustering coefficient calculation failed: %s", e)
                clustering_dict = {node: 0.0 for node in graph.nodes()}
        else:
            clustering_dict = {node: 0.0 for node in graph.nodes()}

        node_metrics: Dict[str, GraphNodeMetrics] = {}

        for ip in graph.nodes():
            node_attrs = graph.nodes[ip]
            in_deg = graph.in_degree(ip)
            out_deg = graph.out_degree(ip)
            total_deg = in_deg + out_deg

            # Fan-out ratio: out_degree / (in_degree + 1)
            # High fan-out with low in-degree strongly indicates reconnaissance/scanning
            fan_out = float(out_deg) / float(in_deg + 1)

            # Unique peers = predecessor + successor nodes
            predecessors = set(graph.predecessors(ip))
            successors = set(graph.successors(ip))
            unique_peers = len(predecessors.union(successors))

            metrics = GraphNodeMetrics(
                ip=ip,
                degree=total_deg,
                in_degree=in_deg,
                out_degree=out_deg,
                degree_centrality=round(deg_centrality.get(ip, 0.0), 6),
                in_degree_centrality=round(in_deg_centrality.get(ip, 0.0), 6),
                out_degree_centrality=round(out_deg_centrality.get(ip, 0.0), 6),
                pagerank=round(pagerank_dict.get(ip, 0.0), 6),
                clustering_coefficient=round(clustering_dict.get(ip, 0.0), 6),
                fan_out_ratio=round(fan_out, 4),
                total_bytes_sent=node_attrs.get("bytes_sent", 0),
                total_bytes_received=node_attrs.get("bytes_recv", 0),
                unique_peers=unique_peers,
            )
            node_metrics[ip] = metrics

        logger.info("Computed graph metrics across %d host nodes", len(node_metrics))
        return node_metrics

    def identify_scanners(
        self, metrics: Dict[str, GraphNodeMetrics]
    ) -> List[str]:
        """
        Identify host nodes displaying reconnaissance or scanning fan-out behavior.

        Returns:
            List of IP addresses flagged as potential scanners.
        """
        scanners = []
        for ip, m in metrics.items():
            if m.fan_out_ratio >= self.fanout_threshold and m.out_degree >= 5:
                scanners.append(ip)
        return scanners
