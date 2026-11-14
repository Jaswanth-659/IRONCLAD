"""
IRONCLAD End-to-End Network Telemetry & Cryptographic Analysis Pipeline.

Coordinates the complete analysis lifecycle:
PCAP Ingestion -> Packet Parsing -> Flow Aggregation -> Anomaly Detection ->
Network Topology Analysis -> Risk Scoring -> Comprehensive Telemetry Report.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional, Tuple, Union

from ironclad.anomaly.detector import HybridAnomalyDetector
from ironclad.anomaly.isolation_forest import IsolationForestDetector
from ironclad.anomaly.statistical import IQRDetector, ZScoreDetector
from ironclad.config.settings import EngineConfig
from ironclad.core.exceptions import IroncladError
from ironclad.core.logging import get_logger, setup_logging
from ironclad.core.types import (
    AnalysisReport,
    AnomalyScore,
    FlowRecord,
    RiskScore,
)
from ironclad.features.flow_aggregator import FlowAggregator
from ironclad.graph.metrics import GraphMetricAnalyzer
from ironclad.graph.topology import NetworkGraphBuilder
from ironclad.ingestion.pcap_reader import PCAPReader
from ironclad.parsing.dissector import PacketDissector
from ironclad.risk.scorer import RiskScorer

logger = get_logger("pipeline")


class IroncladEngine:
    """
    Unified high-level facade for the IRONCLAD analysis engine.
    """

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig.default()

        # Initialize logging
        setup_logging(
            level=self.config.logging.level,
            log_file=self.config.logging.log_file,
            enable_console=self.config.logging.enable_console,
        )

        # Initialize pipeline stages
        self.dissector = PacketDissector(
            parse_payload=self.config.parsing.parse_payload,
            payload_preview_bytes=self.config.parsing.payload_preview_bytes,
            compute_entropy=self.config.parsing.compute_packet_entropy,
        )

        self.flow_aggregator = FlowAggregator(
            bidirectional=self.config.features.bidirectional_flows,
            flow_timeout_seconds=self.config.features.flow_timeout_seconds,
        )

        self.graph_builder = NetworkGraphBuilder()
        self.graph_analyzer = GraphMetricAnalyzer(
            calculate_pagerank=self.config.graph.calculate_pagerank,
            calculate_clustering=self.config.graph.calculate_clustering,
            fanout_threshold=self.config.graph.fanout_threshold,
        )

        self.risk_scorer = RiskScorer(config=self.config.risk)

    def _build_anomaly_detector(self) -> HybridAnomalyDetector:
        """Construct anomaly detection ensemble matching configuration."""
        z_score_det = ZScoreDetector(threshold=self.config.anomaly.z_score_threshold)
        iqr_det = IQRDetector(multiplier=self.config.anomaly.iqr_multiplier)
        iso_det = IsolationForestDetector(
            contamination=self.config.anomaly.contamination,
            n_estimators=self.config.anomaly.n_estimators,
            random_state=self.config.anomaly.random_state,
        )

        ensemble = HybridAnomalyDetector()
        ensemble.add_detector(z_score_det, weight=0.30)
        ensemble.add_detector(iqr_det, weight=0.20)
        ensemble.add_detector(iso_det, weight=0.50)
        return ensemble

    def analyze_pcap(self, pcap_path: Union[str, Path]) -> AnalysisReport:
        """
        Execute end-to-end analysis on a PCAP or PCAPNG capture file.

        Args:
            pcap_path: Path to target capture file.

        Returns:
            AnalysisReport containing metrics, anomaly scores, topology, and risk findings.
        """
        t0 = time.perf_counter()
        target = Path(pcap_path).resolve()
        logger.info("Initiating IRONCLAD analysis on: %s", target)

        # Reset stateful aggregators
        self.flow_aggregator.clear()
        self.graph_builder = NetworkGraphBuilder()

        # Stage 1: Ingestion
        reader = PCAPReader(
            filepath=target,
            batch_size=self.config.ingestion.batch_size,
            max_packets=self.config.ingestion.max_packets,
            bpf_filter=self.config.ingestion.bpf_filter,
        )

        # Stage 2: Packet Parsing & Streaming Dissection
        total_packets = 0
        total_bytes = 0
        first_ts: Optional[float] = None
        last_ts: Optional[float] = None

        for pkt in reader.stream_packets():
            summary = self.dissector.dissect(pkt, index=total_packets)
            if summary is not None:
                total_packets += 1
                total_bytes += summary.length

                if first_ts is None:
                    first_ts = summary.timestamp
                last_ts = summary.timestamp

                # Incorporate into flow table and graph
                self.flow_aggregator.add_packet(summary)
                self.graph_builder.add_packet(summary)

        capture_duration = max(0.0, (last_ts or 0.0) - (first_ts or 0.0))
        flows = self.flow_aggregator.get_flows()
        logger.info(
            "Parsed %d packets (%d bytes, %.2fs duration). Aggregated into %d flows.",
            total_packets,
            total_bytes,
            capture_duration,
            len(flows),
        )

        # Stage 3: Topology Analysis
        graph = self.graph_builder.get_graph()
        host_metrics = self.graph_analyzer.analyze(graph)

        # Stage 4: Feature Matrix & Anomaly Detection
        anomalous_flows: List[Tuple[FlowRecord, AnomalyScore]] = []
        flow_risk_scores: List[RiskScore] = []
        risk_score_map: dict[str, RiskScore] = {}

        if flows:
            df = self.flow_aggregator.to_dataframe()
            detector = self._build_anomaly_detector()

            # Train / evaluate anomaly detector
            if len(df) >= 2:
                try:
                    anomaly_scores = detector.fit_predict(df)
                except Exception as e:
                    logger.warning("Anomaly detector fitting encountered error: %s. Using default scores.", e)
                    anomaly_scores = [
                        AnomalyScore(detector="Fallback", is_anomaly=False, score=0.0, confidence=0.0)
                        for _ in range(len(flows))
                    ]
            else:
                # Single flow case: heuristic only
                anomaly_scores = [
                    AnomalyScore(detector="InsufficientSamples", is_anomaly=False, score=0.0, confidence=0.0)
                    for _ in range(len(flows))
                ]

            # Stage 5: Risk Scoring per Flow
            for idx, flow in enumerate(flows):
                anom_score = anomaly_scores[idx]
                if anom_score.is_anomaly:
                    anomalous_flows.append((flow, anom_score))

                src_host_metric = host_metrics.get(flow.key.src_ip)
                risk = self.risk_scorer.score_flow(
                    flow=flow,
                    anomaly_score=anom_score,
                    graph_metrics=src_host_metric,
                )
                flow_risk_scores.append(risk)
                risk_score_map[flow.canonical_id] = risk

        # Stage 6: Risk Scoring per Host
        host_risk_scores: List[RiskScore] = []
        for ip, metrics in host_metrics.items():
            hrisk = self.risk_scorer.score_host(metrics)
            host_risk_scores.append(hrisk)
            risk_score_map[ip] = hrisk

        # Stage 7: Global Capture Risk Index
        global_risk = self.risk_scorer.compute_global_risk(
            flow_scores=flow_risk_scores,
            host_scores=host_risk_scores,
        )

        execution_time = time.perf_counter() - t0
        logger.info(
            "Analysis complete in %.3fs. Global Risk: %.1f [%s] with %d findings.",
            execution_time,
            global_risk.score,
            global_risk.severity.value,
            len(global_risk.findings),
        )

        return AnalysisReport(
            capture_source=str(target),
            total_packets=total_packets,
            total_bytes=total_bytes,
            capture_duration=round(capture_duration, 3),
            flow_count=len(flows),
            unique_hosts=len(host_metrics),
            anomalous_flows=anomalous_flows,
            host_metrics=host_metrics,
            risk_scores=risk_score_map,
            global_risk=global_risk,
            execution_time_seconds=round(execution_time, 4),
        )
