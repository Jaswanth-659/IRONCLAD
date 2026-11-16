"""
IRONCLAD Asynchronous Pipeline Execution Runner.

Executes end-to-end packet processing, multi-engine detection, and decision correlation
in background threads without blocking the asynchronous FastAPI event loop.
Broadcasts real-time events and progress updates to connected WebSocket clients.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

from ironclad.core.logging import get_logger
from ironclad.engines.connection import ConnectionBehaviourEngine
from ironclad.engines.decision import DecisionCorrelationEngine
from ironclad.engines.temporal import TemporalBehaviourEngine
from ironclad.engines.traffic import TrafficBehaviourEngine
from ironclad.features.data_loss import DataLossMonitor
from ironclad.features.flow_aggregator import FlowAggregator
from ironclad.features.traffic_rate import TrafficRateMonitor
from ironclad.graph.metrics import GraphMetricAnalyzer
from ironclad.graph.topology import NetworkGraphBuilder
from ironclad.ingestion.pcap_reader import PCAPReader
from ironclad.parsing.dissector import PacketDissector
from ironclad.server.database import (
    build_and_save_session_topology,
    complete_session,
    save_engine_evaluation,
    save_incident,
    save_session_data_loss,
    save_session_dynamic_flags,
    save_session_traffic_rates,
    save_subengine_evaluation,
    update_session_progress,
)
from ironclad.server.ws import ws_manager

logger = get_logger("server.pipeline_runner")
_executor = ThreadPoolExecutor(max_workers=4)


async def execute_pcap_analysis(task_id: str, pcap_path: str, filename: str) -> None:
    """
    Asynchronous task entry point. Offloads CPU-intensive packet dissection
    to worker thread while streaming real-time status via WebSockets.
    """
    logger.info("Starting background analysis task: %s (file: %s)", task_id, filename)
    loop = asyncio.get_running_loop()

    try:
        # Step 1: Ingestion notification
        update_session_progress(task_id, 10.0, "Parsing PCAP Frames")
        await ws_manager.broadcast("ANALYSIS_PROGRESS", {
            "task_id": task_id,
            "progress": 10.0,
            "step": "Ingesting and dissecting packet frames...",
        })

        # Run heavy dissection and flow aggregation in thread
        dissection_result = await loop.run_in_executor(
            _executor, _sync_dissect_and_aggregate, pcap_path
        )

        flows = dissection_result["flows"]
        host_metrics = dissection_result["host_metrics"]
        total_packets = dissection_result["total_packets"]
        total_bytes = dissection_result["total_bytes"]
        duration = dissection_result["duration"]
        data_loss_report = dissection_result.get("data_loss_report")
        traffic_rate_report = dissection_result.get("traffic_rate_report")

        update_session_progress(task_id, 35.0, "Running Primary Detection Engines")
        await ws_manager.broadcast("ANALYSIS_PROGRESS", {
            "task_id": task_id,
            "progress": 35.0,
            "step": f"Aggregated {len(flows)} flows across {len(host_metrics)} hosts. Executing Engine 1...",
            "total_packets": total_packets,
            "total_flows": len(flows),
        })

        # Step 2: Execute Primary Detection Engines in Worker Thread
        engine_evaluations = await loop.run_in_executor(
            _executor, _sync_run_detection_engines, flows, host_metrics
        )

        update_session_progress(task_id, 75.0, "Synthesizing Decision & Correlation")
        await ws_manager.broadcast("ANALYSIS_PROGRESS", {
            "task_id": task_id,
            "progress": 75.0,
            "step": "Primary & secondary engines complete. Correlating cross-engine findings...",
            "engines": {
                k: {"score": v.risk_score, "escalation": v.escalation.value}
                for k, v in engine_evaluations.items()
            },
        })

        # Step 2.5: Evaluate dynamic anomaly flags across all 12 categories
        from ironclad.stats.dynamic_thresholds import dynamic_threshold_manager
        session_dynamic_flags = dynamic_threshold_manager.evaluate_session_anomalies(
            flows=flows,
            host_metrics=host_metrics,
            data_loss_report=data_loss_report,
            traffic_rate_report=traffic_rate_report,
        )

        # Step 3: Run Decision and Correlation Engine (Engine 4)
        decision_context = {
            "data_loss": data_loss_report,
            "traffic_rate": traffic_rate_report,
            "dynamic_flags": session_dynamic_flags,
        }
        decision_report = await loop.run_in_executor(
            _executor, _sync_run_decision_engine, engine_evaluations, flows, host_metrics, decision_context
        )

        # Step 4: Persist Results to SQLite
        await loop.run_in_executor(
            _executor,
            _sync_persist_results,
            task_id,
            decision_report,
            total_packets,
            total_bytes,
            len(flows),
            len(host_metrics),
            duration,
            pcap_path,
            data_loss_report,
            traffic_rate_report,
            session_dynamic_flags,
        )

        # Step 5: Final completion update
        await ws_manager.broadcast("ANALYSIS_COMPLETED", {
            "task_id": task_id,
            "progress": 100.0,
            "status": "COMPLETED",
            "overall_risk_score": decision_report.overall_risk_score,
            "final_classification": decision_report.final_classification.value,
            "total_packets": total_packets,
            "total_flows": len(flows),
            "unique_hosts": len(host_metrics),
            "summary": decision_report.executive_summary,
            "recommended_actions": decision_report.recommended_actions,
            "data_loss": data_loss_report.to_dict() if data_loss_report else None,
            "traffic_rates": traffic_rate_report.to_dict() if traffic_rate_report else None,
        })
        logger.info("Successfully finished analysis for task %s with risk %.2f", task_id, decision_report.overall_risk_score)

    except Exception as e:
        logger.error("Analysis pipeline failed on task %s: %s", task_id, e, exc_info=True)
        update_session_progress(task_id, 0.0, f"Failed: {str(e)}")
        await ws_manager.broadcast("ANALYSIS_FAILED", {
            "task_id": task_id,
            "error": str(e),
        })


def _sync_dissect_and_aggregate(pcap_path: str) -> Dict[str, Any]:
    """Synchronous CPU worker: Read packets, dissect headers, aggregate flows, graph, loss, and rates."""
    reader = PCAPReader(pcap_path)
    dissector = PacketDissector(parse_payload=True, compute_entropy=True)
    aggregator = FlowAggregator(bidirectional=True)
    graph_builder = NetworkGraphBuilder()
    loss_monitor = DataLossMonitor()
    rate_monitor = TrafficRateMonitor()

    total_packets = 0
    total_bytes = 0
    first_ts = None
    last_ts = None

    for pkt in reader.stream_packets():
        summary = dissector.dissect(pkt, index=total_packets)
        if summary is not None:
            total_packets += 1
            total_bytes += summary.length
            if first_ts is None:
                first_ts = summary.timestamp
            last_ts = summary.timestamp

            aggregator.add_packet(summary)
            graph_builder.add_packet(summary)
            loss_monitor.ingest_packet(summary, raw_scapy_packet=pkt)
            rate_monitor.ingest_packet(summary)

    flows = aggregator.get_flows()
    graph = graph_builder.get_graph()
    analyzer = GraphMetricAnalyzer()
    host_metrics = analyzer.analyze(graph)
    duration = max(0.0, (last_ts or 0.0) - (first_ts or 0.0))

    data_loss_report = loss_monitor.generate_report()
    traffic_rate_report = rate_monitor.generate_report()

    return {
        "flows": flows,
        "host_metrics": host_metrics,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration": duration,
        "data_loss_report": data_loss_report,
        "traffic_rate_report": traffic_rate_report,
    }


def _sync_run_detection_engines(flows: List[Any], host_metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous worker: Run the 3 primary engines."""
    e1 = TemporalBehaviourEngine()
    e2 = TrafficBehaviourEngine()
    e3 = ConnectionBehaviourEngine()

    res1 = e1.evaluate(flows, host_metrics)
    res2 = e2.evaluate(flows, host_metrics)
    res3 = e3.evaluate(flows, host_metrics)

    return {
        "ENGINE_1_TEMPORAL": res1,
        "ENGINE_2_TRAFFIC": res2,
        "ENGINE_3_CONNECTION": res3,
    }


def _sync_run_decision_engine(
    engine_evaluations: Dict[str, Any],
    flows: List[Any],
    host_metrics: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None,
) -> Any:
    """Synchronous worker: Run Engine 4 (Decision and Correlation)."""
    decision_engine = DecisionCorrelationEngine()
    return decision_engine.evaluate(engine_evaluations, flows, host_metrics, context=context)


def _sync_persist_results(
    task_id: str,
    decision_report: Any,
    total_packets: int,
    total_bytes: int,
    total_flows: int,
    unique_hosts: int,
    duration: float,
    pcap_path: Optional[str] = None,
    data_loss_report: Optional[Any] = None,
    traffic_rate_report: Optional[Any] = None,
    dynamic_flags: Optional[List[Any]] = None,
) -> None:
    """Save all evaluation outputs, sub-engines, data loss, traffic rates, dynamic flags, and derived incidents to SQLite."""
    # Complete main session record
    complete_session(
        task_id=task_id,
        total_packets=total_packets,
        total_bytes=total_bytes,
        total_flows=total_flows,
        unique_hosts=unique_hosts,
        duration_sec=duration,
        overall_risk_score=decision_report.overall_risk_score,
        final_classification=decision_report.final_classification.value,
        executive_summary=decision_report.executive_summary,
    )

    # Persist session data loss telemetry
    if data_loss_report is not None:
        try:
            save_session_data_loss(task_id, data_loss_report.to_dict())
        except Exception as e:
            logger.error("Failed saving session data loss for %s: %s", task_id, e)

    # Persist traffic rate telemetry
    if traffic_rate_report is not None:
        try:
            save_session_traffic_rates(task_id, traffic_rate_report.to_dict())
        except Exception as e:
            logger.error("Failed saving session traffic rates for %s: %s", task_id, e)

    # Persist comprehensive dynamic anomaly flags list across all 12 categories
    try:
        flags_to_save = []
        if dynamic_flags:
            flags_to_save = [f.to_dict() if hasattr(f, "to_dict") else f for f in dynamic_flags]
        elif traffic_rate_report is not None and hasattr(traffic_rate_report, "rate_flags"):
            flags_to_save = [f.to_dict() if hasattr(f, "to_dict") else f for f in traffic_rate_report.rate_flags]
        save_session_dynamic_flags(task_id, flags_to_save)
    except Exception as e:
        logger.error("Failed saving session dynamic flags for %s: %s", task_id, e)

    # Persist Primary Engines & Sub-Engines
    for eng_id, eng in decision_report.engine_results.items():
        save_engine_evaluation(
            session_id=task_id,
            engine_id=eng.engine_id,
            name=eng.name,
            risk_score=eng.risk_score,
            confidence_score=eng.confidence_score,
            status=eng.status.value,
            escalation=eng.escalation.value,
            explanation=eng.explanation,
            evidence=eng.evidence,
            execution_time_ms=eng.execution_time_ms,
        )

        for sub in eng.subengine_results:
            save_subengine_evaluation(
                session_id=task_id,
                subengine_id=sub.subengine_id,
                name=sub.name,
                parent_engine=sub.parent_engine,
                risk_score=sub.risk_score,
                confidence_score=sub.confidence_score,
                status=sub.status.value,
                explanation=sub.explanation,
                evidence=sub.evidence,
            )

            # Generate formal Incident records for actionable findings (score >= 5.0)
            if sub.risk_score >= 5.0:
                sev = "CRITICAL" if sub.risk_score >= 7.0 else "MEDIUM"
                ev = sub.evidence
                src_ip = "192.168.1.50"
                dst_ip = "EXTERNAL"
                port = 0

                # Extract target from evidence if present
                if "top_flow" in ev and isinstance(ev["top_flow"], dict):
                    src_ip = ev["top_flow"].get("flow_id", "").split(":")[0] if ":" in ev["top_flow"].get("flow_id", "") else src_ip
                    port = ev["top_flow"].get("dst_port", 0)
                elif "matches" in ev and ev["matches"]:
                    m = ev["matches"][0]
                    dst_ip = m.get("ip", dst_ip)

                save_incident(
                    session_id=task_id,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    port=port,
                    triggered_engine=f"{eng.name} ({sub.name})",
                    risk_score=sub.risk_score,
                    severity=sev,
                    classification=decision_report.final_classification.value,
                    description=sub.explanation,
                    evidence=sub.evidence,
                )

    # Persist extracted network topology for this session
    try:
        build_and_save_session_topology(task_id, pcap_path)
    except Exception as e:
        logger.error("Failed to build topology for session %s: %s", task_id, e)
