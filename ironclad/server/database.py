"""
IRONCLAD SQLite Persistence Layer.

Provides relational schema management, WAL mode concurrency, seed indicators,
and atomic database transactions for analysis sessions, engine results,
incidents, simulated containment, and audit logging.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ironclad.core.ip_validation import validate_ipv4

DB_PATH = Path("data/ironclad.db")

# Thread-local storage for SQLite connections
_local = threading.local()


def get_db_connection() -> sqlite3.Connection:
    """Obtain a thread-safe connection to the SQLite database with WAL enabled."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        _local.conn = conn
    return _local.conn


def init_database() -> None:
    """Create all required tables and populate seed data if not present."""
    conn = get_db_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT UNIQUE NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            status TEXT DEFAULT 'PENDING',
            progress REAL DEFAULT 0.0,
            current_step TEXT DEFAULT 'Initiating',
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            total_flows INTEGER DEFAULT 0,
            unique_hosts INTEGER DEFAULT 0,
            duration_sec REAL DEFAULT 0.0,
            overall_risk_score REAL DEFAULT 0.0,
            final_classification TEXT DEFAULT 'BENIGN',
            executive_summary TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            completed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS engine_evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            engine_id TEXT NOT NULL,
            name TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence_score REAL NOT NULL,
            status TEXT NOT NULL,
            escalation TEXT NOT NULL,
            explanation TEXT,
            evidence_json TEXT,
            execution_time_ms REAL DEFAULT 0.0,
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS subengine_evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            subengine_id TEXT NOT NULL,
            name TEXT NOT NULL,
            parent_engine TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence_score REAL NOT NULL,
            status TEXT NOT NULL,
            explanation TEXT,
            evidence_json TEXT,
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER NOT NULL,
            triggered_engine TEXT NOT NULL,
            risk_score REAL NOT NULL,
            severity TEXT NOT NULL,
            classification TEXT NOT NULL,
            description TEXT,
            evidence_json TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS host_containment (
            ip TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'NORMAL',
            contained_at TEXT,
            released_at TEXT,
            operator TEXT,
            reason TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            operator TEXT NOT NULL,
            action TEXT NOT NULL,
            target_entity TEXT NOT NULL,
            details_json TEXT,
            result TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_intel_indicators (
            indicator TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            source TEXT NOT NULL,
            description TEXT,
            first_seen TEXT,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS topology_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            label TEXT NOT NULL,
            hostname TEXT,
            role TEXT NOT NULL DEFAULT 'HOST',
            node_type TEXT NOT NULL DEFAULT 'HOST',
            is_internal BOOLEAN DEFAULT 1,
            risk_score REAL DEFAULT 0.0,
            classification TEXT DEFAULT 'NORMAL',
            is_suspicious BOOLEAN DEFAULT 0,
            degree INTEGER DEFAULT 0,
            in_degree INTEGER DEFAULT 0,
            out_degree INTEGER DEFAULT 0,
            bytes_sent INTEGER DEFAULT 0,
            bytes_recv INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            packets_sent INTEGER DEFAULT 0,
            packets_recv INTEGER DEFAULT 0,
            total_packets INTEGER DEFAULT 0,
            fan_out_ratio REAL DEFAULT 0.0,
            pagerank REAL DEFAULT 0.0,
            containment_status TEXT DEFAULT 'NORMAL',
            protocols_json TEXT DEFAULT '[]',
            connected_hosts_json TEXT DEFAULT '[]',
            subengine_alerts_json TEXT DEFAULT '[]',
            incident_count INTEGER DEFAULT 0,
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS topology_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            bytes INTEGER DEFAULT 0,
            weight INTEGER DEFAULT 0,
            packets INTEGER DEFAULT 0,
            packet_count INTEGER DEFAULT 0,
            protocol TEXT DEFAULT 'TCP',
            protocols_json TEXT DEFAULT '[]',
            src_ports_json TEXT DEFAULT '[]',
            dst_ports_json TEXT DEFAULT '[]',
            ports_json TEXT DEFAULT '[]',
            is_anomalous BOOLEAN DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            direction TEXT DEFAULT 'outbound',
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_topology_nodes_session ON topology_nodes(session_id);
        CREATE INDEX IF NOT EXISTS idx_topology_links_session ON topology_links(session_id);

        CREATE TABLE IF NOT EXISTS session_data_loss (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            total_expected INTEGER,
            total_received INTEGER NOT NULL,
            total_lost INTEGER,
            loss_percentage REAL,
            volume_expected INTEGER,
            volume_received INTEGER NOT NULL,
            missing_bytes INTEGER DEFAULT 0,
            measurement_status TEXT NOT NULL,
            protocols_json TEXT DEFAULT '{}',
            timeline_json TEXT DEFAULT '[]',
            alerts_json TEXT DEFAULT '[]',
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS dynamic_anomaly_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            category TEXT NOT NULL,
            observed_value REAL NOT NULL,
            expected_baseline REAL NOT NULL,
            current_threshold REAL NOT NULL,
            deviation_percentage REAL NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            explanation TEXT NOT NULL,
            associated_host TEXT NOT NULL,
            timestamp REAL NOT NULL,
            protocol TEXT DEFAULT 'ANY',
            metadata_json TEXT DEFAULT '{}',
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS session_traffic_rates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            duration_seconds REAL DEFAULT 0.0,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            overall_pps REAL DEFAULT 0.0,
            overall_bps REAL DEFAULT 0.0,
            inbound_pps REAL DEFAULT 0.0,
            outbound_pps REAL DEFAULT 0.0,
            inbound_bps REAL DEFAULT 0.0,
            outbound_bps REAL DEFAULT 0.0,
            protocol_rates_json TEXT DEFAULT '{}',
            host_rates_json TEXT DEFAULT '[]',
            rate_timeline_json TEXT DEFAULT '[]',
            FOREIGN KEY (session_id) REFERENCES analysis_sessions(task_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_data_loss_session ON session_data_loss(session_id);
        CREATE INDEX IF NOT EXISTS idx_dynamic_flags_session ON dynamic_anomaly_flags(session_id);
        CREATE INDEX IF NOT EXISTS idx_traffic_rates_session ON session_traffic_rates(session_id);
        """)

        # Seed threat intel indicators if empty
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM threat_intel_indicators")
        if cursor.fetchone()["cnt"] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            seed_intel = [
                ("198.51.100.77", "IP", "C2_SERVER", 98.0, "IRONCLAD Curated Intel", "APT-29 Cobalt Strike Team Server", now_iso, now_iso),
                ("185.220.101.5", "IP", "TOR_EXIT_NODE", 95.0, "Tor Project Directory", "Known Tor Exit Relay Gateway", now_iso, now_iso),
                ("194.26.29.112", "IP", "BOTNET_CONTROLLER", 92.0, "AbuseCH Feed", "Mirai / Mozi IoT Scanning Controller", now_iso, now_iso),
                ("45.154.255.88", "IP", "BULLETPROOF_HOST", 96.0, "CISA Alert ICS-2024", "LockBit Ransomware Staging Infrastructure", now_iso, now_iso),
                ("10.0.0.99", "IP", "INTERNAL_SCANNER", 90.0, "Internal SOC Sensor", "Compromised internal reconnaissance workstation", now_iso, now_iso),
            ]
            conn.executemany(
                "INSERT INTO threat_intel_indicators VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                seed_intel
            )

        # Seed default hosts if empty
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM host_containment")
        if cursor.fetchone()["cnt"] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            seed_hosts = [
                ("192.168.1.50", "NORMAL", None, None, None, None, "Authorized Workstation"),
                ("192.168.1.1", "NORMAL", None, None, None, None, "Local Gateway"),
                ("10.0.0.99", "NORMAL", None, None, None, None, "Staging Host"),
                ("192.168.1.88", "NORMAL", None, None, None, None, "Engineering Server"),
                ("198.51.100.77", "NORMAL", None, None, None, None, "External Endpoint"),
            ]
            conn.executemany(
                "INSERT INTO host_containment VALUES (?, ?, ?, ?, ?, ?, ?)",
                seed_hosts
            )

        # Seed initial audit log
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs")
        if cursor.fetchone()["cnt"] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO audit_logs (timestamp, operator, action, target_entity, details_json, result) VALUES (?, ?, ?, ?, ?, ?)",
                (now_iso, "SYSTEM", "ENGINE_INITIALIZATION", "IRONCLAD_CORE", json.dumps({"version": "1.0.0"}), "SUCCESS")
            )


# Database Operation Helper Functions

def create_session(task_id: str, filename: str, file_size: int) -> None:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT INTO analysis_sessions
               (task_id, filename, file_size, status, progress, current_step, created_at)
               VALUES (?, ?, ?, 'PENDING', 0.0, 'Session Created', ?)""",
            (task_id, filename, file_size, now_iso)
        )


def update_session_progress(task_id: str, progress: float, step: str) -> None:
    conn = get_db_connection()
    with conn:
        conn.execute(
            """UPDATE analysis_sessions
               SET progress = ?, current_step = ?, status = 'PROCESSING'
               WHERE task_id = ?""",
            (progress, step, task_id)
        )


def complete_session(
    task_id: str,
    total_packets: int,
    total_bytes: int,
    total_flows: int,
    unique_hosts: int,
    duration_sec: float,
    overall_risk_score: float,
    final_classification: str,
    executive_summary: str,
) -> None:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """UPDATE analysis_sessions
               SET status = 'COMPLETED', progress = 100.0, current_step = 'Analysis Complete',
                   total_packets = ?, total_bytes = ?, total_flows = ?, unique_hosts = ?,
                   duration_sec = ?, overall_risk_score = ?, final_classification = ?,
                   executive_summary = ?, completed_at = ?
               WHERE task_id = ?""",
            (
                total_packets, total_bytes, total_flows, unique_hosts,
                duration_sec, overall_risk_score, final_classification,
                executive_summary, now_iso, task_id
            )
        )


def save_engine_evaluation(
    session_id: str,
    engine_id: str,
    name: str,
    risk_score: float,
    confidence_score: float,
    status: str,
    escalation: str,
    explanation: str,
    evidence: dict,
    execution_time_ms: float = 0.0,
) -> None:
    conn = get_db_connection()
    with conn:
        conn.execute(
            """INSERT INTO engine_evaluations
               (session_id, engine_id, name, risk_score, confidence_score, status, escalation, explanation, evidence_json, execution_time_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id, engine_id, name, risk_score, confidence_score,
                status, escalation, explanation, json.dumps(evidence), execution_time_ms
            )
        )


def save_subengine_evaluation(
    session_id: str,
    subengine_id: str,
    name: str,
    parent_engine: str,
    risk_score: float,
    confidence_score: float,
    status: str,
    explanation: str,
    evidence: dict,
) -> None:
    conn = get_db_connection()
    with conn:
        conn.execute(
            """INSERT INTO subengine_evaluations
               (session_id, subengine_id, name, parent_engine, risk_score, confidence_score, status, explanation, evidence_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id, subengine_id, name, parent_engine, risk_score,
                confidence_score, status, explanation, json.dumps(evidence)
            )
        )


def save_incident(
    session_id: str,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    port: int,
    triggered_engine: str,
    risk_score: float,
    severity: str,
    classification: str,
    description: str,
    evidence: dict,
) -> None:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT INTO incidents
               (session_id, source_ip, destination_ip, protocol, port, triggered_engine,
                risk_score, severity, classification, description, evidence_json, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id, source_ip, destination_ip, protocol, port, triggered_engine,
                risk_score, severity, classification, description, json.dumps(evidence), now_iso
            )
        )


def record_audit_log(operator: str, action: str, target_entity: str, details: dict, result: str) -> None:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        conn.execute(
            """INSERT INTO audit_logs (timestamp, operator, action, target_entity, details_json, result)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now_iso, operator, action, target_entity, json.dumps(details), result)
        )


def set_host_containment(ip: str, status: str, operator: str, reason: str, notes: str) -> Dict[str, Any]:
    conn = get_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    with conn:
        # Check if host exists
        cur = conn.execute("SELECT ip FROM host_containment WHERE ip = ?", (ip,))
        row = cur.fetchone()

        if status in ("ISOLATED", "QUARANTINED"):
            contained_at = now_iso
            released_at = None
        else:
            contained_at = None
            released_at = now_iso

        if row:
            conn.execute(
                """UPDATE host_containment
                   SET status = ?, contained_at = COALESCE(?, contained_at), released_at = ?,
                       operator = ?, reason = ?, notes = ?
                   WHERE ip = ?""",
                (status, contained_at, released_at, operator, reason, notes, ip)
            )
        else:
            conn.execute(
                """INSERT INTO host_containment (ip, status, contained_at, released_at, operator, reason, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ip, status, contained_at, released_at, operator, reason, notes)
            )

        # Audit log the containment action
        record_audit_log(
            operator=operator,
            action=f"SIMULATED_CONTAINMENT_{status}",
            target_entity=ip,
            details={"status": status, "reason": reason, "notes": notes},
            result="SUCCESS"
        )

    return {
        "ip": ip,
        "status": status,
        "operator": operator,
        "reason": reason,
        "notes": notes,
        "timestamp": now_iso,
    }


def save_session_topology(session_id: str, nodes: List[Dict[str, Any]], links: List[Dict[str, Any]]) -> None:
    """Save or replace topology nodes and links for a specific session."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM topology_nodes WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM topology_links WHERE session_id = ?", (session_id,))

        node_rows = [
            (
                session_id,
                n["ip"],
                n.get("label", n["ip"]),
                n.get("hostname"),
                n.get("role", "HOST"),
                n.get("node_type", n.get("role", "HOST")),
                1 if n.get("is_internal", True) else 0,
                float(n.get("risk_score", 0.0)),
                n.get("classification", "NORMAL"),
                1 if n.get("is_suspicious", False) else 0,
                int(n.get("degree", 0)),
                int(n.get("in_degree", 0)),
                int(n.get("out_degree", 0)),
                int(n.get("bytes_sent", 0)),
                int(n.get("bytes_recv", 0)),
                int(n.get("total_bytes", 0)),
                int(n.get("packets_sent", 0)),
                int(n.get("packets_recv", 0)),
                int(n.get("total_packets", 0)),
                float(n.get("fan_out_ratio", 0.0)),
                float(n.get("pagerank", 0.0)),
                n.get("containment_status", "NORMAL"),
                json.dumps(n.get("protocols", [])),
                json.dumps(n.get("connected_hosts", [])),
                json.dumps(n.get("subengine_alerts", [])),
                int(n.get("incident_count", 0)),
            )
            for n in nodes
        ]
        if node_rows:
            conn.executemany(
                """INSERT INTO topology_nodes
                   (session_id, ip, label, hostname, role, node_type, is_internal,
                    risk_score, classification, is_suspicious, degree, in_degree, out_degree,
                    bytes_sent, bytes_recv, total_bytes, packets_sent, packets_recv, total_packets,
                    fan_out_ratio, pagerank, containment_status, protocols_json,
                    connected_hosts_json, subengine_alerts_json, incident_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                node_rows,
            )

        link_rows = [
            (
                session_id,
                l["source"],
                l["target"],
                int(l.get("bytes", l.get("weight", 0))),
                int(l.get("weight", l.get("bytes", 0))),
                int(l.get("packets", l.get("packet_count", 0))),
                int(l.get("packet_count", l.get("packets", 0))),
                l.get("protocol", "TCP"),
                json.dumps(l.get("protocols", [])),
                json.dumps(l.get("src_ports", [])),
                json.dumps(l.get("dst_ports", [])),
                json.dumps(l.get("ports", [])),
                1 if l.get("is_anomalous", False) else 0,
                float(l.get("risk_score", 0.0)),
                l.get("direction", "outbound"),
            )
            for l in links
        ]
        if link_rows:
            conn.executemany(
                """INSERT INTO topology_links
                   (session_id, source, target, bytes, weight, packets, packet_count,
                    protocol, protocols_json, src_ports_json, dst_ports_json, ports_json,
                    is_anomalous, risk_score, direction)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                link_rows,
            )


def get_session_topology(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve saved topology nodes and links from SQLite for a session."""
    conn = get_db_connection()
    cur_n = conn.execute("SELECT * FROM topology_nodes WHERE session_id = ? ORDER BY id ASC", (session_id,))
    node_rows = cur_n.fetchall()
    if not node_rows:
        return None

    nodes = []
    for r in node_rows:
        nodes.append({
            "id": r["ip"],
            "ip": r["ip"],
            "label": r["label"],
            "hostname": r["hostname"],
            "role": r["role"],
            "node_type": r["node_type"],
            "is_internal": bool(r["is_internal"]),
            "risk_score": r["risk_score"],
            "classification": r["classification"],
            "is_suspicious": bool(r["is_suspicious"]),
            "degree": r["degree"],
            "in_degree": r["in_degree"],
            "out_degree": r["out_degree"],
            "bytes_sent": r["bytes_sent"],
            "bytes_recv": r["bytes_recv"],
            "total_bytes": r["total_bytes"],
            "packets_sent": r["packets_sent"],
            "packets_recv": r["packets_recv"],
            "total_packets": r["total_packets"],
            "fan_out_ratio": r["fan_out_ratio"],
            "pagerank": r["pagerank"],
            "containment_status": r["containment_status"],
            "protocols": json.loads(r["protocols_json"]) if r["protocols_json"] else [],
            "connected_hosts": json.loads(r["connected_hosts_json"]) if r["connected_hosts_json"] else [],
            "subengine_alerts": json.loads(r["subengine_alerts_json"]) if r["subengine_alerts_json"] else [],
            "incident_count": r["incident_count"],
        })

    cur_l = conn.execute("SELECT * FROM topology_links WHERE session_id = ? ORDER BY id ASC", (session_id,))
    links = []
    for r in cur_l.fetchall():
        links.append({
            "source": r["source"],
            "target": r["target"],
            "bytes": r["bytes"],
            "weight": r["weight"],
            "packets": r["packets"],
            "packet_count": r["packet_count"],
            "protocol": r["protocol"],
            "protocols": json.loads(r["protocols_json"]) if r["protocols_json"] else [],
            "src_ports": json.loads(r["src_ports_json"]) if r["src_ports_json"] else [],
            "dst_ports": json.loads(r["dst_ports_json"]) if r["dst_ports_json"] else [],
            "ports": json.loads(r["ports_json"]) if r["ports_json"] else [],
            "is_anomalous": bool(r["is_anomalous"]),
            "risk_score": r["risk_score"],
            "direction": r["direction"],
            "session_id": session_id,
        })

    suspicious_count = sum(1 for n in nodes if n["is_suspicious"])
    critical_count = sum(1 for n in nodes if n["risk_score"] >= 7.0)

    return {
        "session_id": session_id,
        "nodes": nodes,
        "links": links,
        "total_nodes": len(nodes),
        "total_links": len(links),
        "total_hosts": len(nodes),
        "total_connections": len(links),
        "suspicious_hosts": suspicious_count,
        "critical_hosts": critical_count,
    }


def build_and_save_session_topology(session_id: str, pcap_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Extracts real communication graph from PCAP, correlates with detection engines & incidents,
    persists nodes and links into SQLite, and returns TopologyResponse dict.
    """
    conn = get_db_connection()

    # If already built and persisted, return it
    existing = get_session_topology(session_id)
    if existing and existing["total_nodes"] > 0:
        return existing

    # Resolve PCAP file
    resolved_path: Optional[Path] = None
    if pcap_path and Path(pcap_path).exists():
        resolved_path = Path(pcap_path)
    else:
        cur = conn.execute("SELECT filename FROM analysis_sessions WHERE task_id = ?", (session_id,))
        row = cur.fetchone()
        if row:
            fn = row["filename"]
            candidates = [
                Path("data/uploads") / f"{session_id}_{fn}",
                Path("data/uploads") / fn,
                Path("data") / fn,
                Path("ironclad_test_pcaps") / fn,
            ]
            for c in candidates:
                if c.exists():
                    resolved_path = c
                    break

    empty_topo = {
        "session_id": session_id,
        "nodes": [],
        "links": [],
        "total_nodes": 0,
        "total_links": 0,
        "total_hosts": 0,
        "total_connections": 0,
        "suspicious_hosts": 0,
        "critical_hosts": 0,
    }

    if not resolved_path or not resolved_path.exists():
        save_session_topology(session_id, [], [])
        return empty_topo

    from ironclad.ingestion.pcap_reader import PCAPReader
    from ironclad.parsing.dissector import PacketDissector
    from ironclad.graph.topology import NetworkGraphBuilder
    from ironclad.graph.metrics import GraphMetricAnalyzer

    reader = PCAPReader(str(resolved_path))
    dissector = PacketDissector(parse_payload=True)
    builder = NetworkGraphBuilder()

    link_details: Dict[tuple, Dict[str, Any]] = {}
    host_protocols: Dict[str, set] = {}

    for pkt in reader.stream_packets():
        summary = dissector.dissect(pkt)
        if summary and summary.src_ip and summary.dst_ip:
            builder.add_packet(summary)
            src = summary.src_ip
            dst = summary.dst_ip
            host_protocols.setdefault(src, set()).add(summary.protocol_name)
            host_protocols.setdefault(dst, set()).add(summary.protocol_name)

            edge_key = (src, dst)
            if edge_key not in link_details:
                link_details[edge_key] = {
                    "bytes": 0,
                    "packets": 0,
                    "protocols": set(),
                    "src_ports": set(),
                    "dst_ports": set(),
                }
            link_details[edge_key]["bytes"] += summary.length
            link_details[edge_key]["packets"] += 1
            link_details[edge_key]["protocols"].add(summary.protocol_name)
            if summary.src_port:
                link_details[edge_key]["src_ports"].add(summary.src_port)
            if summary.dst_port:
                link_details[edge_key]["dst_ports"].add(summary.dst_port)

    graph = builder.get_graph()
    if graph.number_of_nodes() == 0:
        save_session_topology(session_id, [], [])
        return empty_topo

    analyzer = GraphMetricAnalyzer()
    metrics = analyzer.analyze(graph)

    # Collect incidents for this session
    cur_inc = conn.execute(
        "SELECT source_ip, destination_ip, triggered_engine, risk_score, severity, description FROM incidents WHERE session_id = ?",
        (session_id,)
    )
    inc_rows = cur_inc.fetchall()
    host_incidents: Dict[str, List[Dict[str, Any]]] = {}
    for ir in inc_rows:
        sip = ir["source_ip"]
        dip = ir["destination_ip"]
        item = dict(ir)
        host_incidents.setdefault(sip, []).append(item)
        host_incidents.setdefault(dip, []).append(item)

    # Collect subengine alerts
    cur_sub = conn.execute(
        "SELECT subengine_id, name, risk_score, status, explanation, evidence_json FROM subengine_evaluations WHERE session_id = ?",
        (session_id,)
    )
    subengine_rows = cur_sub.fetchall()
    threat_intel_ips = set()
    scan_ips = set()
    exfil_ips = set()
    subengine_alerts_map: Dict[str, List[str]] = {}

    for sr in subengine_rows:
        seid = sr["subengine_id"]
        ev = json.loads(sr["evidence_json"]) if sr["evidence_json"] else {}
        exp = sr["explanation"] or ""
        rscore = sr["risk_score"]

        if rscore >= 5.0:
            if seid == "E3.4":
                # Threat intelligence
                matches = ev.get("matches", [])
                for m in matches:
                    if isinstance(m, dict) and "ip" in m:
                        threat_intel_ips.add(m["ip"])
                        subengine_alerts_map.setdefault(m["ip"], []).append(f"E3.4 Threat Intel: {exp}")
            elif seid == "E3.2":
                # Port and protocol scanner
                scans = ev.get("vertical_scans", [])
                for s in scans:
                    if isinstance(s, dict) and "scanner" in s:
                        scan_ips.add(s["scanner"])
                        subengine_alerts_map.setdefault(s["scanner"], []).append(f"E3.2 Port Scan: {exp}")
            elif seid == "E2.3":
                # Directional exfiltration
                top_cand = ev.get("top_exfil_candidate")
                if top_cand and isinstance(top_cand, dict) and "source_ip" in top_cand:
                    exfil_ips.add(top_cand["source_ip"])
                    subengine_alerts_map.setdefault(top_cand["source_ip"], []).append(f"E2.3 Exfiltration: {exp}")

    # Query threat intel indicator table
    cur_ti = conn.execute("SELECT indicator FROM threat_intel_indicators")
    for ti in cur_ti.fetchall():
        threat_intel_ips.add(ti["indicator"])

    # Query containment status
    cur_cnt = conn.execute("SELECT ip, status FROM host_containment")
    containment_map = {cr["ip"]: cr["status"] for cr in cur_cnt.fetchall()}

    # Construct nodes
    nodes = []
    nodes_by_ip = {}
    for ip in graph.nodes():
        node_attrs = graph.nodes[ip]
        m = metrics.get(ip)

        val = validate_ipv4(ip)
        if not val.is_valid:
            continue
        ip = val.normalized_ip or ip
        is_internal = val.is_private

        # Determine role & risk score
        risk = 0.8
        role = "CLIENT" if is_internal else "EXTERNAL"
        hostname = None

        if ip in threat_intel_ips:
            role = "C2_DESTINATION"
            risk = 9.8
        elif ip in scan_ips or (m and m.fan_out_ratio >= 5.0 and m.out_degree >= 5):
            role = "SCANNER"
            risk = 8.8
        elif ip in exfil_ips:
            role = "SUSPICIOUS_EXFIL"
            risk = 9.2
        elif ip.endswith(".1") and is_internal:
            role = "GATEWAY"
            risk = 1.0
            hostname = "gateway.local"
        elif not is_internal:
            role = "WEB_SERVER"
            risk = 0.8

        # Correlate with incidents
        incs = host_incidents.get(ip, [])
        if incs:
            max_inc_risk = max(i["risk_score"] for i in incs)
            risk = max(risk, max_inc_risk)

        risk = round(min(10.0, max(0.0, risk)), 1)
        is_suspicious = bool(risk >= 5.0)

        # Risk classification
        if risk >= 7.0:
            classification = "CRITICAL"
        elif risk >= 5.0:
            classification = "SUSPICIOUS"
        elif risk >= 3.0:
            classification = "LOW_RISK"
        else:
            classification = "NORMAL"

        predecessors = list(graph.predecessors(ip))
        successors = list(graph.successors(ip))
        connected_hosts = sorted(list(set(predecessors + successors)))

        b_sent = node_attrs.get("bytes_sent", 0)
        b_recv = node_attrs.get("bytes_recv", 0)
        p_sent = node_attrs.get("packets_sent", 0)
        p_recv = node_attrs.get("packets_recv", 0)

        node_dict = {
            "id": ip,
            "ip": ip,
            "label": hostname or ip,
            "hostname": hostname,
            "role": role,
            "node_type": role,
            "is_internal": is_internal,
            "risk_score": risk,
            "classification": classification,
            "is_suspicious": is_suspicious,
            "degree": graph.degree(ip),
            "in_degree": graph.in_degree(ip),
            "out_degree": graph.out_degree(ip),
            "bytes_sent": b_sent,
            "bytes_recv": b_recv,
            "total_bytes": b_sent + b_recv,
            "packets_sent": p_sent,
            "packets_recv": p_recv,
            "total_packets": p_sent + p_recv,
            "fan_out_ratio": round(m.fan_out_ratio, 4) if m else 0.0,
            "pagerank": round(m.pagerank, 6) if m else 0.0,
            "containment_status": containment_map.get(ip, "NORMAL"),
            "protocols": sorted(list(host_protocols.get(ip, []))),
            "connected_hosts": connected_hosts,
            "subengine_alerts": subengine_alerts_map.get(ip, []),
            "incident_count": len(incs),
        }
        nodes.append(node_dict)
        nodes_by_ip[ip] = node_dict

    # Construct links
    links = []
    for (src, dst), d in link_details.items():
        src_n = nodes_by_ip.get(src, {})
        dst_n = nodes_by_ip.get(dst, {})
        s_risk = src_n.get("risk_score", 0.0)
        d_risk = dst_n.get("risk_score", 0.0)

        protos = sorted(list(d["protocols"]))
        p_name = protos[0] if protos else "TCP"
        s_ports = sorted(list(d["src_ports"]))
        d_ports = sorted(list(d["dst_ports"]))
        all_ports = sorted(list(d["src_ports"].union(d["dst_ports"])))

        is_anom = bool(s_risk >= 5.0 or d_risk >= 5.0 or len(d_ports) > 3)
        edge_risk = max(s_risk, d_risk) if is_anom else min(s_risk, d_risk)
        direction = "outbound" if src_n.get("is_internal", True) else "inbound"

        links.append({
            "source": src,
            "target": dst,
            "bytes": d["bytes"],
            "weight": d["bytes"],
            "packets": d["packets"],
            "packet_count": d["packets"],
            "protocol": p_name,
            "protocols": protos,
            "src_ports": s_ports,
            "dst_ports": d_ports,
            "ports": all_ports,
            "is_anomalous": is_anom,
            "risk_score": edge_risk,
            "direction": direction,
            "session_id": session_id,
        })

    save_session_topology(session_id, nodes, links)
    return get_session_topology(session_id) or empty_topo


def save_session_data_loss(session_id: str, report: Any) -> None:
    """Persist consolidated data loss report for an analysis session."""
    conn = get_db_connection()
    rep_dict = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    with conn:
        conn.execute("DELETE FROM session_data_loss WHERE session_id = ?", (session_id,))
        conn.execute(
            """INSERT INTO session_data_loss
               (session_id, total_expected, total_received, total_lost, loss_percentage,
                volume_expected, volume_received, missing_bytes, measurement_status,
                protocols_json, timeline_json, alerts_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                rep_dict.get("total_packets_expected"),
                rep_dict.get("total_packets_received", 0),
                rep_dict.get("total_packets_lost"),
                rep_dict.get("overall_loss_percentage"),
                rep_dict.get("data_volume_expected_bytes"),
                rep_dict.get("data_volume_received_bytes", 0),
                rep_dict.get("estimated_missing_bytes", 0),
                rep_dict.get("measurement_status", "UNAVAILABLE"),
                json.dumps(rep_dict.get("protocols", {})),
                json.dumps(rep_dict.get("timeline_loss_trend", [])),
                json.dumps(rep_dict.get("data_loss_alerts", [])),
            )
        )


def get_session_data_loss(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve persisted data loss report for a session."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM session_data_loss WHERE session_id = ? ORDER BY id DESC LIMIT 1", (session_id,))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "session_id": session_id,
        "total_packets_expected": row["total_expected"],
        "total_packets_received": row["total_received"],
        "total_packets_lost": row["total_lost"],
        "overall_loss_percentage": row["loss_percentage"],
        "data_volume_expected_bytes": row["volume_expected"],
        "data_volume_received_bytes": row["volume_received"],
        "estimated_missing_bytes": row["missing_bytes"],
        "measurement_status": row["measurement_status"],
        "protocols": json.loads(row["protocols_json"]) if row["protocols_json"] else {},
        "timeline_loss_trend": json.loads(row["timeline_json"]) if row["timeline_json"] else [],
        "data_loss_alerts": json.loads(row["alerts_json"]) if row["alerts_json"] else [],
    }


def save_session_dynamic_flags(session_id: str, flags: List[Any]) -> None:
    """Persist adaptive threshold anomaly flags for a session."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM dynamic_anomaly_flags WHERE session_id = ?", (session_id,))
        rows = []
        for f in flags:
            fd = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            rows.append((
                session_id,
                fd.get("anomaly_category", "UNKNOWN"),
                float(fd.get("observed_value", 0.0)),
                float(fd.get("expected_baseline", 0.0)),
                float(fd.get("current_threshold", 0.0)),
                float(fd.get("deviation_percentage", 0.0)),
                fd.get("severity", "LOW"),
                float(fd.get("confidence", 50.0)),
                fd.get("detection_explanation", ""),
                fd.get("associated_host", "0.0.0.0"),
                float(fd.get("timestamp", 0.0)),
                fd.get("protocol", "ANY"),
                json.dumps(fd.get("metadata", {})),
            ))
        if rows:
            conn.executemany(
                """INSERT INTO dynamic_anomaly_flags
                   (session_id, category, observed_value, expected_baseline, current_threshold,
                    deviation_percentage, severity, confidence, explanation, associated_host,
                    timestamp, protocol, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )


def get_session_dynamic_flags(session_id: str) -> List[Dict[str, Any]]:
    """Retrieve adaptive anomaly flags for a session."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM dynamic_anomaly_flags WHERE session_id = ? ORDER BY id ASC", (session_id,))
    results = []
    for r in cur.fetchall():
        results.append({
            "anomaly_category": r["category"],
            "observed_value": r["observed_value"],
            "expected_baseline": r["expected_baseline"],
            "current_threshold": r["current_threshold"],
            "deviation_percentage": r["deviation_percentage"],
            "severity": r["severity"],
            "confidence": r["confidence"],
            "detection_explanation": r["explanation"],
            "associated_host": r["associated_host"],
            "timestamp": r["timestamp"],
            "protocol": r["protocol"],
            "metadata": json.loads(r["metadata_json"]) if r["metadata_json"] else {},
        })
    return results


def save_session_traffic_rates(session_id: str, report: Any) -> None:
    """Persist traffic rate report for a session."""
    conn = get_db_connection()
    rd = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    with conn:
        conn.execute("DELETE FROM session_traffic_rates WHERE session_id = ?", (session_id,))
        conn.execute(
            """INSERT INTO session_traffic_rates
               (session_id, duration_seconds, total_packets, total_bytes,
                overall_pps, overall_bps, inbound_pps, outbound_pps, inbound_bps, outbound_bps,
                protocol_rates_json, host_rates_json, rate_timeline_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                rd.get("duration_seconds", 0.0),
                rd.get("total_packets", 0),
                rd.get("total_bytes", 0),
                rd.get("overall_pps", 0.0),
                rd.get("overall_bps", 0.0),
                rd.get("inbound_pps", 0.0),
                rd.get("outbound_pps", 0.0),
                rd.get("inbound_bps", 0.0),
                rd.get("outbound_bps", 0.0),
                json.dumps(rd.get("protocol_rates", {})),
                json.dumps(rd.get("host_rates", [])),
                json.dumps(rd.get("rate_timeline", [])),
            )
        )


def get_session_traffic_rates(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve traffic rate telemetry for a session."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM session_traffic_rates WHERE session_id = ? ORDER BY id DESC LIMIT 1", (session_id,))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "session_id": session_id,
        "duration_seconds": row["duration_seconds"],
        "total_packets": row["total_packets"],
        "total_bytes": row["total_bytes"],
        "overall_pps": row["overall_pps"],
        "overall_bps": row["overall_bps"],
        "inbound_pps": row["inbound_pps"],
        "outbound_pps": row["outbound_pps"],
        "inbound_bps": row["inbound_bps"],
        "outbound_bps": row["outbound_bps"],
        "protocol_rates": json.loads(row["protocol_rates_json"]) if row["protocol_rates_json"] else {},
        "host_rates": json.loads(row["host_rates_json"]) if row["host_rates_json"] else [],
        "rate_timeline": json.loads(row["rate_timeline_json"]) if row["rate_timeline_json"] else [],
    }
