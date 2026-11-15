"""
IRONCLAD SQLite Persistence Layer.

Provides relational schema management, WAL mode concurrency, seed indicators,
and atomic database transactions for analysis sessions, engine results,
incidents, simulated containment, and audit logging.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
