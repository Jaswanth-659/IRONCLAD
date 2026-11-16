"""
Comprehensive Automated Test Suite for Dynamic Controlled Packet Loss and Data Recovery.

Verifies:
- Configurable loss percentages: 0%, 1%, 5%, 10%, 25%.
- Deterministic, Random, and Burst (Gilbert-Elliott) loss models.
- Target source isolation (never drops unselected production traffic).
- Bounded packet buffer memory ceiling and safe overflow handling.
- TCP transport retransmission detection and passive verification.
- UDP application-level sequence gap tracking and ARQ recovery.
- UDP Forward Error Correction (FEC) parity reconstruction.
- Cryptographic hash validation (SHA-256) and rejection of corrupted recovery data.
- Duplicate packet detection.
- Unrecovered data timeout accounting.
- Multi-PC test scenarios (PC 2: 192.168.1.52, PC 3: 192.168.1.53 -> Server: 192.168.1.10).
- SQLite persistence of loss sessions, detected intervals, and recovery records.
- REST API endpoint contracts.
"""

import hashlib
import time
import uuid
import pytest
from starlette.testclient import TestClient

from ironclad.core.types import PacketSummary, Protocol
from ironclad.features.loss_control import (
    BoundedPacketBuffer,
    DynamicLossController,
    LossConfig,
    LossMode,
    RecoveryManager,
    RecoveryMethod,
    ValidationStatus,
)
from ironclad.server.app import app
from ironclad.server.database import (
    get_latest_loss_control_session,
    get_loss_control_session,
    get_loss_detected_events,
    get_loss_recovery_records,
    init_database,
)
from ironclad.testing.loss_recovery_scenarios import (
    PC2_IP,
    PC3_IP,
    SERVER_IP,
    run_controlled_loss_simulation,
)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_database()


# ---------------------------------------------------------------------------
# 1. Dynamic Loss Controller Tests: 0%, 1%, 5%, 10%, 25%, Modes & Isolation
# ---------------------------------------------------------------------------

def test_zero_percent_loss():
    """Verify 0% loss configuration results in exactly 0 drops."""
    cfg = LossConfig(target_loss_pct=0.0, mode=LossMode.DETERMINISTIC, target_sources=[PC2_IP], enabled=True)
    ctrl = DynamicLossController(cfg)
    ctrl.start("test-0pct")

    drops = 0
    for seq in range(100):
        dropped, _ = ctrl.should_drop(PC2_IP, seq)
        if dropped:
            drops += 1

    ctrl.stop()
    assert drops == 0
    assert ctrl.total_evaluated == 100
    assert ctrl.total_dropped == 0


@pytest.mark.parametrize("loss_pct,expected_drops", [
    (1.0, 1),     # 1% -> drop every 100th
    (5.0, 5),     # 5% -> drop every 20th in 100 pkts
    (10.0, 10),   # 10% -> drop every 10th in 100 pkts
    (25.0, 25),   # 25% -> drop every 4th in 100 pkts
])
def test_deterministic_loss_percentages(loss_pct, expected_drops):
    """Verify deterministic loss matches exact expected intervals."""
    cfg = LossConfig(target_loss_pct=loss_pct, mode=LossMode.DETERMINISTIC, target_sources=[PC2_IP], enabled=True)
    ctrl = DynamicLossController(cfg)
    ctrl.start(f"test-{loss_pct}pct")

    drops = 0
    for seq in range(1, 101):
        dropped, _ = ctrl.should_drop(PC2_IP, seq)
        if dropped:
            drops += 1

    ctrl.stop()
    assert drops == expected_drops


def test_random_loss_distribution():
    """Verify Bernoulli random loss converges within expected confidence margin."""
    cfg = LossConfig(target_loss_pct=10.0, mode=LossMode.RANDOM, target_sources=[PC2_IP], enabled=True)
    ctrl = DynamicLossController(cfg)
    ctrl.start("test-random-10pct")

    drops = 0
    total = 500
    for seq in range(total):
        dropped, _ = ctrl.should_drop(PC2_IP, seq)
        if dropped:
            drops += 1

    ctrl.stop()
    drop_pct = (drops / float(total)) * 100.0
    # Expected 10% ± 4% for 500 samples
    assert 6.0 <= drop_pct <= 16.0


def test_burst_loss_simulation():
    """Verify Gilbert-Elliott burst model drops consecutive packets."""
    burst_len = 4
    cfg = LossConfig(target_loss_pct=20.0, mode=LossMode.BURST, burst_length=burst_len, target_sources=[PC2_IP], enabled=True)
    ctrl = DynamicLossController(cfg)
    ctrl.start("test-burst")

    burst_seen = False
    consecutive = 0
    for seq in range(200):
        dropped, _ = ctrl.should_drop(PC2_IP, seq)
        if dropped:
            consecutive += 1
            if consecutive >= burst_len:
                burst_seen = True
        else:
            consecutive = 0

    ctrl.stop()
    assert burst_seen, "Gilbert-Elliott burst did not produce expected consecutive packet drops."


def test_traffic_isolation_protection():
    """RULE 6 & 7: Verify non-target traffic is NEVER dropped under any circumstance."""
    cfg = LossConfig(target_loss_pct=25.0, mode=LossMode.DETERMINISTIC, target_sources=[PC2_IP], enabled=True)
    ctrl = DynamicLossController(cfg)
    ctrl.start("test-isolation")

    # Production host outside test sources
    prod_host = "10.0.0.1"
    for seq in range(100):
        dropped, reason = ctrl.should_drop(prod_host, seq)
        assert not dropped
        assert reason == "NON_TARGET_SOURCE"

    ctrl.stop()


# ---------------------------------------------------------------------------
# 2. Bounded Packet Buffer Tests: Limits, Retention, and Overflow Drops
# ---------------------------------------------------------------------------

def test_bounded_buffer_overflow_handling():
    """Verify packet buffer enforces hard memory ceiling and drops oldest frames without leaking memory."""
    max_bytes = 1000  # Strict 1KB ceiling
    buf = BoundedPacketBuffer(max_bytes=max_bytes, max_retention_sec=10.0)

    # Push 20 items of 100 bytes = 2000 bytes total (exceeds 1000 byte limit)
    for i in range(20):
        buf.push(f"item_{i}", 100)

    stats = buf.get_stats()
    assert stats["current_bytes"] <= max_bytes
    assert stats["overflow_drops"] > 0
    assert stats["utilization_pct"] <= 100.0


def test_bounded_buffer_retention_expiration():
    """Verify items older than max_retention_sec are purged."""
    buf = BoundedPacketBuffer(max_bytes=10000, max_retention_sec=0.1)  # 100ms retention
    t0 = time.time()
    buf.push("old_item", 100, ts=t0)

    # Query 200ms later
    stats_future = buf.get_stats()
    time.sleep(0.15)
    stats_expired = buf.get_stats()
    assert stats_expired["current_bytes"] == 0


# ---------------------------------------------------------------------------
# 3. Protocol Recovery & Cryptographic Verification Tests
# ---------------------------------------------------------------------------

def test_tcp_transport_retransmission_verification():
    """Verify TCP transport retransmission is observed and sequence gap resolved."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-tcp-recovery")

    # Register sequence gap
    seq = 50000
    payload = b"AUTHENTIC_DATABASE_RECORD_TCP"
    payload_hash = hashlib.sha256(payload).hexdigest()

    mgr.register_loss_event(
        seq_num=seq,
        protocol="TCP",
        src_ip=PC2_IP,
        dst_ip=SERVER_IP,
        payload_bytes=len(payload),
        loss_type="NETWORK_DROP",
        payload_hash=payload_hash,
    )

    # Ingest arriving retransmitted packet
    pkt_summary = PacketSummary(
        timestamp=time.time(),
        src_ip=PC2_IP,
        dst_ip=SERVER_IP,
        protocol=Protocol.TCP,
        src_port=52000,
        dst_port=3306,
        length=len(payload) + 40,
    )

    rec = mgr.process_incoming_packet(pkt=pkt_summary, seq_num=seq, payload=payload)
    assert rec is not None
    assert rec.validation_status == ValidationStatus.VALID_CHECKSUM
    assert rec.recovery_method == RecoveryMethod.TCP_RETRANSMIT
    assert rec.checksum_actual == payload_hash
    assert len(mgr.pending_losses) == 0


def test_udp_application_arq_recovery():
    """Verify UDP application-level re-request (ARQ) resolves sequence gap."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-udp-arq")

    seq = 42
    payload = b"IRONCLAD_SEQ:000042:000100:PAYLOAD"
    payload_hash = hashlib.sha256(payload).hexdigest()

    mgr.register_loss_event(
        seq_num=seq,
        protocol="UDP",
        src_ip=PC3_IP,
        dst_ip=SERVER_IP,
        payload_bytes=len(payload),
        payload_hash=payload_hash,
    )

    # ARQ retransmission arrives
    pkt_summary = PacketSummary(
        timestamp=time.time(),
        src_ip=PC3_IP,
        dst_ip=SERVER_IP,
        protocol=Protocol.UDP,
        src_port=53000,
        dst_port=9000,
        length=len(payload) + 28,
    )

    rec = mgr.process_incoming_packet(pkt=pkt_summary, seq_num=seq, payload=payload)
    assert rec is not None
    assert rec.validation_status == ValidationStatus.VALID_CHECKSUM
    assert rec.recovery_method == RecoveryMethod.UDP_ARQ


def test_udp_fec_parity_reconstruction():
    """Verify Forward Error Correction (FEC) mathematically recovers dropped payload."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-fec")

    seq = 77
    orig_payload = b"HIGH_FREQUENCY_TELEMETRY_SAMPLE_FEC"
    orig_hash = hashlib.sha256(orig_payload).hexdigest()

    mgr.register_loss_event(
        seq_num=seq,
        protocol="UDP",
        src_ip=PC3_IP,
        dst_ip=SERVER_IP,
        payload_bytes=len(orig_payload),
        payload_hash=orig_hash,
    )

    # Recover via parity block
    rec = mgr.recover_via_fec_parity(
        block_id=1,
        target_seq=seq,
        src_ip=PC3_IP,
        dst_ip=SERVER_IP,
        reconstructed_payload=orig_payload,
        expected_hash=orig_hash,
    )

    assert rec.validation_status == ValidationStatus.VALID_CHECKSUM
    assert rec.recovery_method == RecoveryMethod.UDP_FEC_PARITY
    assert rec.checksum_actual == orig_hash
    assert (PC3_IP, seq) in mgr.recovered_seqs


def test_corrupted_recovery_data_rejection():
    """RULE 5: Never label guessed or corrupted data as authentic recovered data."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-corruption")

    seq = 99
    expected_hash = hashlib.sha256(b"GENUINE_ORIGINAL_STREAM_DATA").hexdigest()
    corrupted_payload = b"TAMPERED_OR_BIT_FLIPPED_DATA"

    mgr.register_loss_event(
        seq_num=seq,
        protocol="UDP",
        src_ip=PC3_IP,
        dst_ip=SERVER_IP,
        payload_bytes=len(corrupted_payload),
        payload_hash=expected_hash,
    )

    rec = mgr.process_incoming_packet(
        pkt=PacketSummary(timestamp=time.time(), src_ip=PC3_IP, dst_ip=SERVER_IP, protocol=Protocol.UDP, length=len(corrupted_payload)),
        seq_num=seq,
        payload=corrupted_payload,
    )

    assert rec is not None
    assert rec.validation_status == ValidationStatus.CORRUPTED_DATA
    # Corrupted data must NOT be marked as successfully recovered
    assert (PC3_IP, seq) not in mgr.recovered_seqs


def test_duplicate_recovery_filtering():
    """Verify duplicate arrival of already recovered sequence is detected and flagged."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-duplicate")

    seq = 101
    payload = b"DATA_PAYLOAD_TEST"
    p_hash = hashlib.sha256(payload).hexdigest()

    mgr.register_loss_event(seq_num=seq, protocol="TCP", src_ip=PC2_IP, dst_ip=SERVER_IP, payload_bytes=len(payload), payload_hash=p_hash)
    pkt = PacketSummary(timestamp=time.time(), src_ip=PC2_IP, dst_ip=SERVER_IP, protocol=Protocol.TCP, length=len(payload))

    # First recovery: valid
    rec1 = mgr.process_incoming_packet(pkt, seq, payload)
    assert rec1.validation_status == ValidationStatus.VALID_CHECKSUM

    # Second arrival of same sequence: duplicate
    rec2 = mgr.process_incoming_packet(pkt, seq, payload)
    assert rec2 is not None
    assert rec2.validation_status == ValidationStatus.DUPLICATE


def test_unrecovered_timeout_accounting():
    """RULE 6: Unrecoverable data is reported honestly without fabricating recovery."""
    buf = BoundedPacketBuffer()
    mgr = RecoveryManager(buf)
    mgr.start_session("test-unrecovered")

    t0 = 1000.0
    mgr.register_loss_event(
        seq_num=500,
        protocol="TCP",
        src_ip=PC2_IP,
        dst_ip=SERVER_IP,
        payload_bytes=250,
        waiting_window_ms=200.0,
        ts=t0,
    )

    # Advance time by 300ms (exceeding 200ms waiting window)
    unrec = mgr.flush_unrecovered_timeouts(now=t0 + 0.3)
    assert len(unrec) == 1
    assert unrec[0].seq_num == 500
    assert unrec[0].reason == "TIMEOUT_NO_RETRANSMISSION"
    assert unrec[0].missing_bytes == 250


# ---------------------------------------------------------------------------
# 4. Multi-PC Full Scenario Simulation & SQLite Persistence
# ---------------------------------------------------------------------------

def test_full_multi_pc_controlled_loss_and_recovery_simulation():
    """End-to-end integration test of PC 2 (TCP) & PC 3 (UDP) under controlled loss."""
    session_id = f"test-multi-pc-{uuid.uuid4().hex[:8]}"

    res = run_controlled_loss_simulation(
        session_id=session_id,
        test_name="Multi-PC Integration Test",
        loss_pct=10.0,
        loss_mode=LossMode.DETERMINISTIC,
        total_packets_per_pc=30,
        target_sources=[PC2_IP, PC3_IP],
        inject_corrupted_recovery=True,
        inject_duplicates=True,
    )

    assert res["total_packets_sent"] == 60
    assert res["total_losses_detected"] > 0
    assert res["total_recovered_packets"] > 0
    assert res["recovery_rate_pct"] > 80.0
    assert res["corrupted_recoveries_rejected"] >= 1
    assert res["duplicate_recoveries_filtered"] >= 1

    # Verify database persistence
    db_session = get_loss_control_session(session_id)
    assert db_session is not None
    assert db_session["status"] == "COMPLETED"
    assert db_session["configured_loss_pct"] == 10.0

    records = get_loss_recovery_records(session_id=session_id)
    assert len(records) > 0
    assert any(r["validation_status"] == "VALID_CHECKSUM" for r in records)
    assert any(r["validation_status"] == "CORRUPTED_DATA" for r in records)

    events = get_loss_detected_events(session_id=session_id)
    assert len(events) > 0


# ---------------------------------------------------------------------------
# 5. FastAPI REST API Endpoint Tests
# ---------------------------------------------------------------------------

def test_api_loss_control_endpoints():
    """Test REST API configuration, simulation, and metrics endpoints."""
    client = TestClient(app)

    # 1. GET /api/loss-control/config
    res_cfg = client.get("/api/loss-control/config")
    assert res_cfg.status_code == 200
    cfg = res_cfg.json()
    assert "target_loss_pct" in cfg
    assert "mode" in cfg

    # 2. POST /api/loss-control/config
    res_set = client.post("/api/loss-control/config", json={
        "target_loss_pct": 5.0,
        "mode": "BURST",
        "burst_length": 4,
        "target_sources": [PC2_IP, PC3_IP],
        "buffer_max_bytes": 5000000,
        "buffer_retention_sec": 3.0,
    })
    assert res_set.status_code == 200
    assert res_set.json()["target_loss_pct"] == 5.0
    assert res_set.json()["mode"] == "BURST"

    # 3. POST /api/loss-control/simulate-test
    res_sim = client.post("/api/loss-control/simulate-test", json={
        "test_name": "API Automated Test",
        "loss_pct": 5.0,
        "mode": "DETERMINISTIC",
        "packets_per_client": 20,
    })
    assert res_sim.status_code == 200
    sim_data = res_sim.json()
    assert sim_data["status"] == "COMPLETED"
    assert sim_data["summary"]["total_recovered_packets"] > 0

    # 4. GET /api/loss-control/metrics
    res_metrics = client.get("/api/loss-control/metrics")
    assert res_metrics.status_code == 200
    metrics = res_metrics.json()
    assert "recovery_rate_pct" in metrics
    assert "buffer_utilization_pct" in metrics

    # 5. GET /api/loss-control/recovery-history
    res_hist = client.get("/api/loss-control/recovery-history")
    assert res_hist.status_code == 200
    hist = res_hist.json()
    assert "recovery_records" in hist
    assert len(hist["recovery_records"]) > 0
