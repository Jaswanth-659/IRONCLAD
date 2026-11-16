"""
IRONCLAD Controlled Loss and Data Recovery Test Generator.

Simulates multi-PC test traffic (PC 2: 192.168.1.52, PC 3: 192.168.1.53 -> Server: 192.168.1.10)
under configurable controlled loss injection (0%, 1%, 5%, 10%, 25%, random, burst)
and executes protocol-specific recovery (TCP transport retransmission, UDP ARQ, UDP FEC parity).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

from ironclad.core.types import PacketSummary, Protocol
from ironclad.features.loss_control import (
    LossConfig,
    LossMode,
    RecoveryMethod,
    ValidationStatus,
    global_loss_controller,
    global_packet_buffer,
    global_recovery_manager,
)
from ironclad.server.database import (
    complete_loss_control_session,
    create_loss_control_session,
    record_loss_detected_event,
    record_loss_recovery,
    record_loss_unrecovered,
)

SERVER_IP = "192.168.1.10"
PC2_IP = "192.168.1.52"  # TCP Database / Transaction Stream
PC3_IP = "192.168.1.53"  # UDP Sequence & FEC Stream


def run_controlled_loss_simulation(
    session_id: str,
    test_name: str = "Multi-PC Controlled Loss & Recovery Test",
    loss_pct: float = 10.0,
    loss_mode: LossMode = LossMode.DETERMINISTIC,
    burst_length: int = 3,
    total_packets_per_pc: int = 50,
    target_sources: Optional[List[str]] = None,
    inject_corrupted_recovery: bool = True,
    inject_duplicates: bool = True,
    inject_out_of_order: bool = True,
) -> Dict[str, Any]:
    """
    Executes a complete isolated controlled test session with PC 2 and PC 3:
    1. Sets up Dynamic Loss Controller with exact loss percentage and mode.
    2. Transmits sequence-tagged packets from PC 2 (TCP) and PC 3 (UDP).
    3. Drops packets according to the controlled loss model.
    4. Detects missing sequences.
    5. Performs verified recovery:
       - TCP: retransmission of sequence ranges.
       - UDP: ARQ retransmit & FEC parity block reconstruction.
    6. Validates cryptographic hashes (SHA-256) of recovered payloads.
    7. Tests corruption detection (corrupted recovery payloads rejected).
    8. Tests duplicate detection (already-recovered sequences flagged DUPLICATE).
    9. Persists all events and records to SQLite.
    10. Returns comprehensive audit summary.
    """
    targets = target_sources if target_sources is not None else [PC2_IP, PC3_IP]
    cfg = LossConfig(
        target_loss_pct=loss_pct,
        mode=loss_mode,
        burst_length=burst_length,
        target_sources=targets,
        enabled=True,
    )

    # Initialize Controller and Recovery Manager
    global_loss_controller.start(session_id, cfg)
    global_recovery_manager.start_session(session_id)

    # Create session in database
    create_loss_control_session(
        session_id=session_id,
        test_name=test_name,
        configured_loss_pct=loss_pct,
        loss_mode=loss_mode.value,
        burst_length=burst_length,
        target_sources=targets,
    )

    base_time = time.time()
    sim_time = base_time

    # Track missing frames to be recovered
    tcp_dropped_items: List[Dict[str, Any]] = []
    udp_dropped_items: List[Dict[str, Any]] = []

    total_sent = 0
    total_injected_drops = 0

    # -------------------------------------------------------------------------
    # PHASE 1: Primary Stream Transmission with Controlled Loss Injection
    # -------------------------------------------------------------------------
    for i in range(1, total_packets_per_pc + 1):
        sim_time += 0.01

        # 1. PC 2 (TCP Data Stream)
        tcp_payload = f"PC2_TRANSACTION_ID_{i:06d}_PAYLOAD_CHUNK_ALPHA".encode()
        tcp_hash = hashlib.sha256(tcp_payload).hexdigest()
        tcp_seq = 10000 + i * 200
        tcp_len = len(tcp_payload)
        total_sent += 1

        drop_tcp, reason_tcp = global_loss_controller.should_drop(PC2_IP, tcp_seq, tcp_len)
        if drop_tcp:
            total_injected_drops += 1
            evt_tcp = global_recovery_manager.register_loss_event(
                seq_num=tcp_seq,
                protocol="TCP",
                src_ip=PC2_IP,
                dst_ip=SERVER_IP,
                payload_bytes=tcp_len,
                loss_type="NETWORK_DROP",
                payload_hash=tcp_hash,
                ts=sim_time,
            )
            record_loss_detected_event(evt_tcp.to_dict())
            tcp_dropped_items.append({
                "seq": tcp_seq,
                "payload": tcp_payload,
                "hash": tcp_hash,
                "ts": sim_time,
            })
        else:
            # Successfully arrived at server buffer
            pkt_summary = PacketSummary(
                timestamp=sim_time,
                src_ip=PC2_IP,
                dst_ip=SERVER_IP,
                protocol=Protocol.TCP,
                src_port=52000,
                dst_port=3306,
                length=tcp_len + 40,
            )
            global_recovery_manager.process_incoming_packet(
                pkt=pkt_summary,
                seq_num=tcp_seq,
                payload=tcp_payload,
                ts=sim_time,
            )

        # 2. PC 3 (UDP Sequence Stream)
        udp_payload = f"IRONCLAD_SEQ:{i:06d}:{total_packets_per_pc:06d}:{tcp_hash[:16]}:TELEMETRY_SAMPLE".encode()
        udp_hash = hashlib.sha256(udp_payload).hexdigest()
        udp_seq = i
        udp_len = len(udp_payload)
        total_sent += 1

        drop_udp, reason_udp = global_loss_controller.should_drop(PC3_IP, udp_seq, udp_len)
        if drop_udp:
            total_injected_drops += 1
            evt_udp = global_recovery_manager.register_loss_event(
                seq_num=udp_seq,
                protocol="UDP",
                src_ip=PC3_IP,
                dst_ip=SERVER_IP,
                payload_bytes=udp_len,
                loss_type="NETWORK_DROP",
                payload_hash=udp_hash,
                ts=sim_time,
            )
            record_loss_detected_event(evt_udp.to_dict())
            udp_dropped_items.append({
                "seq": udp_seq,
                "payload": udp_payload,
                "hash": udp_hash,
                "ts": sim_time,
            })
        else:
            pkt_summary = PacketSummary(
                timestamp=sim_time,
                src_ip=PC3_IP,
                dst_ip=SERVER_IP,
                protocol=Protocol.UDP,
                src_port=53000,
                dst_port=9000,
                length=udp_len + 28,
            )
            global_recovery_manager.process_incoming_packet(
                pkt=pkt_summary,
                seq_num=udp_seq,
                payload=udp_payload,
                ts=sim_time,
            )

    # -------------------------------------------------------------------------
    # PHASE 2: Protocol Recovery Execution & Cryptographic Verification
    # -------------------------------------------------------------------------
    # Step 2A: TCP Transport Retransmission Recovery (Passive Verification)
    for dropped in tcp_dropped_items:
        sim_time += 0.025  # Retransmission arrives after RTT
        retrans_summary = PacketSummary(
            timestamp=sim_time,
            src_ip=PC2_IP,
            dst_ip=SERVER_IP,
            protocol=Protocol.TCP,
            src_port=52000,
            dst_port=3306,
            length=len(dropped["payload"]) + 40,
        )
        rec_res = global_recovery_manager.process_incoming_packet(
            pkt=retrans_summary,
            seq_num=dropped["seq"],
            payload=dropped["payload"],
            ts=sim_time,
        )
        if rec_res:
            record_loss_recovery(rec_res.to_dict())

    # Step 2B: UDP Application ARQ & FEC Parity Recovery
    for idx, dropped in enumerate(udp_dropped_items):
        sim_time += 0.035
        # 50% recovered via application ARQ retransmit, 50% via FEC parity block
        if idx % 2 == 0:
            # Application ARQ
            arq_summary = PacketSummary(
                timestamp=sim_time,
                src_ip=PC3_IP,
                dst_ip=SERVER_IP,
                protocol=Protocol.UDP,
                src_port=53000,
                dst_port=9000,
                length=len(dropped["payload"]) + 28,
            )
            rec_res = global_recovery_manager.process_incoming_packet(
                pkt=arq_summary,
                seq_num=dropped["seq"],
                payload=dropped["payload"],
                ts=sim_time,
            )
            if rec_res:
                record_loss_recovery(rec_res.to_dict())
        else:
            # FEC Parity Reconstruction
            rec_res = global_recovery_manager.recover_via_fec_parity(
                block_id=idx + 1,
                target_seq=dropped["seq"],
                src_ip=PC3_IP,
                dst_ip=SERVER_IP,
                reconstructed_payload=dropped["payload"],
                expected_hash=dropped["hash"],
                ts=sim_time,
            )
            if rec_res:
                record_loss_recovery(rec_res.to_dict())

    # -------------------------------------------------------------------------
    # PHASE 3: Testing Corruption, Duplicates, and Unrecovered Timeouts
    # -------------------------------------------------------------------------
    if inject_corrupted_recovery:
        # Deliberately attempt recovery with corrupted data (bit-flip)
        corrupt_seq = 99999
        corrupt_payload = b"CORRUPTED_TAMPERED_DATA_PAYLOAD"
        corrupt_expected_hash = hashlib.sha256(b"ORIGINAL_AUTHENTIC_PAYLOAD").hexdigest()
        evt_corrupt = global_recovery_manager.register_loss_event(
            seq_num=corrupt_seq,
            protocol="UDP",
            src_ip=PC3_IP,
            dst_ip=SERVER_IP,
            payload_bytes=len(corrupt_payload),
            payload_hash=corrupt_expected_hash,
            ts=sim_time,
        )
        record_loss_detected_event(evt_corrupt.to_dict())
        rec_corrupt = global_recovery_manager.process_incoming_packet(
            pkt=PacketSummary(timestamp=sim_time, src_ip=PC3_IP, dst_ip=SERVER_IP, protocol=Protocol.UDP, length=len(corrupt_payload)),
            seq_num=corrupt_seq,
            payload=corrupt_payload,
            ts=sim_time + 0.01,
        )
        if rec_corrupt:
            record_loss_recovery(rec_corrupt.to_dict())

    if inject_duplicates:
        candidate_items = tcp_dropped_items or udp_dropped_items
        if candidate_items:
            # Ingest an already recovered packet sequence again (Duplicate test)
            dup_item = candidate_items[0]
            is_tcp = dup_item in tcp_dropped_items
            rec_dup = global_recovery_manager.process_incoming_packet(
                pkt=PacketSummary(
                    timestamp=sim_time + 0.05,
                    src_ip=PC2_IP if is_tcp else PC3_IP,
                    dst_ip=SERVER_IP,
                    protocol=Protocol.TCP if is_tcp else Protocol.UDP,
                    length=len(dup_item["payload"]) + (40 if is_tcp else 28),
                ),
                seq_num=dup_item["seq"],
                payload=dup_item["payload"],
                ts=sim_time + 0.05,
            )
            if rec_dup:
                record_loss_recovery(rec_dup.to_dict())

    # Flush any unrecovered losses (or simulated timeouts)
    unrec_list = global_recovery_manager.flush_unrecovered_timeouts(sim_time + 1.0)
    for un in unrec_list:
        record_loss_unrecovered(un.to_dict())

    # Finalize metrics
    summary = global_recovery_manager.get_summary_metrics()
    summary["total_packets_sent"] = total_sent
    summary["configured_loss_pct"] = loss_pct
    summary["actual_loss_pct"] = round((total_injected_drops / float(total_sent)) * 100.0, 2) if total_sent > 0 else 0.0
    summary["loss_mode"] = loss_mode.value
    summary["target_sources"] = targets

    complete_loss_control_session(session_id, summary)
    global_loss_controller.stop()

    return summary


def generate_controlled_loss_pcap(
    output_path: str,
    loss_pct: float = 10.0,
    packets_per_client: int = 40,
) -> Dict[str, Any]:
    """
    Generates an authentic PCAP file with controlled loss and retransmissions.
    """
    packets = []
    base_time = 1700000000.0
    current_time = base_time

    # PC 2: TCP Stream
    for i in range(1, packets_per_client + 1):
        seq = 20000 + i * 150
        payload = f"PC2_DB_SYNC_RECORD_{i:04d}".encode()
        # Controlled loss: drop every 10th packet
        if loss_pct > 0 and (i % max(1, int(100 / loss_pct))) == 0:
            current_time += 0.02
            # Retransmission arrives later
            retrans_pkt = (
                Ether()
                / IP(src=PC2_IP, dst=SERVER_IP)
                / TCP(sport=52000, dport=3306, flags="PA", seq=seq)
                / Raw(load=payload)
            )
            retrans_pkt.time = current_time + 0.08
            packets.append(retrans_pkt)
            continue

        pkt = (
            Ether()
            / IP(src=PC2_IP, dst=SERVER_IP)
            / TCP(sport=52000, dport=3306, flags="PA", seq=seq)
            / Raw(load=payload)
        )
        pkt.time = current_time
        packets.append(pkt)
        current_time += 0.02

    # PC 3: UDP Sequence & FEC Stream
    for j in range(1, packets_per_client + 1):
        payload = f"IRONCLAD_SEQ:{j:06d}:{packets_per_client:06d}:TEST_TELEMETRY".encode()
        if loss_pct > 0 and (j % max(1, int(100 / loss_pct))) == 0:
            current_time += 0.02
            # FEC parity recovery packet
            fec_payload = f"IRONCLAD_FEC:BLOCK_01:{j:06d}:RECOVERED_TELEMETRY".encode()
            fec_pkt = (
                Ether()
                / IP(src=PC3_IP, dst=SERVER_IP)
                / UDP(sport=53000, dport=9000)
                / Raw(load=fec_payload)
            )
            fec_pkt.time = current_time + 0.06
            packets.append(fec_pkt)
            continue

        pkt_udp = (
            Ether()
            / IP(src=PC3_IP, dst=SERVER_IP)
            / UDP(sport=53000, dport=9000)
            / Raw(load=payload)
        )
        pkt_udp.time = current_time
        packets.append(pkt_udp)
        current_time += 0.02

    packets.sort(key=lambda p: getattr(p, "time", 0.0))
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)

    return {
        "output_path": output_path,
        "total_packets": len(packets),
        "loss_pct": loss_pct,
        "clients": [PC2_IP, PC3_IP],
    }
