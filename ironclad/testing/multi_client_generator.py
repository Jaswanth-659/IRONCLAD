"""
IRONCLAD Multi-Client Network Traffic Generator with Controlled Degradation.

Generates repeatable, authentic PCAP test scenarios modeling multi-host environments:
- 1 Primary Receiving Host: 192.168.1.10
- 3 Distinct Client Hosts:
  - Client 1 (Workstation-A): 192.168.1.51 (Web, DNS, API)
  - Client 2 (Workstation-B): 192.168.1.52 (Database sync, periodic bursts)
  - Client 3 (Workstation-C): 192.168.1.53 (Telemetry stream, high volume, or loss-injected)

Scenarios:
- Scenario A: Normal multi-client communication within baseline thresholds.
- Scenario B: Progressive traffic rate increase exceeding dynamic adaptive threshold.
- Scenario C: Controlled packet loss with sequence-tagged metadata for exact loss measurement.
- Scenario D: Compound simultaneous anomalies (high rate surge + packet loss + directional imbalance).
"""

from __future__ import annotations

from enum import Enum
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, wrpcap


class SimulationScenario(str, Enum):
    SCENARIO_A_NORMAL = "A_NORMAL"
    SCENARIO_B_RATE_SURGE = "B_RATE_INCREASE"
    SCENARIO_C_DATA_LOSS = "C_CONTROLLED_PACKET_LOSS"
    SCENARIO_D_COMPOUND = "D_COMPOUND_ANOMALIES"


PRIMARY_RECEIVER_IP = "192.168.1.10"
CLIENT_IPS = {
    "CLIENT_A": "192.168.1.51",  # Laptop 1 (Periodic C2 beaconing)
    "CLIENT_B": "192.168.1.52",  # Laptop 2 (TCP sequence gaps & retransmissions)
    "CLIENT_C": "192.168.1.53",  # Laptop 3 (UDP controlled sequence loss & burst)
    "CLIENT_D": "192.168.1.54",  # Laptop 4 (Port reconnaissance & horizontal sweep)
}


def generate_scenario_a_normal(
    output_path: str, packet_count_per_client: int = 30
) -> Dict[str, Any]:
    """
    Scenario A: Normal baseline multi-client traffic.
    All 3 clients send low-frequency, healthy traffic to the primary receiver.
    """
    packets = []
    base_time = 1700000000.0
    current_time = base_time

    for i in range(packet_count_per_client):
        # Client A: HTTP requests
        pkt_a = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_A"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=50000 + (i % 100), dport=80, flags="PA", seq=1000 + i * 200)
            / Raw(load=f"GET /index.html HTTP/1.1\r\nHost: server\r\n\r\n".encode())
        )
        pkt_a.time = current_time
        packets.append(pkt_a)
        current_time += 0.05

        # Client B: DNS queries and UDP telemetry
        pkt_b = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_B"], dst=PRIMARY_RECEIVER_IP)
            / UDP(sport=53000 + (i % 50), dport=53)
            / Raw(load=f"DNS_QUERY_id_{i}.corp.local".encode())
        )
        pkt_b.time = current_time
        packets.append(pkt_b)
        current_time += 0.05

        # Client C: Routine ICMP / Heartbeats
        pkt_c = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_C"], dst=PRIMARY_RECEIVER_IP)
            / ICMP(type=8, id=1001, seq=i)
            / Raw(load=b"HEARTBEAT_PING_OK")
        )
        pkt_c.time = current_time
        packets.append(pkt_c)
        current_time += 0.05

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    return {
        "scenario": "A_NORMAL",
        "output_path": output_path,
        "total_packets": len(packets),
        "clients": list(CLIENT_IPS.values()),
        "primary_receiver": PRIMARY_RECEIVER_IP,
    }


def generate_scenario_b_rate_increase(
    output_path: str, normal_packets: int = 20, surge_packets: int = 120
) -> Dict[str, Any]:
    """
    Scenario B: Progressive traffic rate surge on Client C exceeding dynamic threshold.
    Client A and B remain normal; Client C transitions from 5 PPS to 150 PPS.
    """
    packets = []
    base_time = 1700000000.0
    current_time = base_time

    # Phase 1: Normal baseline
    for i in range(normal_packets):
        for client_name, client_ip in CLIENT_IPS.items():
            pkt = (
                Ether()
                / IP(src=client_ip, dst=PRIMARY_RECEIVER_IP)
                / TCP(sport=54000 + i, dport=443, flags="PA", seq=5000 + i * 100)
                / Raw(load=b"NORMAL_DATA_STREAM")
            )
            pkt.time = current_time
            packets.append(pkt)
            current_time += 0.04

    # Phase 2: Client C traffic surge
    for j in range(surge_packets):
        # Client C volumetric injection
        pkt_surge = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_C"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=58000 + (j % 20), dport=8080, flags="PA", seq=20000 + j * 500)
            / Raw(load=b"X" * 500)
        )
        pkt_surge.time = current_time
        packets.append(pkt_surge)
        current_time += 0.005  # High frequency 200 PPS

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)
    return {
        "scenario": "B_RATE_INCREASE",
        "output_path": output_path,
        "total_packets": len(packets),
        "surging_host": CLIENT_IPS["CLIENT_C"],
        "normal_hosts": [CLIENT_IPS["CLIENT_A"], CLIENT_IPS["CLIENT_B"]],
    }


def generate_scenario_c_packet_loss(
    output_path: str,
    total_expected_packets: int = 100,
    drop_percentage: float = 25.0,
) -> Dict[str, Any]:
    """
    Scenario C: Controlled packet loss.
    Client C sends sequence-tagged UDP packets (IRONCLAD_SEQ:n:total).
    A known percentage of packets are dropped intentionally to test exact measurement:
    Packet Loss % = ((Expected - Received) / Expected) * 100
    """
    packets = []
    base_time = 1700000000.0
    current_time = base_time

    dropped_indices = set()
    num_to_drop = int(total_expected_packets * (drop_percentage / 100.0))
    # Pick random deterministic drop indices (skip sequence #1 to avoid dropping stream init)
    rng = random.Random(42)
    dropped_indices = set(rng.sample(range(2, total_expected_packets), num_to_drop))

    actual_sent = 0
    for seq_num in range(1, total_expected_packets + 1):
        if seq_num in dropped_indices:
            # Packet is dropped; advance simulated time only
            current_time += 0.02
            continue

        payload = f"IRONCLAD_SEQ:{seq_num:06d}:{total_expected_packets:06d}:TEST_DATA_PAYLOAD".encode()
        pkt = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_C"], dst=PRIMARY_RECEIVER_IP)
            / UDP(sport=51000, dport=9000)
            / Raw(load=payload)
        )
        pkt.time = current_time
        packets.append(pkt)
        actual_sent += 1
        current_time += 0.02

    # Include background control traffic from Client A (no loss)
    for k in range(15):
        bg_pkt = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_A"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=52000 + k, dport=80, flags="PA", seq=1000 + k * 100)
            / Raw(load=b"CONTROL_STREAM_NO_LOSS")
        )
        bg_pkt.time = base_time + k * 0.1
        packets.append(bg_pkt)

    packets.sort(key=lambda p: getattr(p, "time", 0.0))
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)

    measured_loss_pct = ((total_expected_packets - actual_sent) / float(total_expected_packets)) * 100.0

    return {
        "scenario": "C_CONTROLLED_PACKET_LOSS",
        "output_path": output_path,
        "total_expected": total_expected_packets,
        "actual_received": actual_sent,
        "packets_dropped": num_to_drop,
        "expected_loss_percentage": round(measured_loss_pct, 2),
        "loss_target_client": CLIENT_IPS["CLIENT_C"],
    }


def generate_scenario_d_compound_anomalies(
    output_path: str,
) -> Dict[str, Any]:
    """
    Scenario D: Multiple simultaneous attack vectors from >2 client laptops hitting 1 primary receiver.
    Primary Receiver (Target Laptop): 192.168.1.10
    Attacking Laptops:
    - Client 1 / Laptop A (192.168.1.51): Slow steady periodic C2 beaconing (Periodicity Anomaly)
    - Client 2 / Laptop B (192.168.1.52): Degraded TCP stream with sequence gaps and retransmissions (TCP Data Loss Anomaly)
    - Client 3 / Laptop C (192.168.1.53): Volumetric burst with controlled UDP sequence loss (25% dropped tagged packets)
    - Client 4 / Laptop D (192.168.1.54): Rapid port reconnaissance & horizontal scan sweep across management ports
    """
    packets = []
    base_time = 1700000000.0
    current_time = base_time

    # Client A (Laptop 1): Periodic Beaconing with low jitter (Periodicity Anomaly)
    for b in range(15):
        pkt_a = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_A"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=53000, dport=443, flags="PA", seq=1000 + b * 64)
            / Raw(load=b"BEACON_HEARTBEAT_STEADY")
        )
        pkt_a.time = base_time + b * 1.0  # Exactly 1.00s interval (CV -> 0.0)
        packets.append(pkt_a)

    # Client B (Laptop 2): TCP Retransmissions and Sequence Gaps (Data Loss Anomaly)
    for r in range(10):
        # Normal packet
        pkt_b = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_B"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=54000, dport=3306, flags="PA", seq=5000 + r * 100)
            / Raw(load=b"SQL_QUERY_PAYLOAD_CHUNK")
        )
        pkt_b.time = base_time + r * 0.15
        packets.append(pkt_b)

        # Deliberate retransmissions on intervals 3, 5, 7
        if r in (3, 5, 7):
            retrans_pkt = (
                Ether()
                / IP(src=CLIENT_IPS["CLIENT_B"], dst=PRIMARY_RECEIVER_IP)
                / TCP(sport=54000, dport=3306, flags="PA", seq=5000 + r * 100)
                / Raw(load=b"SQL_QUERY_PAYLOAD_CHUNK")
            )
            retrans_pkt.time = base_time + r * 0.15 + 0.05
            packets.append(retrans_pkt)

    # Client C (Laptop 3): Controlled UDP Sequence Loss (25% Drop) + High Rate Burst
    total_c_expected = 60
    c_received = 0
    for c in range(1, total_c_expected + 1):
        if c % 4 == 0:
            # Controlled 25% drop rate: do not transmit packet
            continue
        pkt_c = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_C"], dst=PRIMARY_RECEIVER_IP)
            / UDP(sport=55000, dport=8443)
            / Raw(load=f"IRONCLAD_SEQ:{c:06d}:{total_c_expected:06d}:CONTROLLED_UDP_DATA_LOSS".encode() + b"X" * 200)
        )
        pkt_c.time = base_time + (c * 0.01)  # 100 PPS high-rate burst
        packets.append(pkt_c)
        c_received += 1

    # Client D (Laptop 4): Rapid Port Reconnaissance Sweep against Primary Laptop (Scan Anomaly)
    scan_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]
    for idx, port in enumerate(scan_ports):
        pkt_d = (
            Ether()
            / IP(src=CLIENT_IPS["CLIENT_D"], dst=PRIMARY_RECEIVER_IP)
            / TCP(sport=61000 + idx, dport=port, flags="S", seq=90000 + idx * 1000)
        )
        pkt_d.time = base_time + 0.2 + (idx * 0.04)
        packets.append(pkt_d)

    packets.sort(key=lambda p: getattr(p, "time", 0.0))
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wrpcap(output_path, packets)

    return {
        "scenario": "D_COMPOUND_ANOMALIES",
        "output_path": output_path,
        "total_packets": len(packets),
        "primary_laptop": PRIMARY_RECEIVER_IP,
        "attacking_laptops": list(CLIENT_IPS.values()),
        "controlled_loss_expected": total_c_expected,
        "controlled_loss_received": c_received,
        "controlled_loss_percentage": round(((total_c_expected - c_received) / total_c_expected) * 100.0, 2),
        "anomalies_present": [
            "PERIODICITY_BEACON_CLIENT_A_192.168.1.51",
            "TCP_RETRANSMISSIONS_CLIENT_B_192.168.1.52",
            "UDP_CONTROLLED_25PCT_LOSS_CLIENT_C_192.168.1.53",
            "RATE_SURGE_CLIENT_C_192.168.1.53",
            "PORT_RECONNAISSANCE_CLIENT_D_192.168.1.54",
        ],
    }


# Convenience aliases
generate_scenario_b_rate_surge = generate_scenario_b_rate_increase
generate_scenario_c_data_loss = generate_scenario_c_packet_loss
generate_scenario_d_compound = generate_scenario_d_compound_anomalies
