"""
Unit tests for IRONCLAD Multi-Client Traffic Generation and Simulation Scenarios.
"""

import os
import tempfile
import pytest
from scapy.all import rdpcap, IP
from ironclad.testing.multi_client_generator import (
    SimulationScenario,
    generate_scenario_a_normal,
    generate_scenario_b_rate_surge,
    generate_scenario_c_data_loss,
    generate_scenario_d_compound,
)


class TestMultiClientGenerator:
    """Verify multi-laptop traffic generator topologies and scenario specifications."""

    def test_scenario_a_normal_traffic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "scenario_a.pcap")
            meta = generate_scenario_a_normal(out_pcap, packet_count_per_client=30)

            assert os.path.exists(out_pcap)
            assert meta["scenario"] == SimulationScenario.SCENARIO_A_NORMAL.value
            assert meta["total_packets"] > 0
            assert meta["primary_receiver"] == "192.168.1.10"
            assert "192.168.1.51" in meta["clients"]

            # Read back pcap
            pkts = rdpcap(out_pcap)
            assert len(pkts) == meta["total_packets"]
            dst_ips = {p[IP].dst for p in pkts if IP in p}
            src_ips = {p[IP].src for p in pkts if IP in p}
            assert "192.168.1.10" in dst_ips
            assert "192.168.1.51" in src_ips

    def test_scenario_b_rate_surge(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "scenario_b.pcap")
            meta = generate_scenario_b_rate_surge(out_pcap, normal_packets=10, surge_packets=50)

            assert os.path.exists(out_pcap)
            assert meta["scenario"] == SimulationScenario.SCENARIO_B_RATE_SURGE.value
            assert meta["surging_host"] == "192.168.1.53"
            assert meta["total_packets"] > 50

    def test_scenario_c_controlled_packet_loss(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "scenario_c.pcap")
            # Drop 20%
            meta = generate_scenario_c_data_loss(out_pcap, total_expected_packets=100, drop_percentage=20.0)

            assert os.path.exists(out_pcap)
            assert meta["scenario"] == SimulationScenario.SCENARIO_C_DATA_LOSS.value
            assert meta["loss_target_client"] == "192.168.1.53"
            assert meta["expected_loss_percentage"] == 20.0
            assert meta["packets_dropped"] == 20
            assert meta["actual_received"] < meta["total_expected"]

    def test_scenario_d_compound_anomalies(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_pcap = os.path.join(tmpdir, "scenario_d.pcap")
            meta = generate_scenario_d_compound(out_pcap)

            assert os.path.exists(out_pcap)
            assert meta["scenario"] == SimulationScenario.SCENARIO_D_COMPOUND.value
            assert len(meta["anomalies_present"]) >= 3
