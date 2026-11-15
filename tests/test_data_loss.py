"""
Unit tests for IRONCLAD Data-Loss and Transmission Integrity Monitor.
"""

import os
import tempfile
import pytest
from ironclad.core.types import PacketSummary, Protocol
from ironclad.features.data_loss import (
    DataLossMonitor,
    LossMeasurementStatus,
    OverallDataLossReport,
)
from ironclad.ingestion.pcap_reader import PCAPReader
from ironclad.parsing.dissector import PacketDissector
from ironclad.testing.multi_client_generator import generate_scenario_c_packet_loss


class TestDataLossMonitoring:
    """Rigorous verification of packet loss, retransmission, and continuity tracking."""

    def test_untagged_udp_reports_unavailable_status(self):
        """Rule: Never report unavailable measurements as confirmed data loss."""
        monitor = DataLossMonitor()
        pkt = PacketSummary(
            timestamp=100.0,
            length=100,
            protocol=Protocol.UDP,
            protocol_name="UDP",
            src_ip="192.168.1.51",
            dst_ip="192.168.1.10",
            src_port=5000,
            dst_port=5000,
            payload_preview=b"arbitrary_untagged_stream",
        )
        monitor.ingest_packet(pkt)
        report = monitor.generate_report()

        assert report.protocols["UDP"].measurement_status == LossMeasurementStatus.UNAVAILABLE
        assert report.protocols["UDP"].expected_packets is None
        assert report.protocols["UDP"].loss_percentage is None

    def test_tcp_retransmissions_and_gaps(self):
        """Verify TCP inferred loss tracking via duplicate sequence and gaps."""
        monitor = DataLossMonitor()
        from scapy.all import IP, TCP
        pkt1 = IP(src="192.168.1.51", dst="192.168.1.10")/TCP(sport=1000, dport=80, seq=1000, flags="PA")/b"data1"
        sum1 = PacketSummary(
            timestamp=1.0, length=len(pkt1), protocol=Protocol.TCP, protocol_name="TCP",
            src_ip="192.168.1.51", dst_ip="192.168.1.10", src_port=1000, dst_port=80,
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
        )
        monitor.ingest_packet(sum1, raw_scapy_packet=pkt1)

        # Retransmission of seq 1000
        pkt2 = IP(src="192.168.1.51", dst="192.168.1.10")/TCP(sport=1000, dport=80, seq=1000, flags="PA")/b"data1"
        sum2 = PacketSummary(
            timestamp=1.1, length=len(pkt2), protocol=Protocol.TCP, protocol_name="TCP",
            src_ip="192.168.1.51", dst_ip="192.168.1.10", src_port=1000, dst_port=80,
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
        )
        monitor.ingest_packet(sum2, raw_scapy_packet=pkt2)

        report = monitor.generate_report()
        tcp_met = report.protocols["TCP"]
        assert tcp_met.retransmissions == 1
        assert tcp_met.measurement_status == LossMeasurementStatus.INFERRED

    def test_sequence_referenced_udp_loss_detection(self):
        """
        Verify that Scenario C controlled loss with IRONCLAD_SEQ header
        is accurately detected as CONFIRMED packet loss.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            pcap_path = os.path.join(tmpdir, "test_loss.pcap")
            # Drop 30% of 100 packets
            generate_scenario_c_packet_loss(pcap_path, total_expected_packets=100, drop_percentage=30.0)

            reader = PCAPReader(pcap_path)
            dissector = PacketDissector(parse_payload=True)
            monitor = DataLossMonitor()

            idx = 0
            for pkt in reader.stream_packets():
                sum_pkt = dissector.dissect(pkt, index=idx)
                if sum_pkt:
                    monitor.ingest_packet(sum_pkt, raw_scapy_packet=pkt)
                    idx += 1

            report = monitor.generate_report()
            assert report.measurement_status == LossMeasurementStatus.CONFIRMED
            assert report.total_packets_expected is not None
            assert report.total_packets_lost is not None
            assert report.total_packets_lost == 30
            assert report.overall_loss_percentage is not None
            assert 20.0 <= report.overall_loss_percentage <= 40.0
            # Check alert triggered
            assert len(report.data_loss_alerts) > 0
