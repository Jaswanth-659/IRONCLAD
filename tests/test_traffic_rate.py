"""
Unit tests for IRONCLAD Traffic Rate Analysis and Velocity Engine.
"""

import pytest
from ironclad.core.types import PacketSummary, Protocol
from ironclad.features.traffic_rate import TrafficRateMonitor


class TestTrafficRateMonitor:
    """Test rate calculation, directional transfer, per-host velocity, and hysteresis."""

    def test_overall_pps_and_bps(self):
        monitor = TrafficRateMonitor(monitored_host="192.168.1.10")
        # Ingest 10 packets over 2 seconds
        for i in range(10):
            pkt = PacketSummary(
                timestamp=100.0 + (i * 0.2),  # 0.0 to 1.8s
                length=500,
                protocol=Protocol.TCP,
                protocol_name="TCP",
                src_ip="192.168.1.51",
                dst_ip="192.168.1.10",
                src_port=1000 + i,
                dst_port=80,
            )
            monitor.ingest_packet(pkt)

        report = monitor.generate_report()
        assert report.total_packets == 10
        assert report.total_bytes == 5000
        assert report.overall_pps > 0.0
        assert report.overall_bps > 0.0
        # All packets inbound to 192.168.1.10
        assert report.inbound_pps > 0.0
        assert report.outbound_pps == 0.0

    def test_per_host_velocity_and_directionality(self):
        monitor = TrafficRateMonitor(monitored_host="192.168.1.10")
        # Inbound packet from 192.168.1.51
        monitor.ingest_packet(
            PacketSummary(
                timestamp=1.0, length=200, protocol=Protocol.UDP, protocol_name="UDP",
                src_ip="192.168.1.51", dst_ip="192.168.1.10",
            )
        )
        # Outbound response from 192.168.1.10 to 192.168.1.51
        monitor.ingest_packet(
            PacketSummary(
                timestamp=1.1, length=1000, protocol=Protocol.UDP, protocol_name="UDP",
                src_ip="192.168.1.10", dst_ip="192.168.1.51",
            )
        )

        report = monitor.generate_report()
        host_dict = {h.host_ip: h for h in report.host_rates}

        assert "192.168.1.51" in host_dict
        h51 = host_dict["192.168.1.51"]
        assert h51.packets_out == 1  # 51 sent 1
        assert h51.packets_in == 1   # 51 received 1
        assert h51.bytes_out == 200
        assert h51.bytes_in == 1000

    def test_alert_hysteresis_state(self):
        monitor = TrafficRateMonitor(monitored_host="192.168.1.10")
        assert len(monitor.active_alert_states) == 0
