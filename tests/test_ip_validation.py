"""
Unit tests for IRONCLAD IPv4 Regex Validation and Semantic Classification Engine.
"""

import pytest
from ironclad.core.ip_validation import (
    IPV4_STRICT_REGEX,
    IPAddressCategory,
    IPValidationResult,
    classify_ip_address,
    deduplicate_ips,
    filter_valid_ips,
    is_valid_ipv4,
    normalize_ipv4,
    validate_ipv4,
)


class TestIPv4Validation:
    """Test rigorous IPv4 regular expression format & octet bounds validation."""

    def test_valid_ipv4_addresses(self):
        valid_ips = [
            "0.0.0.0",
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "192.168.1.10",
            "192.168.1.51",
            "8.8.8.8",
            "1.1.1.1",
            "255.255.255.255",
            "100.64.0.1",
            "224.0.0.1",
        ]
        for ip in valid_ips:
            res = validate_ipv4(ip)
            assert res.is_valid is True, f"Failed on valid IP: {ip} - {res.error_message}"
            assert res.normalized_ip == ip
            assert is_valid_ipv4(ip) is True

    def test_reject_out_of_range_octets(self):
        invalid_ips = [
            "256.0.0.1",
            "192.168.1.256",
            "300.1.2.3",
            "192.168.999.1",
            "1.2.3.400",
        ]
        for ip in invalid_ips:
            res = validate_ipv4(ip)
            assert res.is_valid is False, f"Did not reject out-of-range IP: {ip}"
            assert is_valid_ipv4(ip) is False

    def test_reject_leading_zeros(self):
        """Prevent octal ambiguity / leading zero security flaws."""
        leading_zeros = [
            "192.168.01.1",
            "010.0.0.1",
            "192.168.1.001",
            "001.002.003.004",
        ]
        for ip in leading_zeros:
            res = validate_ipv4(ip)
            assert res.is_valid is False, f"Did not reject leading zero IP: {ip}"

    def test_reject_malformed_incomplete_ips(self):
        malformed = [
            "192.168.1",
            "192.168.1.",
            ".192.168.1.1",
            "192.168..1",
            "192.168.1.1.1",
            "192.168.1.a",
            "hello_world",
            "",
            "   ",
            "192.168.1.1/24",
            "fe80::1",
            "::1",
            "192.168.1.-5",
        ]
        for ip in malformed:
            res = validate_ipv4(ip)
            assert res.is_valid is False, f"Did not reject malformed string: {ip}"
            assert is_valid_ipv4(ip) is False

    def test_normalize_ipv4_whitespace(self):
        raw = "   192.168.1.50   "
        normalized = normalize_ipv4(raw)
        assert normalized == "192.168.1.50"

        res = validate_ipv4(raw)
        assert res.is_valid is True
        assert res.normalized_ip == "192.168.1.50"

    def test_semantic_classification(self):
        """Verify RFC categories: private, public, loopback, link-local, multicast."""
        assert validate_ipv4("10.10.10.10").category == IPAddressCategory.PRIVATE
        assert validate_ipv4("172.20.0.1").category == IPAddressCategory.PRIVATE
        assert validate_ipv4("192.168.1.10").category == IPAddressCategory.PRIVATE
        assert validate_ipv4("127.0.0.1").category == IPAddressCategory.LOOPBACK
        assert validate_ipv4("169.254.1.1").category == IPAddressCategory.LINK_LOCAL
        assert validate_ipv4("224.0.0.251").category == IPAddressCategory.MULTICAST
        assert validate_ipv4("8.8.8.8").category == IPAddressCategory.PUBLIC
        assert validate_ipv4("1.1.1.1").category == IPAddressCategory.PUBLIC

    def test_private_ips_never_inherently_malicious(self):
        """Rule: RFC-1918 private IPs are normal internal infrastructure."""
        res = validate_ipv4("192.168.1.10")
        assert res.is_valid is True
        assert res.category == IPAddressCategory.PRIVATE
        # Ensure semantic helper functions do not label it external or malicious
        assert classify_ip_address("192.168.1.10") == IPAddressCategory.PRIVATE

    def test_filter_valid_ips(self):
        raw_list = ["192.168.1.1", "bad_ip", "10.0.0.1", "256.0.0.1", "  172.16.0.5  "]
        valid = filter_valid_ips(raw_list)
        assert valid == ["192.168.1.1", "10.0.0.1", "172.16.0.5"]

    def test_deduplicate_ips(self):
        raw_list = [
            "192.168.1.1",
            "10.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "bad_ip",
            "172.16.0.1",
            "192.168.1.1",
        ]
        deduped, dups = deduplicate_ips(raw_list)
        assert deduped == ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        assert len(dups) > 0
