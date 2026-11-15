"""
IRONCLAD IPv4 Validation and Semantic Classification Engine.

Implements a two-tier validation pipeline:
1. Strict Regular Expression syntax & octet range parsing (0-255).
2. Python `ipaddress` semantic verification & address-space categorization:
   - Private (RFC 1918)
   - Public / Global
   - Loopback (RFC 1122)
   - Link-Local (RFC 3927)
   - Multicast (RFC 5771)
   - Reserved / Experimental (RFC 1112 / 6890)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


# Strict IPv4 Regular Expression: exactly four octets each in 0-255 with no leading zeros (unless single '0')
IPV4_STRICT_REGEX = re.compile(
    r"^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
)


class IPAddressCategory(str, Enum):
    """Semantic category of an IPv4 address according to IANA / RFC standards."""
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"
    INVALID = "INVALID"


@dataclass(frozen=True)
class IPValidationResult:
    """Detailed validation and classification metadata for an IP string."""
    raw_ip: str
    normalized_ip: Optional[str]
    is_valid: bool
    category: IPAddressCategory
    is_private: bool
    is_public: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    error_reason: Optional[str] = None


def normalize_ipv4(ip_str: Any) -> Optional[str]:
    """
    Cleanses and standardizes an input string into a canonical dotted-decimal IPv4 address.
    Returns normalized string, or None if input cannot be normalized.
    """
    if ip_str is None:
        return None
    if not isinstance(ip_str, str):
        ip_str = str(ip_str)

    cleaned = ip_str.strip()
    if not cleaned:
        return None

    # Fast regex match before semantic validation
    if not IPV4_STRICT_REGEX.match(cleaned):
        return None

    try:
        addr = ipaddress.IPv4Address(cleaned)
        return str(addr)
    except (ValueError, ipaddress.AddressValueError):
        return None


def validate_ipv4(ip_str: Any) -> IPValidationResult:
    """
    Performs comprehensive two-tier validation on an IPv4 candidate.
    
    1. Regex pattern check for exact dotted-decimal syntax (0-255 per octet).
    2. Semantic parsing via ipaddress.IPv4Address.
    3. Classification into address space categories.
    """
    raw = "" if ip_str is None else str(ip_str).strip()

    if not raw:
        return IPValidationResult(
            raw_ip=raw,
            normalized_ip=None,
            is_valid=False,
            category=IPAddressCategory.INVALID,
            is_private=False,
            is_public=False,
            is_loopback=False,
            is_link_local=False,
            is_multicast=False,
            is_reserved=False,
            error_reason="IP address string is empty or None",
        )

    # Tier 1: Regex syntax validation
    if not IPV4_STRICT_REGEX.match(raw):
        reason = "Does not match dotted-decimal IPv4 syntax (0-255 per octet without malformed characters or leading zeros)"
        return IPValidationResult(
            raw_ip=raw,
            normalized_ip=None,
            is_valid=False,
            category=IPAddressCategory.INVALID,
            is_private=False,
            is_public=False,
            is_loopback=False,
            is_link_local=False,
            is_multicast=False,
            is_reserved=False,
            error_reason=reason,
        )

    # Tier 2: Semantic verification via ipaddress module
    try:
        addr = ipaddress.IPv4Address(raw)
        norm = str(addr)
    except (ValueError, ipaddress.AddressValueError) as err:
        return IPValidationResult(
            raw_ip=raw,
            normalized_ip=None,
            is_valid=False,
            category=IPAddressCategory.INVALID,
            is_private=False,
            is_public=False,
            is_loopback=False,
            is_link_local=False,
            is_multicast=False,
            is_reserved=False,
            error_reason=f"Semantic parsing error: {str(err)}",
        )

    # Classify address space
    # Note: RFC 5737 (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24) are documentation nets.
    # We treat RFC 5737 as external test nets rather than local private.
    is_loopback = addr.is_loopback
    is_link_local = addr.is_link_local
    is_multicast = addr.is_multicast
    is_reserved = addr.is_reserved

    is_doc_net = (
        norm.startswith("198.51.100.")
        or norm.startswith("203.0.113.")
        or norm.startswith("192.0.2.")
    )
    is_private = addr.is_private and not is_doc_net
    is_public = (addr.is_global or is_doc_net) and not (is_private or is_loopback or is_link_local or is_multicast or is_reserved)

    if is_loopback:
        category = IPAddressCategory.LOOPBACK
    elif is_link_local:
        category = IPAddressCategory.LINK_LOCAL
    elif is_multicast:
        category = IPAddressCategory.MULTICAST
    elif is_reserved:
        category = IPAddressCategory.RESERVED
    elif is_private:
        category = IPAddressCategory.PRIVATE
    else:
        category = IPAddressCategory.PUBLIC

    return IPValidationResult(
        raw_ip=raw,
        normalized_ip=norm,
        is_valid=True,
        category=category,
        is_private=is_private,
        is_public=is_public,
        is_loopback=is_loopback,
        is_link_local=is_link_local,
        is_multicast=is_multicast,
        is_reserved=is_reserved,
        error_reason=None,
    )


def is_valid_ipv4(ip_str: Any) -> bool:
    """Convenience helper: returns True if candidate is a strictly valid IPv4 address."""
    if not ip_str:
        return False
    val = validate_ipv4(ip_str)
    return val.is_valid


def classify_ip_address(ip_str: Any) -> IPAddressCategory:
    """Convenience helper: returns the semantic category of an IPv4 candidate."""
    return validate_ipv4(ip_str).category


def filter_valid_ips(ips: Iterable[Any]) -> List[str]:
    """Filters an iterable of candidate IPs, returning only valid, normalized strings."""
    result: List[str] = []
    for item in ips:
        val = validate_ipv4(item)
        if val.is_valid and val.normalized_ip:
            result.append(val.normalized_ip)
    return result


def deduplicate_ips(ips: Iterable[Any]) -> Tuple[List[str], List[str]]:
    """
    Cleanses and deduplicates a sequence of IP strings preserving first appearance order.
    Returns:
      (unique_valid_ips, duplicates_detected)
    """
    seen: Set[str] = set()
    unique: List[str] = []
    duplicates: List[str] = []

    for item in ips:
        val = validate_ipv4(item)
        if not val.is_valid or not val.normalized_ip:
            continue
        norm = val.normalized_ip
        if norm in seen:
            duplicates.append(norm)
        else:
            seen.add(norm)
            unique.append(norm)

    return unique, duplicates
