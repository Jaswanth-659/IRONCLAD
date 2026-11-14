"""
IRONCLAD Network Protocol Definitions and Utilities.

Defines protocol mappings, well-known port mappings, and bitwise TCP flag parsers.
"""

from __future__ import annotations

from typing import Any, Dict

from ironclad.core.types import Protocol

# Well-known service port mappings
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "KERBEROS",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    587: "SMTP-SUBMISSION",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "ELASTICSEARCH",
    27017: "MONGODB",
}

# TCP Flag Bitmasks (RFC 793 / RFC 3168)
TCP_FLAG_MASKS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
    "ECE": 0x40,
    "CWR": 0x80,
}


def parse_tcp_flags(flags_val: Any) -> Dict[str, bool]:
    """
    Robustly dissect TCP flags from Scapy FlagValue, int, or string representation.

    Args:
        flags_val: Flag representation (int, FlagValue, or string like 'S', 'SA', 'PA', etc.)

    Returns:
        Dictionary mapping flag names (SYN, ACK, FIN, RST, PSH, URG) to booleans.
    """
    flags_dict = {
        "SYN": False,
        "ACK": False,
        "FIN": False,
        "RST": False,
        "PSH": False,
        "URG": False,
    }

    if flags_val is None:
        return flags_dict

    # If flags_val is integer or convertible to int (e.g. Scapy FlagValue)
    try:
        flags_int = int(flags_val)
        for name, mask in TCP_FLAG_MASKS.items():
            if name in flags_dict:
                flags_dict[name] = bool(flags_int & mask)
        return flags_dict
    except (ValueError, TypeError):
        pass

    # If string representation (e.g. 'SA', 'FA', 'PA')
    str_val = str(flags_val).upper()
    char_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }
    for char, name in char_map.items():
        if char in str_val:
            flags_dict[name] = True

    return flags_dict


def get_service_name(port: int, default: str = "UNKNOWN") -> str:
    """Resolve well-known service name from port number."""
    return WELL_KNOWN_PORTS.get(port, default)
