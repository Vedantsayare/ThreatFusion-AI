"""
normalization/net.py — Shared IP classification helpers.

"External" means globally routable OR inside the RFC 5737 documentation
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those ranges are
reserved for examples and never used as internal address space, so synthetic
scenarios and tests use them as stand-ins for public internet hosts.
Python's ``ipaddress.is_global`` returns False for them, hence this helper.
"""

from __future__ import annotations

import ipaddress

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def is_external_ip(value: str) -> bool:
    """True for globally routable or RFC 5737 documentation addresses."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if ip.is_global:
        return True
    return any(ip in net for net in DOCUMENTATION_NETWORKS if ip.version == net.version)
