"""Masking and hashing helpers for API keys and IP addresses.

These helpers guarantee that complete API keys and client IPs never reach
logs, the database or the dashboard.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress


def mask_api_key(api_key: str | None) -> str:
    """Return a display-safe version of an API key.

    Examples:
        >>> mask_api_key("demo-key-001")
        'demo-****-001'
        >>> mask_api_key("sk_live_abcdef123456")
        'sk_l****3456'
    """
    if not api_key:
        return "****"
    key = api_key.strip()
    parts = key.split("-")
    if len(parts) >= 3 and all(parts):
        return f"{parts[0]}-****-{parts[-1]}"
    if len(key) < 8:
        return "****"
    visible = 4 if len(key) >= 12 else 2
    return f"{key[:visible]}****{key[-visible:]}"


def hash_api_key(api_key: str, secret: str) -> str:
    """Keyed HMAC-SHA256 hash of an API key (hex, 64 chars)."""
    return hmac.new(secret.encode("utf-8"), api_key.strip().encode("utf-8"), hashlib.sha256).hexdigest()


def mask_ip(ip: str | None) -> str:
    """Mask the host portion of an IPv4/IPv6 address.

    ``203.0.113.42`` → ``203.0.113.***``; IPv6 keeps only the first 3 hextets.
    """
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv4Address):
        octets = str(addr).split(".")
        return ".".join(octets[:3] + ["***"])
    hextets = addr.exploded.split(":")
    return ":".join(hextets[:3]) + ":****:****:****:****:****"
