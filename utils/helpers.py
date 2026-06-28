"""Helper utility functions."""

import re
from typing import Tuple
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address


def mac_to_int(mac: str) -> int:
    """Convert MAC address to integer.
    
    Args:
        mac: MAC address (e.g., "00:11:22:33:44:55")
    
    Returns:
        Integer representation
    """
    mac_int = int(mac.replace(":", "").replace("-", ""), 16)
    return mac_int


def int_to_mac(mac_int: int) -> str:
    """Convert integer to MAC address.
    
    Args:
        mac_int: Integer representation
    
    Returns:
        MAC address string
    """
    return ":".join(f"{(mac_int >> (i << 3)) & 0xff:02x}" for i in reversed(range(6)))


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to colon-separated format.
    
    Args:
        mac: MAC address (various formats)
    
    Returns:
        Normalized MAC address
    """
    # Remove common separators
    mac_clean = re.sub(r"[:-]", "", mac.upper())
    # Validate
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        raise ValueError(f"Invalid MAC address: {mac}")
    # Reformat
    return ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))


def is_private_ip(ip_str: str) -> bool:
    """Check if IP address is private.
    
    Args:
        ip_str: IP address string
    
    Returns:
        True if private, False otherwise
    """
    try:
        ip = ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def format_bytes(num_bytes: int) -> str:
    """Format bytes to human-readable format.
    
    Args:
        num_bytes: Number of bytes
    
    Returns:
        Formatted string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def format_timestamp(dt: datetime) -> str:
    """Format datetime to ISO format.
    
    Args:
        dt: Datetime object
    
    Returns:
        ISO formatted string
    """
    return dt.isoformat()


def is_multicast_mac(mac: str) -> bool:
    """Check if MAC address is multicast.
    
    Args:
        mac: MAC address
    
    Returns:
        True if multicast, False otherwise
    """
    normalized = normalize_mac(mac)
    first_octet = int(normalized.split(":")[0], 16)
    return (first_octet & 0x01) == 1


def is_broadcast_mac(mac: str) -> bool:
    """Check if MAC address is broadcast.
    
    Args:
        mac: MAC address
    
    Returns:
        True if broadcast, False otherwise
    """
    normalized = normalize_mac(mac)
    return normalized == "FF:FF:FF:FF:FF:FF"
