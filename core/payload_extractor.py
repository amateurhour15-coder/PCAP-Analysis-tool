"""Extract UDP payloads and detect application-layer protocols."""

import logging
from typing import Optional, TYPE_CHECKING

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

if TYPE_CHECKING:
    from models.packet import PacketMetadata

logger = logging.getLogger(__name__)

DHCP_PORTS = {67, 68}
DNS_PORT = 53
NETBIOS_PORT = 137
MDNS_PORT = 5353


def extract_udp_payload(packet) -> Optional[bytes]:
    """Extract raw UDP payload bytes from a Scapy packet."""
    if not scapy or not packet or scapy.UDP not in packet:
        return None

    payload = bytes(packet[scapy.UDP].payload)
    return payload if payload else None


def _collect_ports(metadata: "PacketMetadata") -> set[int]:
    ports: set[int] = set()
    if metadata.src_port is not None:
        ports.add(metadata.src_port)
    if metadata.dst_port is not None:
        ports.add(metadata.dst_port)
    return ports


def detect_app_protocol(metadata: "PacketMetadata", packet=None) -> Optional[str]:
    """Detect application protocol from UDP/TCP port numbers."""
    ports = _collect_ports(metadata)

    if ports & DHCP_PORTS:
        return "DHCP"
    if MDNS_PORT in ports:
        return "MDNS"
    if DNS_PORT in ports:
        return "DNS"
    if NETBIOS_PORT in ports:
        return "NETBIOS"

    return None
