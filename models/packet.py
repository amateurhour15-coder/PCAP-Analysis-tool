"""Packet data structures for NetSleuth."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class PacketMetadata:
    """Metadata extracted from a packet."""
    
    timestamp: datetime
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    protocol_version: Optional[int] = None
    packet_size: int = 0
    flags: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = {}
    
    def __str__(self) -> str:
        return f"Packet({self.protocol}, {self.src_mac} -> {self.dst_mac}, {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port})"
