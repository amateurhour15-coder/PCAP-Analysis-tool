"""Device model for NetSleuth."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set
from enum import Enum


class DeviceType(Enum):
    """Device type classifications."""
    UNKNOWN = "unknown"
    COMPUTER = "computer"
    MOBILE = "mobile"
    PRINTER = "printer"
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    IOT = "iot"
    CAMERA = "camera"
    SPEAKER = "speaker"
    TV = "tv"
    GAMING_CONSOLE = "gaming_console"
    SERVER = "server"


@dataclass
class Device:
    """Represents a network device."""
    
    mac_address: str
    vendor_name: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    packet_count: int = 0
    byte_count: int = 0
    device_type: DeviceType = DeviceType.UNKNOWN
    hostnames: Set[str] = field(default_factory=set)
    ip_addresses: Set[str] = field(default_factory=set)
    is_gateway: bool = False
    is_access_point: bool = False
    is_wireless: bool = False
    is_multicast: bool = False
    is_broadcast: bool = False
    
    def __post_init__(self):
        """Validate device data."""
        if not self.mac_address:
            raise ValueError("MAC address is required")
    
    def add_ip(self, ip_address: str) -> None:
        """Add IP address to device."""
        self.ip_addresses.add(ip_address)
    
    def add_hostname(self, hostname: str) -> None:
        """Add hostname to device."""
        if hostname:
            self.hostnames.add(hostname)
    
    def update_last_seen(self) -> None:
        """Update last seen timestamp."""
        self.last_seen = datetime.utcnow()
    
    def __str__(self) -> str:
        return f"Device({self.mac_address}, {self.vendor_name})"
    
    def __repr__(self) -> str:
        return f"Device(mac={self.mac_address}, vendor={self.vendor_name}, ips={len(self.ip_addresses)}, packets={self.packet_count})"
