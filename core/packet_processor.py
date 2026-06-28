"""Process and analyze packets."""

import logging
from datetime import datetime
from typing import Optional

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

from models.packet import PacketMetadata
from utils.helpers import normalize_mac

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Process packets and extract metadata."""
    
    @staticmethod
    def extract_metadata(packet) -> Optional[PacketMetadata]:
        if not packet or not scapy:
            return None
        
        try:
            metadata = PacketMetadata(
                timestamp=datetime.utcnow(),
                packet_size=len(packet),
            )
            
            if scapy.Ether in packet:
                eth = packet[scapy.Ether]
                metadata.src_mac = normalize_mac(eth.src)
                metadata.dst_mac = normalize_mac(eth.dst)
            
            if scapy.IP in packet:
                ip = packet[scapy.IP]
                metadata.src_ip = ip.src
                metadata.dst_ip = ip.dst
                metadata.protocol = ip.proto
                metadata.protocol_version = 4
            
            elif scapy.IPv6 in packet:
                ip6 = packet[scapy.IPv6]
                metadata.src_ip = ip6.src
                metadata.dst_ip = ip6.dst
                metadata.protocol = ip6.nxt
                metadata.protocol_version = 6
            
            if scapy.TCP in packet:
                tcp = packet[scapy.TCP]
                metadata.src_port = tcp.sport
                metadata.dst_port = tcp.dport
                metadata.flags["tcp_flags"] = tcp.flags
            
            elif scapy.UDP in packet:
                udp = packet[scapy.UDP]
                metadata.src_port = udp.sport
                metadata.dst_port = udp.dport
            
            if scapy.ARP in packet:
                arp = packet[scapy.ARP]
                metadata.src_mac = normalize_mac(arp.hwsrc)
                metadata.dst_mac = normalize_mac(arp.hwdst)
                metadata.src_ip = arp.psrc
                metadata.dst_ip = arp.pdst
                metadata.protocol = "ARP"
                metadata.flags["arp_op"] = arp.op
            
            return metadata
        
        except Exception as e:
            logger.debug(f"Error extracting packet metadata: {e}")
            return None
