"""IPv4 packet parser."""

import logging
from typing import Optional, Dict

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)


class IPv4Parser:
    @staticmethod
    def parse(packet) -> Optional[Dict]:
        if not scapy or scapy.IP not in packet:
            return None
        
        try:
            ip = packet[scapy.IP]
            return {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "protocol": ip.proto,
                "flags": ip.flags,
                "ihl": ip.ihl,
                "length": ip.len,
            }
        except Exception as e:
            logger.debug(f"Error parsing IPv4: {e}")
            return None
