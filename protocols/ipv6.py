"""IPv6 packet parser."""

import logging
from typing import Optional, Dict

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)


class IPv6Parser:
    @staticmethod
    def parse(packet) -> Optional[Dict]:
        if not scapy or scapy.IPv6 not in packet:
            return None
        
        try:
            ip6 = packet[scapy.IPv6]
            return {
                "src_ip": ip6.src,
                "dst_ip": ip6.dst,
                "hop_limit": ip6.hlim,
                "flow_label": ip6.fl,
                "next_header": ip6.nxt,
                "traffic_class": ip6.tc,
            }
        except Exception as e:
            logger.debug(f"Error parsing IPv6: {e}")
            return None
