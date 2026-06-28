"""Ethernet frame parser."""

import logging
from typing import Optional, Dict

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)


class EthernetParser:
    @staticmethod
    def parse(packet) -> Optional[Dict]:
        if not scapy or scapy.Ether not in packet:
            return None
        
        try:
            eth = packet[scapy.Ether]
            return {
                "src_mac": eth.src,
                "dst_mac": eth.dst,
                "eth_type": eth.type,
            }
        except Exception as e:
            logger.debug(f"Error parsing Ethernet: {e}")
            return None
