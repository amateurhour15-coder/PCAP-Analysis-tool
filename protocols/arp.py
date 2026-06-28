"""ARP protocol parser."""

import logging
from typing import Optional, Dict

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)

ARP_OPS = {
    1: "REQUEST",
    2: "REPLY",
    3: "RARP_REQUEST",
    4: "RARP_REPLY",
}


class ARPParser:
    @staticmethod
    def parse(packet) -> Optional[Dict]:
        if not scapy or scapy.ARP not in packet:
            return None
        
        try:
            arp = packet[scapy.ARP]
            return {
                "src_mac": arp.hwsrc,
                "dst_mac": arp.hwdst,
                "src_ip": arp.psrc,
                "dst_ip": arp.pdst,
                "op": ARP_OPS.get(arp.op, str(arp.op)),
                "hw_type": arp.hwtype,
                "proto_type": arp.ptype,
            }
        except Exception as e:
            logger.debug(f"Error parsing ARP: {e}")
            return None
