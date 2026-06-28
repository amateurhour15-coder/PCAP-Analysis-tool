"""PCAP/PCAPNG file reader."""

import logging
from pathlib import Path
from typing import Iterator, Optional

try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

logger = logging.getLogger(__name__)


class PCAPReader:
    """Read PCAP and PCAPNG files."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        
        if not self.file_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        
        if not HAS_SCAPY:
            raise RuntimeError("scapy is required to read PCAP files")
        
        logger.info(f"Opened PCAP file: {self.file_path}")
    
    def read(self) -> Iterator:
        """Read packets from PCAP file."""
        try:
            packets = scapy.rdpcap(str(self.file_path))
            logger.info(f"Loaded {len(packets)} packets from {self.file_path.name}")
            for packet in packets:
                yield packet
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            raise
    
    def get_packet_count(self) -> int:
        """Get total packet count in file."""
        try:
            packets = scapy.rdpcap(str(self.file_path))
            return len(packets)
        except Exception as e:
            logger.error(f"Error counting packets: {e}")
            return 0
