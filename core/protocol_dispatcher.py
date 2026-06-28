"""Protocol packet dispatcher."""

import logging
from typing import Callable, Dict, Optional

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)


class ProtocolDispatcher:
    """Route packets to appropriate protocol handlers."""
    
    def __init__(self):
        self.handlers: Dict[str, Callable] = {}
        self._register_default_handlers()
    
    def register_handler(self, protocol: str, handler: Callable) -> None:
        self.handlers[protocol] = handler
        logger.debug(f"Registered handler for {protocol}")
    
    def _register_default_handlers(self) -> None:
        if scapy:
            pass
    
    def dispatch(self, packet) -> Optional[Dict]:
        if not packet:
            return None
        
        extracted_data = {}
        
        for protocol, handler in self.handlers.items():
            try:
                if scapy and hasattr(packet, protocol):
                    layer = packet[protocol]
                    data = handler(layer)
                    if data:
                        extracted_data.update(data)
            except Exception as e:
                logger.debug(f"Error dispatching to {protocol}: {e}")
        
        return extracted_data if extracted_data else None
