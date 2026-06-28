"""OUI (Organizationally Unique Identifier) lookup utility."""

import logging
from pathlib import Path
from typing import Optional, Dict

try:
    from mac_vendor_lookup import MacLookup
    HAS_MAC_VENDOR = True
except ImportError:
    HAS_MAC_VENDOR = False

logger = logging.getLogger(__name__)


class OUILookup:
    """Resolve MAC addresses to vendor names."""
    
    def __init__(self):
        """Initialize OUI lookup."""
        self.cache: Dict[str, Optional[str]] = {}
        self.mac_lookup = None
        
        if HAS_MAC_VENDOR:
            try:
                self.mac_lookup = MacLookup()
                logger.info("MAC vendor lookup initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize MAC vendor lookup: {e}")
    
    def lookup(self, mac_address: str) -> Optional[str]:
        """Resolve a MAC address to vendor name.
        
        Args:
            mac_address: MAC address (e.g., "00:11:22:33:44:55")
        
        Returns:
            Vendor name or None if not found
        """
        # Normalize MAC address
        mac = mac_address.upper().replace("-", ":")
        
        # Check cache
        if mac in self.cache:
            return self.cache[mac]
        
        vendor = None
        
        if self.mac_lookup:
            try:
                vendor = self.mac_lookup.lookup(mac)
            except Exception as e:
                logger.debug(f"OUI lookup failed for {mac}: {e}")
        
        # Cache result
        self.cache[mac] = vendor
        return vendor
