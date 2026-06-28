"""Database manager for NetSleuth."""

import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from database.schema import DATABASE_PATH, init_database

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manage database operations."""
    
    def __init__(self, db_path: Path = DATABASE_PATH):
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = db_path
        if not self.db_path.exists():
            init_database(self.db_path)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection.
        
        Returns:
            SQLite connection
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def add_or_update_device(
        self,
        mac_address: str,
        vendor_name: Optional[str] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
    ) -> int:
        """Add or update a device.
        
        Args:
            mac_address: MAC address
            vendor_name: Vendor/manufacturer name
            first_seen: First seen timestamp
            last_seen: Last seen timestamp
        
        Returns:
            Device ID
        """
        now = datetime.utcnow()
        first_seen = first_seen or now
        last_seen = last_seen or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO devices (mac_address, vendor_name, first_seen, last_seen, packet_count) VALUES (?, ?, ?, ?, 0)",
                (mac_address, vendor_name, first_seen, last_seen),
            )
            device_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                "UPDATE devices SET last_seen = ?, vendor_name = COALESCE(?, vendor_name) WHERE mac_address = ?",
                (last_seen, vendor_name, mac_address),
            )
            cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (mac_address,))
            device_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return device_id
    
    def add_device_ip(
        self,
        device_id: int,
        ip_address: str,
        version: int = 4,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add IP address to device.
        
        Args:
            device_id: Device ID
            ip_address: IP address
            version: IP version (4 or 6)
            timestamp: Timestamp
        
        Returns:
            IP record ID
        """
        timestamp = timestamp or datetime.utcnow()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO device_ips (device_id, ip_address, version, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (device_id, ip_address, version, timestamp, timestamp),
            )
            ip_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                "UPDATE device_ips SET last_seen = ? WHERE device_id = ? AND ip_address = ?",
                (timestamp, device_id, ip_address),
            )
            cursor.execute(
                "SELECT id FROM device_ips WHERE device_id = ? AND ip_address = ?",
                (device_id, ip_address),
            )
            ip_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return ip_id
    
    def get_device_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get device by MAC address.
        
        Args:
            mac_address: MAC address
        
        Returns:
            Device dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get all devices.
        
        Returns:
            List of device dicts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_device_ips(self, device_id: int) -> List[Dict[str, Any]]:
        """Get all IPs for a device.
        
        Args:
            device_id: Device ID
        
        Returns:
            List of IP records
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM device_ips WHERE device_id = ? ORDER BY last_seen DESC",
            (device_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def increment_device_stats(self, mac_address: str, packet_size: int = 0) -> None:
        """Increment device packet/byte counts.
        
        Args:
            mac_address: MAC address
            packet_size: Packet size in bytes
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET packet_count = packet_count + 1, byte_count = byte_count + ? WHERE mac_address = ?",
            (packet_size, mac_address),
        )
        conn.commit()
        conn.close()
