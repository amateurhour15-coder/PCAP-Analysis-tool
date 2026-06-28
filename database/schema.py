"""Database schema definitions for NetSleuth."""

import sqlite3
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Create data directory if it doesn't exist
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATA_DIR / "netsleuth.db"

# SQL schema
SCHEMA = """
-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    vendor_name TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    device_type TEXT DEFAULT 'unknown'
);

-- Device IP addresses
CREATE TABLE IF NOT EXISTS device_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    version INTEGER,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    UNIQUE(device_id, ip_address)
);

-- ARP cache
CREATE TABLE IF NOT EXISTS arp_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (mac_address) REFERENCES devices(mac_address)
);

-- Packets (basic logging)
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    packet_size INTEGER,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (src_mac) REFERENCES devices(mac_address),
    FOREIGN KEY (dst_mac) REFERENCES devices(mac_address)
);

-- DNS lookups
CREATE TABLE IF NOT EXISTS dns_lookups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    query_name TEXT,
    query_type TEXT,
    response_ip TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_device_ips_device_id ON device_ips(device_id);
CREATE INDEX IF NOT EXISTS idx_device_ips_ip ON device_ips(ip_address);
CREATE INDEX IF NOT EXISTS idx_arp_cache_mac ON arp_cache(mac_address);
CREATE INDEX IF NOT EXISTS idx_arp_cache_ip ON arp_cache(ip_address);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src_mac ON packets(src_mac);
CREATE INDEX IF NOT EXISTS idx_packets_dst_mac ON packets(dst_mac);
CREATE INDEX IF NOT EXISTS idx_dns_lookups_device ON dns_lookups(device_id);
"""


def init_database(db_path: Path = DATABASE_PATH) -> None:
    """Initialize the SQLite database.
    
    Args:
        db_path: Path to database file
    """
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.executescript(SCHEMA)
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {db_path}")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
