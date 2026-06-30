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

-- Device identity ledger (Milestone 2)
CREATE TABLE IF NOT EXISTS device_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    identity_type TEXT NOT NULL,
    identity_value TEXT NOT NULL,
    protocol_source TEXT NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    UNIQUE(device_id, identity_type, identity_value, protocol_source)
);

-- DHCP discoveries (Milestone 2)
CREATE TABLE IF NOT EXISTS dhcp_discoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    client_mac TEXT,
    hostname TEXT,
    assigned_ip TEXT,
    vendor_class TEXT,
    parameter_request_list TEXT,
    message_type TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- NetBIOS discoveries (Milestone 2)
CREATE TABLE IF NOT EXISTS netbios_discoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    netbios_name TEXT,
    name_type TEXT,
    workgroup TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- mDNS services (Milestone 2)
CREATE TABLE IF NOT EXISTS mdns_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    service_name TEXT,
    service_type TEXT,
    service_category TEXT,
    txt_records TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- Passive DNS cache (Milestone 3)
CREATE TABLE IF NOT EXISTS passive_dns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    domain_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    ttl INTEGER,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    cname_chain TEXT,
    UNIQUE(ip_address, domain_name, record_type)
);

-- External IP connections (Milestone 3)
CREATE TABLE IF NOT EXISTS external_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    external_ip TEXT NOT NULL,
    external_port INTEGER,
    protocol TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    connection_count INTEGER DEFAULT 1,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(id),
    UNIQUE(device_id, external_ip, external_port, protocol)
);

-- ASN/WHOIS cache (Milestone 3)
CREATE TABLE IF NOT EXISTS asn_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    asn INTEGER,
    as_name TEXT,
    as_country TEXT,
    bgp_prefix TEXT,
    organization TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

-- GeoIP cache (Milestone 3)
CREATE TABLE IF NOT EXISTS geoip_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    country_code TEXT,
    country_name TEXT,
    city TEXT,
    postal_code TEXT,
    latitude REAL,
    longitude REAL,
    continent_code TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL
);

-- Device external intelligence summary (Milestone 3)
CREATE TABLE IF NOT EXISTS device_external_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL UNIQUE,
    unique_external_ips INTEGER DEFAULT 0,
    unique_domains INTEGER DEFAULT 0,
    unique_asns INTEGER DEFAULT 0,
    unique_countries INTEGER DEFAULT 0,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- WiFi Access Points (Milestone 4)
CREATE TABLE IF NOT EXISTS wifi_access_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid TEXT NOT NULL UNIQUE,
    ssid TEXT,
    channel INTEGER,
    frequency REAL,
    rssi INTEGER,
    data_rate REAL,
    encryption_type TEXT,
    cipher_suite TEXT,
    akm_suite TEXT,
    wps_enabled INTEGER DEFAULT 0,
    capabilities TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    beacon_count INTEGER DEFAULT 0
);

-- WiFi Clients (Milestone 4)
CREATE TABLE IF NOT EXISTS wifi_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT NOT NULL UNIQUE,
    device_id INTEGER,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- WiFi Client-AP Associations (Milestone 4)
CREATE TABLE IF NOT EXISTS wifi_associations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    ap_id INTEGER NOT NULL,
    association_type TEXT,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    frame_count INTEGER DEFAULT 0,
    FOREIGN KEY (client_id) REFERENCES wifi_clients(id),
    FOREIGN KEY (ap_id) REFERENCES wifi_access_points(id),
    UNIQUE(client_id, ap_id)
);

-- WiFi Probe Requests (Milestone 4)
CREATE TABLE IF NOT EXISTS wifi_probe_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_mac TEXT NOT NULL,
    ssid TEXT,
    timestamp TIMESTAMP NOT NULL,
    rssi INTEGER,
    FOREIGN KEY (client_mac) REFERENCES wifi_clients(mac_address)
);

-- WiFi Management Frames (Milestone 4)
CREATE TABLE IF NOT EXISTS wifi_management_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    frame_type TEXT NOT NULL,
    frame_subtype TEXT,
    transmitter_mac TEXT,
    receiver_mac TEXT,
    bssid TEXT,
    timestamp TIMESTAMP NOT NULL,
    rssi INTEGER,
    channel INTEGER,
    FOREIGN KEY (transmitter_mac) REFERENCES wifi_clients(mac_address),
    FOREIGN KEY (bssid) REFERENCES wifi_access_points(bssid)
);

-- Device Fingerprints (Milestone 5)
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL UNIQUE,
    manufacturer TEXT,
    device_type TEXT,
    device_model TEXT,
    operating_system TEXT,
    os_version TEXT,
    confidence_score REAL DEFAULT 0.0,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- DHCP Fingerprints (Milestone 5)
CREATE TABLE IF NOT EXISTS dhcp_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parameter_request_list TEXT NOT NULL UNIQUE,
    os_family TEXT,
    os_version TEXT,
    confidence REAL DEFAULT 0.0,
    source TEXT
);

-- MAC OUI Categories (Milestone 5)
CREATE TABLE IF NOT EXISTS mac_oui_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    oui_prefix TEXT NOT NULL UNIQUE,
    vendor TEXT,
    device_category TEXT,
    device_subcategory TEXT
);

-- HTTP User-Agents (Milestone 5)
CREATE TABLE IF NOT EXISTS http_user_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    user_agent TEXT NOT NULL,
    os_family TEXT,
    os_version TEXT,
    browser TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(id)
);

-- mDNS Model Strings (Milestone 5)
CREATE TABLE IF NOT EXISTS mdns_model_strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_string TEXT NOT NULL UNIQUE,
    manufacturer TEXT,
    device_model TEXT,
    device_type TEXT
);

-- TCP/IP Stack Fingerprints (Milestone 5)
CREATE TABLE IF NOT EXISTS tcp_stack_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    ttl INTEGER,
    window_size INTEGER,
    os_family TEXT,
    confidence REAL DEFAULT 0.0,
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
CREATE INDEX IF NOT EXISTS idx_device_identities_device ON device_identities(device_id);
CREATE INDEX IF NOT EXISTS idx_device_identities_value ON device_identities(identity_value);
CREATE INDEX IF NOT EXISTS idx_dhcp_discoveries_mac ON dhcp_discoveries(client_mac);
CREATE INDEX IF NOT EXISTS idx_netbios_discoveries_name ON netbios_discoveries(netbios_name);
CREATE INDEX IF NOT EXISTS idx_mdns_services_name ON mdns_services(service_name);
CREATE INDEX IF NOT EXISTS idx_passive_dns_ip ON passive_dns(ip_address);
CREATE INDEX IF NOT EXISTS idx_passive_dns_domain ON passive_dns(domain_name);
CREATE INDEX IF NOT EXISTS idx_external_connections_device ON external_connections(device_id);
CREATE INDEX IF NOT EXISTS idx_external_connections_ip ON external_connections(external_ip);
CREATE INDEX IF NOT EXISTS idx_asn_cache_ip ON asn_cache(ip_address);
CREATE INDEX IF NOT EXISTS idx_geoip_cache_ip ON geoip_cache(ip_address);
CREATE INDEX IF NOT EXISTS idx_wifi_aps_bssid ON wifi_access_points(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_aps_ssid ON wifi_access_points(ssid);
CREATE INDEX IF NOT EXISTS idx_wifi_clients_mac ON wifi_clients(mac_address);
CREATE INDEX IF NOT EXISTS idx_wifi_associations_client ON wifi_associations(client_id);
CREATE INDEX IF NOT EXISTS idx_wifi_associations_ap ON wifi_associations(ap_id);
CREATE INDEX IF NOT EXISTS idx_wifi_probe_requests_client ON wifi_probe_requests(client_mac);
CREATE INDEX IF NOT EXISTS idx_wifi_mgmt_frames_bssid ON wifi_management_frames(bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_mgmt_frames_tx ON wifi_management_frames(transmitter_mac);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_device ON device_fingerprints(device_id);
CREATE INDEX IF NOT EXISTS idx_dhcp_fingerprints_params ON dhcp_fingerprints(parameter_request_list);
CREATE INDEX IF NOT EXISTS idx_mac_oui_categories_prefix ON mac_oui_categories(oui_prefix);
CREATE INDEX IF NOT EXISTS idx_http_user_agents_device ON http_user_agents(device_id);
CREATE INDEX IF NOT EXISTS idx_mdns_model_strings_service ON mdns_model_strings(service_string);
CREATE INDEX IF NOT EXISTS idx_tcp_stack_fingerprints_device ON tcp_stack_fingerprints(device_id);
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
