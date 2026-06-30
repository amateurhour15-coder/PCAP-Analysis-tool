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
        else:
            # Check if tables exist, if not initialize
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices'")
            if not cursor.fetchone():
                conn.close()
                init_database(self.db_path)
            else:
                conn.close()
    
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
    
    def get_device_by_id(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get device by ID.
        
        Args:
            device_id: Device ID
        
        Returns:
            Device dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_device_id_by_mac(self, mac_address: str) -> Optional[int]:
        """Get device ID by MAC address.
        
        Args:
            mac_address: MAC address
        
        Returns:
            Device ID or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM devices WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    
    def add_dhcp_discovery(
        self,
        device_id: int,
        client_mac: str,
        hostname: Optional[str] = None,
        assigned_ip: Optional[str] = None,
        vendor_class: Optional[str] = None,
        parameter_request_list: Optional[List[int]] = None,
        message_type: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add DHCP discovery record.
        
        Args:
            device_id: Device ID
            client_mac: Client MAC address
            hostname: DHCP hostname
            assigned_ip: Assigned IP address
            vendor_class: Vendor class identifier
            parameter_request_list: DHCP Option 55 parameter list
            message_type: DHCP message type
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        timestamp = timestamp or datetime.utcnow()
        param_list_str = ",".join(map(str, parameter_request_list)) if parameter_request_list else None
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO dhcp_discoveries 
               (device_id, client_mac, hostname, assigned_ip, vendor_class, parameter_request_list, message_type, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (device_id, client_mac, hostname, assigned_ip, vendor_class, param_list_str, message_type, timestamp),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def add_netbios_discovery(
        self,
        device_id: int,
        netbios_name: str,
        name_type: Optional[str] = None,
        workgroup: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add NetBIOS discovery record.
        
        Args:
            device_id: Device ID
            netbios_name: NetBIOS name
            name_type: NetBIOS name type
            workgroup: Workgroup name
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        timestamp = timestamp or datetime.utcnow()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO netbios_discoveries 
               (device_id, netbios_name, name_type, workgroup, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (device_id, netbios_name, name_type, workgroup, timestamp),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def add_mdns_service(
        self,
        device_id: int,
        service_name: str,
        service_type: Optional[str] = None,
        service_category: Optional[str] = None,
        txt_records: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add mDNS service record.
        
        Args:
            device_id: Device ID
            service_name: Service name
            service_type: Service type
            service_category: Service category
            txt_records: TXT records
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        timestamp = timestamp or datetime.utcnow()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO mdns_services 
               (device_id, service_name, service_type, service_category, txt_records, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (device_id, service_name, service_type, service_category, txt_records, timestamp),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def add_device_identity(
        self,
        device_id: int,
        identity_type: str,
        identity_value: str,
        protocol_source: str,
        priority: int = 0,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
    ) -> int:
        """Add or update device identity in the identity ledger.
        
        Args:
            device_id: Device ID
            identity_type: Type of identity (hostname, netbios_name, etc.)
            identity_value: The identity value
            protocol_source: Protocol source (DHCP, DNS, NetBIOS, mDNS)
            priority: Priority for conflict resolution (higher = more trusted)
            first_seen: First seen timestamp
            last_seen: Last seen timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        first_seen = first_seen or now
        last_seen = last_seen or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO device_identities 
                   (device_id, identity_type, identity_value, protocol_source, first_seen, last_seen, priority, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (device_id, identity_type, identity_value, protocol_source, first_seen, last_seen, priority),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE device_identities 
                   SET last_seen = ?, priority = MAX(priority, ?), is_active = 1
                   WHERE device_id = ? AND identity_type = ? AND identity_value = ? AND protocol_source = ?""",
                (last_seen, priority, device_id, identity_type, identity_value, protocol_source),
            )
            cursor.execute(
                """SELECT id FROM device_identities 
                   WHERE device_id = ? AND identity_type = ? AND identity_value = ? AND protocol_source = ?""",
                (device_id, identity_type, identity_value, protocol_source),
            )
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def get_device_identities(self, device_id: int) -> List[Dict[str, Any]]:
        """Get all identities for a device.
        
        Args:
            device_id: Device ID
        
        Returns:
            List of identity records
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM device_identities 
               WHERE device_id = ? AND is_active = 1 
               ORDER BY priority DESC, last_seen DESC""",
            (device_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def add_passive_dns(
        self,
        ip_address: str,
        domain_name: str,
        record_type: str,
        ttl: Optional[int] = None,
        cname_chain: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update passive DNS entry.
        
        Args:
            ip_address: IP address
            domain_name: Domain name
            record_type: DNS record type (A, AAAA, CNAME, etc.)
            ttl: Time-to-live value
            cname_chain: CNAME chain if applicable
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO passive_dns 
                   (ip_address, domain_name, record_type, ttl, first_seen, last_seen, cname_chain)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ip_address, domain_name, record_type, ttl, timestamp, timestamp, cname_chain),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE passive_dns 
                   SET last_seen = ?, ttl = COALESCE(?, ttl), cname_chain = COALESCE(?, cname_chain)
                   WHERE ip_address = ? AND domain_name = ? AND record_type = ?""",
                (timestamp, ttl, cname_chain, ip_address, domain_name, record_type),
            )
            cursor.execute(
                """SELECT id FROM passive_dns 
                   WHERE ip_address = ? AND domain_name = ? AND record_type = ?""",
                (ip_address, domain_name, record_type),
            )
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_external_connection(
        self,
        device_id: int,
        external_ip: str,
        external_port: Optional[int] = None,
        protocol: Optional[str] = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update external connection record.
        
        Args:
            device_id: Device ID
            external_ip: External IP address
            external_port: External port
            protocol: Protocol (TCP/UDP)
            bytes_sent: Bytes sent
            bytes_received: Bytes received
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO external_connections 
                   (device_id, external_ip, external_port, protocol, first_seen, last_seen, connection_count, bytes_sent, bytes_received)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                (device_id, external_ip, external_port, protocol, timestamp, timestamp, bytes_sent, bytes_received),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE external_connections 
                   SET last_seen = ?, connection_count = connection_count + 1, 
                       bytes_sent = bytes_sent + ?, bytes_received = bytes_received + ?
                   WHERE device_id = ? AND external_ip = ? AND external_port = ? AND protocol = ?""",
                (timestamp, bytes_sent, bytes_received, device_id, external_ip, external_port, protocol),
            )
            cursor.execute(
                """SELECT id FROM external_connections 
                   WHERE device_id = ? AND external_ip = ? AND external_port = ? AND protocol = ?""",
                (device_id, external_ip, external_port, protocol),
            )
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_asn_cache(
        self,
        ip_address: str,
        asn: Optional[int] = None,
        as_name: Optional[str] = None,
        as_country: Optional[str] = None,
        bgp_prefix: Optional[str] = None,
        organization: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update ASN cache entry.
        
        Args:
            ip_address: IP address
            asn: Autonomous System Number
            as_name: AS name
            as_country: AS country code
            bgp_prefix: BGP prefix
            organization: Organization name
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO asn_cache 
                   (ip_address, asn, as_name, as_country, bgp_prefix, organization, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ip_address, asn, as_name, as_country, bgp_prefix, organization, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE asn_cache 
                   SET last_seen = ?, asn = COALESCE(?, asn), as_name = COALESCE(?, as_name),
                       as_country = COALESCE(?, as_country), bgp_prefix = COALESCE(?, bgp_prefix),
                       organization = COALESCE(?, organization)
                   WHERE ip_address = ?""",
                (timestamp, asn, as_name, as_country, bgp_prefix, organization, ip_address),
            )
            cursor.execute("SELECT id FROM asn_cache WHERE ip_address = ?", (ip_address,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_geoip_cache(
        self,
        ip_address: str,
        country_code: Optional[str] = None,
        country_name: Optional[str] = None,
        city: Optional[str] = None,
        postal_code: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        continent_code: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update GeoIP cache entry.
        
        Args:
            ip_address: IP address
            country_code: ISO 3166-1 alpha-2 country code
            country_name: Country name
            city: City name
            postal_code: Postal code
            latitude: Latitude
            longitude: Longitude
            continent_code: Continent code
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO geoip_cache 
                   (ip_address, country_code, country_name, city, postal_code, latitude, longitude, continent_code, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ip_address, country_code, country_name, city, postal_code, latitude, longitude, continent_code, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE geoip_cache 
                   SET last_seen = ?, country_code = COALESCE(?, country_code), country_name = COALESCE(?, country_name),
                       city = COALESCE(?, city), postal_code = COALESCE(?, postal_code),
                       latitude = COALESCE(?, latitude), longitude = COALESCE(?, longitude),
                       continent_code = COALESCE(?, continent_code)
                   WHERE ip_address = ?""",
                (timestamp, country_code, country_name, city, postal_code, latitude, longitude, continent_code, ip_address),
            )
            cursor.execute("SELECT id FROM geoip_cache WHERE ip_address = ?", (ip_address,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def get_passive_dns_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """Get passive DNS entries for an IP.
        
        Args:
            ip_address: IP address
        
        Returns:
            List of DNS records
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM passive_dns WHERE ip_address = ? ORDER BY last_seen DESC""",
            (ip_address,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_external_connections_by_device(self, device_id: int) -> List[Dict[str, Any]]:
        """Get external connections for a device.
        
        Args:
            device_id: Device ID
        
        Returns:
            List of external connections
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT * FROM external_connections WHERE device_id = ? ORDER BY last_seen DESC""",
            (device_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def add_wifi_access_point(
        self,
        bssid: str,
        ssid: Optional[str] = None,
        channel: Optional[int] = None,
        frequency: Optional[float] = None,
        rssi: Optional[int] = None,
        data_rate: Optional[float] = None,
        encryption_type: Optional[str] = None,
        cipher_suite: Optional[str] = None,
        akm_suite: Optional[str] = None,
        wps_enabled: bool = False,
        capabilities: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update WiFi access point.
        
        Args:
            bssid: BSSID (MAC address)
            ssid: SSID
            channel: Channel number
            frequency: Frequency in MHz
            rssi: Signal strength
            data_rate: Data rate
            encryption_type: Encryption type (WPA2, WPA3, etc.)
            cipher_suite: Cipher suite (AES/CCMP, TKIP)
            akm_suite: AKM suite (PSK, Enterprise)
            wps_enabled: WPS enabled
            capabilities: Capabilities string
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO wifi_access_points 
                   (bssid, ssid, channel, frequency, rssi, data_rate, encryption_type, cipher_suite, akm_suite, wps_enabled, capabilities, first_seen, last_seen, beacon_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (bssid, ssid, channel, frequency, rssi, data_rate, encryption_type, cipher_suite, akm_suite, int(wps_enabled), capabilities, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE wifi_access_points 
                   SET last_seen = ?, ssid = COALESCE(?, ssid), channel = COALESCE(?, channel), frequency = COALESCE(?, frequency),
                       rssi = COALESCE(?, rssi), data_rate = COALESCE(?, data_rate), encryption_type = COALESCE(?, encryption_type),
                       cipher_suite = COALESCE(?, cipher_suite), akm_suite = COALESCE(?, akm_suite), wps_enabled = COALESCE(?, wps_enabled),
                       capabilities = COALESCE(?, capabilities), beacon_count = beacon_count + 1
                   WHERE bssid = ?""",
                (timestamp, ssid, channel, frequency, rssi, data_rate, encryption_type, cipher_suite, akm_suite, int(wps_enabled), capabilities, bssid),
            )
            cursor.execute("SELECT id FROM wifi_access_points WHERE bssid = ?", (bssid,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_wifi_client(
        self,
        mac_address: str,
        device_id: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update WiFi client.
        
        Args:
            mac_address: MAC address
            device_id: Device ID
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO wifi_clients (mac_address, device_id, first_seen, last_seen)
                   VALUES (?, ?, ?, ?)""",
                (mac_address, device_id, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE wifi_clients 
                   SET last_seen = ?, device_id = COALESCE(?, device_id)
                   WHERE mac_address = ?""",
                (timestamp, device_id, mac_address),
            )
            cursor.execute("SELECT id FROM wifi_clients WHERE mac_address = ?", (mac_address,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_wifi_association(
        self,
        client_id: int,
        ap_id: int,
        association_type: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update WiFi client-AP association.
        
        Args:
            client_id: Client ID
            ap_id: Access point ID
            association_type: Association type
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO wifi_associations (client_id, ap_id, association_type, first_seen, last_seen, frame_count)
                   VALUES (?, ?, ?, ?, ?, 1)""",
                (client_id, ap_id, association_type, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE wifi_associations 
                   SET last_seen = ?, association_type = COALESCE(?, association_type), frame_count = frame_count + 1
                   WHERE client_id = ? AND ap_id = ?""",
                (timestamp, association_type, client_id, ap_id),
            )
            cursor.execute(
                """SELECT id FROM wifi_associations WHERE client_id = ? AND ap_id = ?""",
                (client_id, ap_id),
            )
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_wifi_probe_request(
        self,
        client_mac: str,
        ssid: Optional[str] = None,
        rssi: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add WiFi probe request.
        
        Args:
            client_mac: Client MAC address
            ssid: SSID being probed
            rssi: Signal strength
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO wifi_probe_requests (client_mac, ssid, timestamp, rssi)
               VALUES (?, ?, ?, ?)""",
            (client_mac, ssid, timestamp, rssi),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def add_wifi_management_frame(
        self,
        frame_type: str,
        frame_subtype: Optional[str] = None,
        transmitter_mac: Optional[str] = None,
        receiver_mac: Optional[str] = None,
        bssid: Optional[str] = None,
        rssi: Optional[int] = None,
        channel: Optional[int] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add WiFi management frame.
        
        Args:
            frame_type: Frame type (Management, Control, Data)
            frame_subtype: Frame subtype
            transmitter_mac: Transmitter MAC
            receiver_mac: Receiver MAC
            bssid: BSSID
            rssi: Signal strength
            channel: Channel
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO wifi_management_frames 
               (frame_type, frame_subtype, transmitter_mac, receiver_mac, bssid, timestamp, rssi, channel)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (frame_type, frame_subtype, transmitter_mac, receiver_mac, bssid, timestamp, rssi, channel),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def get_wifi_access_points(self) -> List[Dict[str, Any]]:
        """Get all WiFi access points.
        
        Returns:
            List of access points
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM wifi_access_points ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_wifi_clients(self) -> List[Dict[str, Any]]:
        """Get all WiFi clients.
        
        Returns:
            List of clients
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM wifi_clients ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_wifi_associations(self) -> List[Dict[str, Any]]:
        """Get all WiFi client-AP associations.
        
        Returns:
            List of associations
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """SELECT wa.*, wc.mac_address as client_mac, wap.bssid, wap.ssid 
               FROM wifi_associations wa
               JOIN wifi_clients wc ON wa.client_id = wc.id
               JOIN wifi_access_points wap ON wa.ap_id = wap.id
               ORDER BY wa.last_seen DESC"""
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def add_device_fingerprint(
        self,
        device_id: int,
        manufacturer: Optional[str] = None,
        device_type: Optional[str] = None,
        device_model: Optional[str] = None,
        operating_system: Optional[str] = None,
        os_version: Optional[str] = None,
        confidence_score: float = 0.0,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add or update device fingerprint.
        
        Args:
            device_id: Device ID
            manufacturer: Manufacturer
            device_type: Device type
            device_model: Device model
            operating_system: Operating system
            os_version: OS version
            confidence_score: Confidence score (0-1)
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO device_fingerprints 
                   (device_id, manufacturer, device_type, device_model, operating_system, os_version, confidence_score, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (device_id, manufacturer, device_type, device_model, operating_system, os_version, confidence_score, timestamp, timestamp),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE device_fingerprints 
                   SET last_seen = ?, manufacturer = COALESCE(?, manufacturer), device_type = COALESCE(?, device_type),
                       device_model = COALESCE(?, device_model), operating_system = COALESCE(?, operating_system),
                       os_version = COALESCE(?, os_version), confidence_score = COALESCE(?, confidence_score)
                   WHERE device_id = ?""",
                (timestamp, manufacturer, device_type, device_model, operating_system, os_version, confidence_score, device_id),
            )
            cursor.execute("SELECT id FROM device_fingerprints WHERE device_id = ?", (device_id,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_dhcp_fingerprint(
        self,
        parameter_request_list: str,
        os_family: Optional[str] = None,
        os_version: Optional[str] = None,
        confidence: float = 0.0,
        source: Optional[str] = None,
    ) -> int:
        """Add DHCP fingerprint signature.
        
        Args:
            parameter_request_list: Comma-separated parameter list
            os_family: OS family
            os_version: OS version
            confidence: Confidence score
            source: Source of fingerprint
        
        Returns:
            Record ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO dhcp_fingerprints (parameter_request_list, os_family, os_version, confidence, source)
                   VALUES (?, ?, ?, ?, ?)""",
                (parameter_request_list, os_family, os_version, confidence, source),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute("SELECT id FROM dhcp_fingerprints WHERE parameter_request_list = ?", (parameter_request_list,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_mac_oui_category(
        self,
        oui_prefix: str,
        vendor: Optional[str] = None,
        device_category: Optional[str] = None,
        device_subcategory: Optional[str] = None,
    ) -> int:
        """Add MAC OUI category mapping.
        
        Args:
            oui_prefix: OUI prefix (first 3-6 octets)
            vendor: Vendor name
            device_category: Device category
            device_subcategory: Device subcategory
        
        Returns:
            Record ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO mac_oui_categories (oui_prefix, vendor, device_category, device_subcategory)
                   VALUES (?, ?, ?, ?)""",
                (oui_prefix, vendor, device_category, device_subcategory),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE mac_oui_categories 
                   SET vendor = COALESCE(?, vendor), device_category = COALESCE(?, device_category),
                       device_subcategory = COALESCE(?, device_subcategory)
                   WHERE oui_prefix = ?""",
                (vendor, device_category, device_subcategory, oui_prefix),
            )
            cursor.execute("SELECT id FROM mac_oui_categories WHERE oui_prefix = ?", (oui_prefix,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_http_user_agent(
        self,
        device_id: int,
        user_agent: str,
        os_family: Optional[str] = None,
        os_version: Optional[str] = None,
        browser: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add HTTP User-Agent string.
        
        Args:
            device_id: Device ID
            user_agent: User-Agent string
            os_family: OS family
            os_version: OS version
            browser: Browser
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO http_user_agents (device_id, user_agent, os_family, os_version, browser, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (device_id, user_agent, os_family, os_version, browser, timestamp),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def add_mdns_model_string(
        self,
        service_string: str,
        manufacturer: Optional[str] = None,
        device_model: Optional[str] = None,
        device_type: Optional[str] = None,
    ) -> int:
        """Add mDNS model string mapping.
        
        Args:
            service_string: Service string (e.g., model=MacBookPro15,1)
            manufacturer: Manufacturer
            device_model: Device model
            device_type: Device type
        
        Returns:
            Record ID
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """INSERT INTO mdns_model_strings (service_string, manufacturer, device_model, device_type)
                   VALUES (?, ?, ?, ?)""",
                (service_string, manufacturer, device_model, device_type),
            )
            record_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            cursor.execute(
                """UPDATE mdns_model_strings 
                   SET manufacturer = COALESCE(?, manufacturer), device_model = COALESCE(?, device_model),
                       device_type = COALESCE(?, device_type)
                   WHERE service_string = ?""",
                (manufacturer, device_model, device_type, service_string),
            )
            cursor.execute("SELECT id FROM mdns_model_strings WHERE service_string = ?", (service_string,))
            record_id = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        return record_id
    
    def add_tcp_stack_fingerprint(
        self,
        device_id: int,
        ttl: Optional[int] = None,
        window_size: Optional[int] = None,
        os_family: Optional[str] = None,
        confidence: float = 0.0,
        timestamp: Optional[datetime] = None,
    ) -> int:
        """Add TCP/IP stack fingerprint.
        
        Args:
            device_id: Device ID
            ttl: TTL value
            window_size: TCP window size
            os_family: OS family
            confidence: Confidence score
            timestamp: Timestamp
        
        Returns:
            Record ID
        """
        now = datetime.utcnow()
        timestamp = timestamp or now
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO tcp_stack_fingerprints (device_id, ttl, window_size, os_family, confidence, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (device_id, ttl, window_size, os_family, confidence, timestamp),
        )
        record_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return record_id
    
    def get_device_fingerprint(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get device fingerprint.
        
        Args:
            device_id: Device ID
        
        Returns:
            Fingerprint dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM device_fingerprints WHERE device_id = ?",
            (device_id,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_dhcp_fingerprint(self, parameter_request_list: str) -> Optional[Dict[str, Any]]:
        """Get DHCP fingerprint by parameter list.
        
        Args:
            parameter_request_list: Comma-separated parameter list
        
        Returns:
            Fingerprint dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM dhcp_fingerprints WHERE parameter_request_list = ?",
            (parameter_request_list,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_mac_oui_category(self, oui_prefix: str) -> Optional[Dict[str, Any]]:
        """Get MAC OUI category.
        
        Args:
            oui_prefix: OUI prefix
        
        Returns:
            Category dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM mac_oui_categories WHERE oui_prefix = ?",
            (oui_prefix,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_mdns_model_string(self, service_string: str) -> Optional[Dict[str, Any]]:
        """Get mDNS model string mapping.
        
        Args:
            service_string: Service string
        
        Returns:
            Model string dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM mdns_model_strings WHERE service_string = ?",
            (service_string,),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
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
    
    def get_wifi_access_point_by_bssid(self, bssid: str) -> Optional[Dict[str, Any]]:
        """Get WiFi access point by BSSID.
        
        Args:
            bssid: BSSID
        
        Returns:
            AP dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM wifi_access_points WHERE bssid = ?", (bssid,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_wifi_client_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Get WiFi client by MAC address.
        
        Args:
            mac_address: MAC address
        
        Returns:
            Client dict or None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM wifi_clients WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    
    def get_wifi_management_frames_by_mac(self, mac_address: str) -> List[Dict[str, Any]]:
        """Get WiFi management frames by MAC address.
        
        Args:
            mac_address: MAC address
        
        Returns:
            List of management frames
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM wifi_management_frames WHERE transmitter_mac = ? OR receiver_mac = ?",
            (mac_address, mac_address),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_packet_count(self) -> int:
        """Get total packet count.
        
        Returns:
            Total packet count
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM packets")
        count = cursor.fetchone()[0]
        conn.close()
        return count
