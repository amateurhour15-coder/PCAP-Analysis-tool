"""
Internet Intelligence Module - Milestone 3
Analyzes external traffic, passive DNS, ASN, and GeoIP enrichment
"""

import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Private IP ranges (RFC 1918, link-local, multicast)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_public_ip(ip_str: str) -> bool:
    """Check if IP address is public (not private/link-local/multicast).
    
    Args:
        ip_str: IP address string
    
    Returns:
        True if public, False if private
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for private_range in PRIVATE_IP_RANGES:
            if ip in private_range:
                return False
        return True
    except ValueError:
        return False


class PassiveDNSEngine:
    """Passive DNS correlation engine for mapping IPs to domains."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.dns_cache: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.pending_lookups: Set[str] = set()
    
    def process_dns_response(
        self,
        domain: str,
        ip_address: str,
        record_type: str,
        ttl: Optional[int] = None,
        cname_chain: Optional[List[str]] = None,
    ) -> None:
        """Process DNS response and cache IP-to-domain mapping.
        
        Args:
            domain: Domain name
            ip_address: IP address resolved
            record_type: DNS record type (A, AAAA, CNAME)
            ttl: Time-to-live value
            cname_chain: CNAME chain if applicable
        """
        if not is_public_ip(ip_address):
            return
        
        cname_str = " -> ".join(cname_chain) if cname_chain else None
        
        # Store in memory cache
        self.dns_cache[ip_address].append({
            "domain": domain,
            "record_type": record_type,
            "ttl": ttl,
            "cname_chain": cname_str,
            "timestamp": datetime.utcnow(),
        })
        
        # Persist to database
        if self.db_manager:
            try:
                self.db_manager.add_passive_dns(
                    ip_address=ip_address,
                    domain_name=domain,
                    record_type=record_type,
                    ttl=ttl,
                    cname_chain=cname_str,
                )
            except Exception as e:
                logger.debug("Error storing passive DNS: %s", e)
    
    def resolve_ip_to_domain(self, ip_address: str) -> List[str]:
        """Resolve IP address to domain names using passive DNS cache.
        
        Args:
            ip_address: IP address
        
        Returns:
            List of domain names
        """
        domains = []
        
        # Check memory cache
        for entry in self.dns_cache.get(ip_address, []):
            if entry["domain"]:
                domains.append(entry["domain"])
        
        # Check database cache
        if self.db_manager:
            try:
                records = self.db_manager.get_passive_dns_by_ip(ip_address)
                for record in records:
                    if record["domain_name"] and record["domain_name"] not in domains:
                        domains.append(record["domain_name"])
            except Exception as e:
                logger.debug("Error querying passive DNS: %s", e)
        
        return domains
    
    def get_valid_mappings(self, ip_address: str) -> List[Dict[str, Any]]:
        """Get valid IP-to-domain mappings considering TTL.
        
        Args:
            ip_address: IP address
        
        Returns:
            List of valid mappings
        """
        valid_mappings = []
        now = datetime.utcnow()
        
        for entry in self.dns_cache.get(ip_address, []):
            if entry["ttl"]:
                expiry = entry["timestamp"] + timedelta(seconds=entry["ttl"])
                if now < expiry:
                    valid_mappings.append(entry)
            else:
                # No TTL, consider valid
                valid_mappings.append(entry)
        
        return valid_mappings


class ExternalConnectionTracker:
    """Track external IP connections from local devices."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.connections: Dict[int, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    
    def track_connection(
        self,
        device_id: int,
        external_ip: str,
        external_port: Optional[int] = None,
        protocol: Optional[str] = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
    ) -> None:
        """Track external connection from device.
        
        Args:
            device_id: Device ID
            external_ip: External IP address
            external_port: External port
            protocol: Protocol (TCP/UDP)
            bytes_sent: Bytes sent
            bytes_received: Bytes received
        """
        if not is_public_ip(external_ip):
            return
        
        key = f"{external_ip}:{external_port}:{protocol}"
        
        # Update in-memory tracking
        if key not in self.connections[device_id]:
            self.connections[device_id][key] = {
                "external_ip": external_ip,
                "external_port": external_port,
                "protocol": protocol,
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "connection_count": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
            }
        
        conn = self.connections[device_id][key]
        conn["last_seen"] = datetime.utcnow()
        conn["connection_count"] += 1
        conn["bytes_sent"] += bytes_sent
        conn["bytes_received"] += bytes_received
        
        # Persist to database
        if self.db_manager:
            try:
                self.db_manager.add_external_connection(
                    device_id=device_id,
                    external_ip=external_ip,
                    external_port=external_port,
                    protocol=protocol,
                    bytes_sent=bytes_sent,
                    bytes_received=bytes_received,
                )
            except Exception as e:
                logger.debug("Error storing external connection: %s", e)
    
    def get_device_external_ips(self, device_id: int) -> Set[str]:
        """Get unique external IPs for a device.
        
        Args:
            device_id: Device ID
        
        Returns:
            Set of external IP addresses
        """
        ips = set()
        
        # From memory
        for conn in self.connections.get(device_id, {}).values():
            ips.add(conn["external_ip"])
        
        # From database
        if self.db_manager:
            try:
                connections = self.db_manager.get_external_connections_by_device(device_id)
                for conn in connections:
                    ips.add(conn["external_ip"])
            except Exception as e:
                logger.debug("Error querying external connections: %s", e)
        
        return ips


class ASNResolver:
    """Resolve IP addresses to ASN information (offline mode)."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.asn_cache: Dict[str, Dict[str, Any]] = {}
    
    def resolve_asn(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Resolve IP to ASN information.
        
        Args:
            ip_address: IP address
        
        Returns:
            ASN information dict or None
        """
        if not is_public_ip(ip_address):
            return None
        
        # Check memory cache
        if ip_address in self.asn_cache:
            return self.asn_cache[ip_address]
        
        # Check database cache
        if self.db_manager:
            try:
                conn = self.db_manager.get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM asn_cache WHERE ip_address = ?",
                    (ip_address,),
                )
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    asn_info = dict(row)
                    self.asn_cache[ip_address] = asn_info
                    return asn_info
            except Exception as e:
                logger.debug("Error querying ASN cache: %s", e)
        
        # No cached data - would need offline ASN database integration
        # This is a placeholder for MaxMind/IPinfo integration
        return None
    
    def cache_asn_info(
        self,
        ip_address: str,
        asn: Optional[int] = None,
        as_name: Optional[str] = None,
        as_country: Optional[str] = None,
        bgp_prefix: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> None:
        """Cache ASN information for an IP.
        
        Args:
            ip_address: IP address
            asn: Autonomous System Number
            as_name: AS name
            as_country: AS country code
            bgp_prefix: BGP prefix
            organization: Organization name
        """
        asn_info = {
            "asn": asn,
            "as_name": as_name,
            "as_country": as_country,
            "bgp_prefix": bgp_prefix,
            "organization": organization,
        }
        
        self.asn_cache[ip_address] = asn_info
        
        if self.db_manager:
            try:
                self.db_manager.add_asn_cache(
                    ip_address=ip_address,
                    asn=asn,
                    as_name=as_name,
                    as_country=as_country,
                    bgp_prefix=bgp_prefix,
                    organization=organization,
                )
            except Exception as e:
                logger.debug("Error caching ASN info: %s", e)


class GeoIPResolver:
    """Resolve IP addresses to geographic location (offline mode)."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.geoip_cache: Dict[str, Dict[str, Any]] = {}
    
    def resolve_geoip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Resolve IP to geographic location.
        
        Args:
            ip_address: IP address
        
        Returns:
            GeoIP information dict or None
        """
        if not is_public_ip(ip_address):
            return None
        
        # Check memory cache
        if ip_address in self.geoip_cache:
            return self.geoip_cache[ip_address]
        
        # Check database cache
        if self.db_manager:
            try:
                conn = self.db_manager.get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM geoip_cache WHERE ip_address = ?",
                    (ip_address,),
                )
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    geoip_info = dict(row)
                    self.geoip_cache[ip_address] = geoip_info
                    return geoip_info
            except Exception as e:
                logger.debug("Error querying GeoIP cache: %s", e)
        
        # No cached data - would need offline GeoIP database integration
        # This is a placeholder for MaxMind GeoLite2 integration
        return None
    
    def cache_geoip_info(
        self,
        ip_address: str,
        country_code: Optional[str] = None,
        country_name: Optional[str] = None,
        city: Optional[str] = None,
        postal_code: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        continent_code: Optional[str] = None,
    ) -> None:
        """Cache GeoIP information for an IP.
        
        Args:
            ip_address: IP address
            country_code: ISO 3166-1 alpha-2 country code
            country_name: Country name
            city: City name
            postal_code: Postal code
            latitude: Latitude
            longitude: Longitude
            continent_code: Continent code
        """
        geoip_info = {
            "country_code": country_code,
            "country_name": country_name,
            "city": city,
            "postal_code": postal_code,
            "latitude": latitude,
            "longitude": longitude,
            "continent_code": continent_code,
        }
        
        self.geoip_cache[ip_address] = geoip_info
        
        if self.db_manager:
            try:
                self.db_manager.add_geoip_cache(
                    ip_address=ip_address,
                    country_code=country_code,
                    country_name=country_name,
                    city=city,
                    postal_code=postal_code,
                    latitude=latitude,
                    longitude=longitude,
                    continent_code=continent_code,
                )
            except Exception as e:
                logger.debug("Error caching GeoIP info: %s", e)


class InternetIntelligence:
    """Main Internet Intelligence engine combining all analyzers."""
    
    def __init__(self, db_manager=None, offline_mode=True):
        self.db_manager = db_manager
        self.offline_mode = offline_mode
        
        self.passive_dns = PassiveDNSEngine(db_manager)
        self.connection_tracker = ExternalConnectionTracker(db_manager)
        self.asn_resolver = ASNResolver(db_manager)
        self.geoip_resolver = GeoIPResolver(db_manager)
        
        logger.info("Internet Intelligence module initialized (offline mode: %s)", offline_mode)
    
    def process_packet(self, packet, metadata, device_id: int) -> Optional[Dict[str, Any]]:
        """Process packet for internet intelligence.
        
        Args:
            packet: Scapy packet
            metadata: Packet metadata
            device_id: Device ID
        
        Returns:
            Analysis result dict or None
        """
        result = {}
        
        # Track external connections
        if metadata.dst_ip and is_public_ip(metadata.dst_ip):
            self.connection_tracker.track_connection(
                device_id=device_id,
                external_ip=metadata.dst_ip,
                external_port=metadata.dst_port,
                protocol=metadata.protocol,
                bytes_sent=metadata.packet_size,
            )
        
        if metadata.src_ip and is_public_ip(metadata.src_ip):
            self.connection_tracker.track_connection(
                device_id=device_id,
                external_ip=metadata.src_ip,
                external_port=metadata.src_port,
                protocol=metadata.protocol,
                bytes_received=metadata.packet_size,
            )
        
        return result
    
    def enrich_external_ip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich external IP with ASN and GeoIP data.
        
        Args:
            ip_address: IP address
        
        Returns:
            Enrichment data dict
        """
        if not is_public_ip(ip_address):
            return {}
        
        enrichment = {
            "ip_address": ip_address,
            "domains": self.passive_dns.resolve_ip_to_domain(ip_address),
            "asn": self.asn_resolver.resolve_asn(ip_address),
            "geoip": self.geoip_resolver.resolve_geoip(ip_address),
        }
        
        return enrichment
    
    def get_device_intelligence_summary(self, device_id: int) -> Dict[str, Any]:
        """Get internet intelligence summary for a device.
        
        Args:
            device_id: Device ID
        
        Returns:
            Summary dict with external IPs, domains, ASNs, countries
        """
        external_ips = self.connection_tracker.get_device_external_ips(device_id)
        
        unique_domains = set()
        unique_asns = set()
        unique_countries = set()
        
        for ip in external_ips:
            enrichment = self.enrich_external_ip(ip)
            
            for domain in enrichment.get("domains", []):
                unique_domains.add(domain)
            
            asn_info = enrichment.get("asn")
            if asn_info and asn_info.get("asn"):
                unique_asns.add(asn_info["asn"])
            
            geoip_info = enrichment.get("geoip")
            if geoip_info and geoip_info.get("country_code"):
                unique_countries.add(geoip_info["country_code"])
        
        return {
            "device_id": device_id,
            "unique_external_ips": len(external_ips),
            "unique_domains": len(unique_domains),
            "unique_asns": len(unique_asns),
            "unique_countries": len(unique_countries),
            "external_ips": list(external_ips),
            "domains": list(unique_domains),
        }


if __name__ == "__main__":
    ii = InternetIntelligence()
    logger.info("Internet Intelligence module initialized")
