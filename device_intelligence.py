"""
Device Intelligence Module - Milestone 2
Analyzes DHCP, DNS, NetBIOS, and mDNS protocols for device discovery and identification
"""

import logging
import struct
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Optional

from core.payload_extractor import detect_app_protocol, extract_udp_payload
from utils.helpers import normalize_mac

logger = logging.getLogger(__name__)

# Protocol priority for conflict resolution (higher = more trusted)
PROTOCOL_PRIORITY = {
    "DHCP": 3,      # DHCP hostnames are most reliable
    "DNS": 2,       # DNS responses are reliable
    "NETBIOS": 1,   # NetBIOS names are less reliable
    "MDNS": 2,      # mDNS is reliable
}

# mDNS service categorization
MDNS_SERVICE_CATEGORIES = {
    # Apple services
    "_airplay._tcp": "Media Streaming",
    "_raop._tcp": "Media Streaming",
    "_apple-mobdev._tcp": "Apple Mobile Device",
    "_ipp._tcp": "Printing",
    "_ipps._tcp": "Printing",
    "_http._tcp": "Web Service",
    "_https._tcp": "Web Service",
    
    # Google/Chromecast
    "_googlecast._tcp": "Media Streaming",
    "_privet._tcp": "Printing",
    
    # Home automation
    "_hap._tcp": "HomeKit",
    "_homekit._tcp": "HomeKit",
    "_hue-bridgeid._tcp": "Smart Home",
    "_esphomelib._tcp": "Smart Home",
    "_home-assistant._tcp": "Smart Home",
    
    # File sharing
    "_smb._tcp": "File Sharing",
    "_afpovertcp._tcp": "File Sharing",
    "_ftp._tcp": "File Sharing",
    
    # Other common services
    "_ssh._tcp": "Remote Access",
    "_telnet._tcp": "Remote Access",
    "_rfb._tcp": "Remote Access",
    "_printer._tcp": "Printing",
}


def _normalize_dhcp_mac(chaddr_hex: str) -> Optional[str]:
    """Convert DHCP chaddr field (16 bytes hex) to normalized MAC."""
    mac_hex = chaddr_hex.replace(":", "").replace("-", "")[:12]
    if len(mac_hex) != 12:
        return None
    try:
        return normalize_mac(mac_hex)
    except ValueError:
        return None


class DHCPAnalyzer:
    """Analyzes DHCP packets for device information"""

    DHCP_MESSAGE_TYPES = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM",
    }

    def __init__(self):
        self.devices: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.dhcp_transactions: Dict[int, Dict[str, Any]] = {}

    def parse_dhcp_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DHCP packet and extract device information."""
        try:
            if len(packet_data) < 240:
                return None

            op = packet_data[0]
            xid = struct.unpack("!I", packet_data[4:8])[0]
            ciaddr = self._parse_ip(packet_data[12:16])
            yiaddr = self._parse_ip(packet_data[16:20])
            siaddr = self._parse_ip(packet_data[20:24])
            giaddr = self._parse_ip(packet_data[24:28])
            chaddr = packet_data[28:44].hex().upper()

            dhcp_info: Dict[str, Any] = {
                "transaction_id": xid,
                "client_ip": ciaddr,
                "assigned_ip": yiaddr,
                "server_ip": siaddr,
                "gateway_ip": giaddr,
                "client_mac": chaddr,
                "operation": "REQUEST" if op == 1 else "REPLY",
                "timestamp": datetime.now().isoformat(),
            }

            options = self._parse_dhcp_options(packet_data[240:])
            dhcp_info.update(options)

            mac = _normalize_dhcp_mac(chaddr)
            if mac:
                dhcp_info["client_mac"] = mac
                self._store_device(mac, dhcp_info)
                self.dhcp_transactions[xid] = dhcp_info

            return dhcp_info
        except Exception as e:
            logger.debug("Error parsing DHCP packet: %s", e)
            return None

    def _store_device(self, mac: str, dhcp_info: Dict[str, Any]) -> None:
        existing = self.devices[mac]
        for key, value in dhcp_info.items():
            if value not in (None, "", "0.0.0.0"):
                existing[key] = value
        self.devices[mac] = existing

    def _parse_dhcp_options(self, options_data: bytes) -> Dict[str, Any]:
        """Parse DHCP options field."""
        options: Dict[str, Any] = {}
        offset = 0

        while offset < len(options_data) - 2:
            option_type = options_data[offset]

            if option_type == 255:
                break

            if option_type == 0:
                offset += 1
                continue

            length = options_data[offset + 1]
            option_value = options_data[offset + 2 : offset + 2 + length]

            if option_type == 53:
                msg_type = option_value[0]
                options["message_type"] = self.DHCP_MESSAGE_TYPES.get(msg_type, "UNKNOWN")
            elif option_type == 55:
                options["parameter_request_list"] = list(option_value)
            elif option_type == 60:
                options["vendor_class"] = option_value.decode("utf-8", errors="ignore")
            elif option_type == 61:
                options["client_id"] = option_value.hex().upper()
            elif option_type == 12:
                options["hostname"] = option_value.decode("utf-8", errors="ignore")

            offset += 2 + length

        return options

    def _parse_ip(self, ip_bytes: bytes) -> str:
        """Convert IP bytes to string format."""
        return ".".join(map(str, ip_bytes))

    def get_device_list(self) -> Dict[str, Dict[str, Any]]:
        """Return discovered devices from DHCP."""
        return dict(self.devices)


class DNSAnalyzer:
    """Analyzes DNS packets for device and service discovery"""

    RECORD_TYPES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    def __init__(self):
        self.dns_records: Dict[str, list] = defaultdict(list)
        self.device_hostnames: Dict[str, Dict[str, Any]] = {}

    def parse_dns_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS packet and extract device information."""
        try:
            if len(packet_data) < 12:
                return None

            transaction_id = struct.unpack("!H", packet_data[0:2])[0]
            flags = struct.unpack("!H", packet_data[2:4])[0]
            questions = struct.unpack("!H", packet_data[4:6])[0]
            answers = struct.unpack("!H", packet_data[6:8])[0]

            dns_info: Dict[str, Any] = {
                "transaction_id": transaction_id,
                "is_response": bool(flags & 0x8000),
                "questions_count": questions,
                "answers_count": answers,
                "queries": [],
                "responses": [],
                "timestamp": datetime.now().isoformat(),
            }

            offset = 12

            for _ in range(questions):
                query, offset = self._parse_dns_name(packet_data, offset)
                qtype = struct.unpack("!H", packet_data[offset : offset + 2])[0]
                qclass = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
                dns_info["queries"].append(
                    {
                        "name": query,
                        "type": self.RECORD_TYPES.get(qtype, str(qtype)),
                        "class": qclass,
                    }
                )
                offset += 4

            for _ in range(answers):
                name, offset = self._parse_dns_name(packet_data, offset)
                rtype = struct.unpack("!H", packet_data[offset : offset + 2])[0]
                rclass = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
                ttl = struct.unpack("!I", packet_data[offset + 4 : offset + 8])[0]
                rdlen = struct.unpack("!H", packet_data[offset + 8 : offset + 10])[0]
                rdata = packet_data[offset + 10 : offset + 10 + rdlen]

                dns_info["responses"].append(
                    {
                        "name": name,
                        "type": self.RECORD_TYPES.get(rtype, str(rtype)),
                        "ttl": ttl,
                        "data": self._parse_rdata(rtype, rdata),
                    }
                )

                offset += 10 + rdlen

            self._store_dns_info(dns_info)
            return dns_info
        except Exception as e:
            logger.debug("Error parsing DNS packet: %s", e)
            return None

    def _store_dns_info(self, dns_info: Dict[str, Any]) -> None:
        for query in dns_info.get("queries", []):
            name = query.get("name", "").rstrip(".")
            if name:
                self.device_hostnames[name] = dns_info
                self.dns_records[name].append(query)

        for response in dns_info.get("responses", []):
            name = response.get("name", "").rstrip(".")
            if name:
                self.device_hostnames[name] = dns_info
                self.dns_records[name].append(response)

    def _parse_dns_name(self, packet_data: bytes, offset: int):
        """Parse DNS name from packet."""
        name = []

        while offset < len(packet_data):
            length = packet_data[offset]
            offset += 1

            if length == 0:
                break

            if length & 0xC0:
                pointer = struct.unpack(
                    "!H", bytes([(length & 0x3F), packet_data[offset]])
                )[0]
                offset += 1
                _, sub_name = self._parse_dns_name(packet_data, pointer)
                name.append(sub_name)
                break

            name.append(packet_data[offset : offset + length].decode("utf-8", errors="ignore"))
            offset += length

        return ".".join(name), offset

    def _parse_rdata(self, rtype: int, rdata: bytes):
        """Parse DNS resource data based on type."""
        if rtype == 1:
            return ".".join(map(str, rdata))
        if rtype == 28:
            return ":".join(
                f"{int.from_bytes(rdata[i : i + 2], 'big'):x}" for i in range(0, 16, 2)
            )
        if rtype == 16:
            return rdata.decode("utf-8", errors="ignore")
        return rdata.hex().upper()

    def get_discovered_devices(self) -> Dict[str, Dict[str, Any]]:
        """Return discovered devices from DNS."""
        return dict(self.device_hostnames)


class NetBIOSAnalyzer:
    """Analyzes NetBIOS packets for device discovery"""

    def __init__(self):
        self.netbios_names: Dict[str, Dict[str, Any]] = {}
        self.workgroups: Dict[str, list] = defaultdict(list)

    def parse_netbios_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse NetBIOS name query/response."""
        try:
            netbios_info: Dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "names": [],
                "workgroups": [],
            }

            if len(packet_data) >= 12:
                name_trn_id = struct.unpack("!H", packet_data[0:2])[0]
                flags = struct.unpack("!H", packet_data[2:4])[0]

                netbios_info["transaction_id"] = name_trn_id
                netbios_info["is_response"] = bool(flags & 0x8000)
                netbios_info["is_authoritative"] = bool(flags & 0x0400)

                # Extract NetBIOS names from questions section (offset 12+)
                if len(packet_data) >= 57:
                    questions = struct.unpack("!H", packet_data[4:6])[0]
                    offset = 12
                    
                    for _ in range(questions):
                        if offset + 34 > len(packet_data):
                            break
                        
                        # NetBIOS name is encoded in "first-level encoding"
                        encoded_name = packet_data[offset:offset + 32]
                        decoded_name = self._decode_netbios_name(encoded_name)
                        
                        if decoded_name:
                            netbios_info["names"].append(decoded_name)
                            # Store by decoded name for correlation
                            self.netbios_names[decoded_name] = netbios_info
                        
                        suffix = packet_data[offset + 32]
                        name_type = self._get_netbios_name_type(suffix)
                        
                        offset += 34  # 32 bytes name + 1 byte suffix + 1 byte null

                key = f"txn_{name_trn_id}"
                self.netbios_names[key] = netbios_info

            return netbios_info
        except Exception as e:
            logger.debug("Error parsing NetBIOS packet: %s", e)
            return None

    def _decode_netbios_name(self, encoded: bytes) -> Optional[str]:
        """Decode NetBIOS first-level encoding to ASCII."""
        try:
            decoded = []
            for i in range(0, len(encoded), 2):
                if i + 1 >= len(encoded):
                    break
                byte_val = (encoded[i] - 0x41) << 4 | (encoded[i + 1] - 0x41)
                if 0x20 <= byte_val <= 0x7E:  # Printable ASCII
                    decoded.append(chr(byte_val))
                elif byte_val == 0x00:  # Padding
                    break
            return "".join(decoded).strip()
        except Exception as e:
            logger.debug("Error decoding NetBIOS name: %s", e)
            return None

    def _get_netbios_name_type(self, suffix: int) -> str:
        """Get NetBIOS name type description from suffix byte."""
        name_types = {
            0x00: "Workstation Name",
            0x03: "Messenger Service",
            0x1C: "Domain Controllers",
            0x1E: "Browser Service Elections",
            0x20: "File Server Service",
        }
        return name_types.get(suffix, f"Unknown (0x{suffix:02X})")

    def get_netbios_devices(self) -> Dict[str, Dict[str, Any]]:
        """Return discovered NetBIOS devices."""
        return dict(self.netbios_names)


class mDNSAnalyzer:
    """Analyzes mDNS (Multicast DNS) packets for device discovery"""

    def __init__(self):
        self.mdns_services: Dict[str, list] = defaultdict(list)
        self.mdns_devices: Dict[str, Dict[str, Any]] = {}

    def parse_mdns_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """Parse mDNS packet and extract service information."""
        try:
            if len(packet_data) < 12:
                return None

            transaction_id = struct.unpack("!H", packet_data[0:2])[0]
            flags = struct.unpack("!H", packet_data[2:4])[0]
            questions = struct.unpack("!H", packet_data[4:6])[0]
            answers = struct.unpack("!H", packet_data[6:8])[0]

            mdns_info: Dict[str, Any] = {
                "transaction_id": transaction_id,
                "is_response": bool(flags & 0x8000),
                "questions_count": questions,
                "answers_count": answers,
                "services": [],
                "timestamp": datetime.now().isoformat(),
            }

            offset = 12

            for _ in range(questions):
                name = ""
                while offset < len(packet_data):
                    length = packet_data[offset]
                    offset += 1
                    if length == 0:
                        break
                    name += (
                        packet_data[offset : offset + length].decode("utf-8", errors="ignore")
                        + "."
                    )
                    offset += length

                if offset + 4 <= len(packet_data):
                    qtype = struct.unpack("!H", packet_data[offset : offset + 2])[0]
                    qclass = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
                    offset += 4

                    service_name = name.rstrip(".")
                    service_category = self._categorize_service(service_name)
                    
                    service_entry = {
                        "service": service_name,
                        "type": qtype,
                        "class": qclass,
                        "category": service_category,
                    }
                    mdns_info["services"].append(service_entry)

                    if service_name:
                        self.mdns_services[service_name].append(service_entry)

            return mdns_info
        except Exception as e:
            logger.debug("Error parsing mDNS packet: %s", e)
            return None

    def _categorize_service(self, service_name: str) -> str:
        """Categorize mDNS service by type."""
        for pattern, category in MDNS_SERVICE_CATEGORIES.items():
            if pattern in service_name.lower():
                return category
        return "Unknown"

    def get_mdns_services(self) -> Dict[str, list]:
        """Return discovered mDNS services."""
        return dict(self.mdns_services)


class DeviceIntelligence:
    """Main Device Intelligence engine combining all protocol analyzers"""

    def __init__(self, db_manager=None, internet_intelligence=None):
        self.dhcp_analyzer = DHCPAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.netbios_analyzer = NetBIOSAnalyzer()
        self.mdns_analyzer = mDNSAnalyzer()
        self.discovered_devices: Dict[str, Dict[str, Any]] = {}
        self.db_manager = db_manager
        self.internet_intelligence = internet_intelligence

    def analyze_packet(self, packet, metadata) -> Optional[Dict[str, Any]]:
        """Analyze a Scapy packet using metadata for protocol detection."""
        protocol = detect_app_protocol(metadata, packet)
        if not protocol:
            return None

        payload = extract_udp_payload(packet)
        if not payload:
            logger.debug("No UDP payload for %s packet", protocol)
            return None

        result = None
        if protocol == "DHCP":
            result = self.dhcp_analyzer.parse_dhcp_packet(payload)
            if result and result.get("client_mac"):
                self.discovered_devices[result["client_mac"]] = result
                self._persist_dhcp_discovery(result, metadata)
        elif protocol == "DNS":
            result = self.dns_analyzer.parse_dns_packet(payload)
            if result:
                self._persist_dns_discovery(result, metadata)
        elif protocol == "NETBIOS":
            result = self.netbios_analyzer.parse_netbios_packet(payload)
            if result:
                self._persist_netbios_discovery(result, metadata)
        elif protocol == "MDNS":
            result = self.mdns_analyzer.parse_mdns_packet(payload)
            if result:
                self._persist_mdns_discovery(result, metadata)

        return result

    def _persist_dhcp_discovery(self, dhcp_info: Dict[str, Any], metadata) -> None:
        """Persist DHCP discovery to database with identity ledger."""
        if not self.db_manager:
            return
        
        try:
            mac = dhcp_info.get("client_mac")
            if not mac:
                return
            
            device_id = self.db_manager.add_or_update_device(mac)
            
            self.db_manager.add_dhcp_discovery(
                device_id=device_id,
                client_mac=mac,
                hostname=dhcp_info.get("hostname"),
                assigned_ip=dhcp_info.get("assigned_ip"),
                vendor_class=dhcp_info.get("vendor_class"),
                parameter_request_list=dhcp_info.get("parameter_request_list"),
                message_type=dhcp_info.get("message_type"),
            )
            
            # Add to identity ledger
            if dhcp_info.get("hostname"):
                self.db_manager.add_device_identity(
                    device_id=device_id,
                    identity_type="hostname",
                    identity_value=dhcp_info["hostname"],
                    protocol_source="DHCP",
                    priority=PROTOCOL_PRIORITY.get("DHCP", 0),
                )
        except Exception as e:
            logger.debug("Error persisting DHCP discovery: %s", e)

    def _persist_dns_discovery(self, dns_info: Dict[str, Any], metadata) -> None:
        """Persist DNS discovery to database with identity ledger."""
        if not self.db_manager:
            return
        
        try:
            mac = metadata.src_mac if metadata else None
            if not mac:
                return
            
            device_id = self.db_manager.add_or_update_device(mac)
            
            for query in dns_info.get("queries", []):
                hostname = query.get("name", "").rstrip(".")
                if hostname:
                    self.db_manager.add_device_identity(
                        device_id=device_id,
                        identity_type="hostname",
                        identity_value=hostname,
                        protocol_source="DNS",
                        priority=PROTOCOL_PRIORITY.get("DNS", 0),
                    )
            
            # Feed DNS responses to passive DNS engine (Milestone 3)
            if self.internet_intelligence and dns_info.get("is_response"):
                for response in dns_info.get("responses", []):
                    domain = response.get("name", "").rstrip(".")
                    record_type = response.get("type")
                    data = response.get("data")
                    ttl = response.get("ttl")
                    
                    if domain and data and record_type in ("A", "AAAA"):
                        # Extract IP address from response data
                        ip_address = data if record_type == "A" else data
                        self.internet_intelligence.passive_dns.process_dns_response(
                            domain=domain,
                            ip_address=ip_address,
                            record_type=record_type,
                            ttl=ttl,
                        )
        except Exception as e:
            logger.debug("Error persisting DNS discovery: %s", e)

    def _persist_netbios_discovery(self, netbios_info: Dict[str, Any], metadata) -> None:
        """Persist NetBIOS discovery to database with identity ledger."""
        if not self.db_manager:
            return
        
        try:
            mac = metadata.src_mac if metadata else None
            if not mac:
                return
            
            device_id = self.db_manager.add_or_update_device(mac)
            
            for name in netbios_info.get("names", []):
                if name:
                    self.db_manager.add_netbios_discovery(
                        device_id=device_id,
                        netbios_name=name,
                        name_type="Workstation",
                    )
                    self.db_manager.add_device_identity(
                        device_id=device_id,
                        identity_type="netbios_name",
                        identity_value=name,
                        protocol_source="NETBIOS",
                        priority=PROTOCOL_PRIORITY.get("NETBIOS", 0),
                    )
        except Exception as e:
            logger.debug("Error persisting NetBIOS discovery: %s", e)

    def _persist_mdns_discovery(self, mdns_info: Dict[str, Any], metadata) -> None:
        """Persist mDNS discovery to database with identity ledger."""
        if not self.db_manager:
            return
        
        try:
            mac = metadata.src_mac if metadata else None
            if not mac:
                return
            
            device_id = self.db_manager.add_or_update_device(mac)
            
            for service in mdns_info.get("services", []):
                service_name = service.get("service")
                if service_name:
                    self.db_manager.add_mdns_service(
                        device_id=device_id,
                        service_name=service_name,
                        service_type=service.get("type"),
                        service_category=service.get("category"),
                    )
        except Exception as e:
            logger.debug("Error persisting mDNS discovery: %s", e)

    def get_device_summary(self) -> Dict[str, Any]:
        """Generate summary of all discovered devices."""
        dhcp_devices = self.dhcp_analyzer.get_device_list()
        dns_devices = self.dns_analyzer.get_discovered_devices()
        netbios_devices = self.netbios_analyzer.get_netbios_devices()
        mdns_services = self.mdns_analyzer.get_mdns_services()

        unique_ids = set(dhcp_devices.keys())
        unique_ids.update(dns_devices.keys())
        unique_ids.update(netbios_devices.keys())
        unique_ids.update(mdns_services.keys())

        return {
            "dhcp_devices": dhcp_devices,
            "dns_devices": dns_devices,
            "netbios_devices": netbios_devices,
            "mdns_services": mdns_services,
            "total_devices": len(unique_ids),
        }

    def correlate_device_info(self) -> Dict[str, Dict[str, Any]]:
        """Correlate device information across protocols."""
        correlated: Dict[str, Dict[str, Any]] = {}

        for mac, dhcp_info in self.dhcp_analyzer.devices.items():
            hostname = dhcp_info.get("hostname")
            if not hostname:
                continue

            correlated[hostname] = {
                "mac_address": mac,
                "dhcp_info": dhcp_info,
                "dns_records": self.dns_analyzer.device_hostnames.get(hostname),
                "netbios_info": self.netbios_analyzer.netbios_names.get(hostname),
            }

        return correlated


if __name__ == "__main__":
    di = DeviceIntelligence()
    logger.info("Device Intelligence module initialized (DHCP, DNS, NetBIOS, mDNS)")
