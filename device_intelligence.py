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

                key = f"txn_{name_trn_id}"
                self.netbios_names[key] = netbios_info

            return netbios_info
        except Exception as e:
            logger.debug("Error parsing NetBIOS packet: %s", e)
            return None

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

                    service_entry = {
                        "service": name.rstrip("."),
                        "type": qtype,
                        "class": qclass,
                    }
                    mdns_info["services"].append(service_entry)

                    service_name = service_entry["service"]
                    if service_name:
                        self.mdns_services[service_name].append(service_entry)

            return mdns_info
        except Exception as e:
            logger.debug("Error parsing mDNS packet: %s", e)
            return None

    def get_mdns_services(self) -> Dict[str, list]:
        """Return discovered mDNS services."""
        return dict(self.mdns_services)


class DeviceIntelligence:
    """Main Device Intelligence engine combining all protocol analyzers"""

    def __init__(self):
        self.dhcp_analyzer = DHCPAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.netbios_analyzer = NetBIOSAnalyzer()
        self.mdns_analyzer = mDNSAnalyzer()
        self.discovered_devices: Dict[str, Dict[str, Any]] = {}

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
        elif protocol == "DNS":
            result = self.dns_analyzer.parse_dns_packet(payload)
        elif protocol == "NETBIOS":
            result = self.netbios_analyzer.parse_netbios_packet(payload)
        elif protocol == "MDNS":
            result = self.mdns_analyzer.parse_mdns_packet(payload)

        return result

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
