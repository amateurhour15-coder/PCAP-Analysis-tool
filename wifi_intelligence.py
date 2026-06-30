"""
WiFi Intelligence Module - Milestone 4
Analyzes 802.11 wireless frames, Radiotap headers, and security information
"""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)

# 802.11 Frame Types
FRAME_TYPES = {
    0: "Management",
    1: "Control",
    2: "Data",
    3: "Extension",
}

# Management Frame Subtypes
MGMT_SUBTYPES = {
    0: "Association Request",
    1: "Association Response",
    2: "Reassociation Request",
    3: "Reassociation Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
}

# Control Frame Subtypes
CTRL_SUBTYPES = {
    24: "Block Ack Request",
    25: "Block Ack",
    26: "PS-Poll",
    27: "RTS",
    28: "CTS",
    29: "Ack",
    30: "CF-End",
    31: "CF-End + CF-Ack",
}

# Data Frame Subtypes
DATA_SUBTYPES = {
    0: "Data",
    1: "Data + CF-Ack",
    2: "Data + CF-Poll",
    3: "Data + CF-Ack + CF-Poll",
    4: "Null",
    5: "CF-Ack",
    6: "CF-Poll",
    7: "CF-Ack + CF-Poll",
    8: "QoS Data",
    12: "QoS Null",
}

# Cipher Suites
CIPHER_SUITES = {
    0x00FAC02: "Use group cipher",
    0x00FAC04: "WEP-40",
    0x00FAC01: "TKIP",
    0x00FAC02: "Reserved",
    0x00FAC05: "WEP-104",
    0x00FAC06: "BIP-CMAC-128",
    0x00FAC08: "GCMP",
    0x00FAC09: "GCMP-256",
    0x00FAC0A: "CCMP-256",
    0x00FAC0B: "BIP-GMAC-128",
    0x00FAC0C: "BIP-GMAC-256",
    0x00FAC0D: "BIP-CMAC-256",
}

# AKM Suites
AKM_SUITES = {
    0x00FAC01: "802.1X",
    0x00FAC02: "PSK",
    0x00FAC03: "FT-802.1X",
    0x00FAC04: "FT-PSK",
    0x00FAC05: "WPA-SHA256",
    0x00FAC06: "WPA-SHA256-PSK",
    0x00FAC07: "TDLS",
    0x00FAC08: "SAE",
    0x00FAC09: "FT-SAE",
    0x00FAC0B: "AP-PEER-KEY",
    0x00FAC0C: "WPA-SHA384",
    0x00FAC0D: "FT-SHA384",
    0x00FAC0E: "OWE",
    0x00FAC0F: "WPA-SHA512",
}


class RadiotapParser:
    """Parse Radiotap header for physical layer metadata."""
    
    @staticmethod
    def parse_radiotap(packet) -> Optional[Dict[str, Any]]:
        """Extract Radiotap metadata from packet.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Radiotap metadata dict or None
        """
        if not scapy or not packet:
            return None
        
        try:
            if hasattr(scapy, 'RadioTap') and scapy.RadioTap in packet:
                radiotap = packet[scapy.RadioTap]
                metadata = {}
                
                # Signal strength (RSSI)
                if hasattr(radiotap, 'dBm_AntSignal'):
                    metadata['rssi'] = radiotap.dBm_AntSignal
                elif hasattr(radiotap, 'antenna_signal'):
                    metadata['rssi'] = radiotap.antenna_signal
                
                # Channel frequency
                if hasattr(radiotap, 'Channel'):
                    metadata['frequency'] = radiotap.Channel
                    # Convert frequency to channel (2.4 GHz)
                    if 2412 <= metadata['frequency'] <= 2484:
                        metadata['channel'] = (metadata['frequency'] - 2407) // 5
                    elif 5160 <= metadata['frequency'] <= 5865:
                        metadata['channel'] = (metadata['frequency'] - 5000) // 5
                
                # Data rate
                if hasattr(radiotap, 'Rate'):
                    metadata['data_rate'] = radiotap.Rate
                
                # Channel flags
                if hasattr(radiotap, 'ChannelFlags'):
                    metadata['channel_flags'] = radiotap.ChannelFlags
                
                return metadata if metadata else None
        except Exception as e:
            logger.debug("Error parsing Radiotap: %s", e)
        
        return None


class FrameControlParser:
    """Parse 802.11 Frame Control field."""
    
    @staticmethod
    def parse_frame_control(packet) -> Optional[Dict[str, Any]]:
        """Extract frame control information.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Frame control dict or None
        """
        if not scapy or not packet or scapy.Dot11 not in packet:
            return None
        
        try:
            dot11 = packet[scapy.Dot11]
            
            frame_type = (dot11.type >> 2) & 0x03
            frame_subtype = dot11.type & 0x0F
            
            control = {
                'type': FRAME_TYPES.get(frame_type, "Unknown"),
                'type_code': frame_type,
                'subtype': None,
                'subtype_code': frame_subtype,
                'proto_version': dot11.proto,
                'to_ds': bool(dot11.FCfield & 0x01),
                'from_ds': bool(dot11.FCfield & 0x02),
                'more_frag': bool(dot11.FCfield & 0x04),
                'retry': bool(dot11.FCfield & 0x08),
                'pwr_mgt': bool(dot11.FCfield & 0x10),
                'more_data': bool(dot11.FCfield & 0x20),
                'wep': bool(dot11.FCfield & 0x40),
                'order': bool(dot11.FCfield & 0x80),
            }
            
            # Get subtype name
            if frame_type == 0:
                control['subtype'] = MGMT_SUBTYPES.get(frame_subtype, f"Unknown ({frame_subtype})")
            elif frame_type == 1:
                control['subtype'] = CTRL_SUBTYPES.get(frame_subtype, f"Unknown ({frame_subtype})")
            elif frame_type == 2:
                control['subtype'] = DATA_SUBTYPES.get(frame_subtype, f"Unknown ({frame_subtype})")
            
            return control
        except Exception as e:
            logger.debug("Error parsing frame control: %s", e)
        
        return None


class MACAddressExtractor:
    """Extract MAC addresses from 802.11 frames."""
    
    @staticmethod
    def extract_addresses(packet, frame_control: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """Extract TA, RA, SA, DA, and BSSID from 802.11 frame.
        
        Args:
            packet: Scapy packet
            frame_control: Frame control info
        
        Returns:
            Dict with address fields
        """
        if not scapy or not packet or scapy.Dot11 not in packet:
            return {}
        
        try:
            dot11 = packet[scapy.Dot11]
            addresses = {
                'ta': None,  # Transmitter Address
                'ra': None,  # Receiver Address
                'sa': None,  # Source Address
                'da': None,  # Destination Address
                'bssid': None,
            }
            
            # Address mapping based on ToDS/FromDS flags
            to_ds = frame_control.get('to_ds', False)
            from_ds = frame_control.get('from_ds', False)
            
            if not to_ds and not from_ds:
                # IBSS (Ad-hoc) or AP to DS
                addresses['da'] = dot11.addr1
                addresses['sa'] = dot11.addr2
                addresses['bssid'] = dot11.addr3
                addresses['ra'] = dot11.addr1
                addresses['ta'] = dot11.addr2
            
            elif to_ds and not from_ds:
                # STA to AP
                addresses['ra'] = dot11.addr1
                addresses['ta'] = dot11.addr2
                addresses['bssid'] = dot11.addr1
                addresses['sa'] = dot11.addr2
                addresses['da'] = dot11.addr3
            
            elif not to_ds and from_ds:
                # AP to STA
                addresses['da'] = dot11.addr1
                addresses['ta'] = dot11.addr2
                addresses['bssid'] = dot11.addr2
                addresses['ra'] = dot11.addr1
                addresses['sa'] = dot11.addr3
            
            elif to_ds and from_ds:
                # WDS (Wireless Distribution System)
                addresses['ra'] = dot11.addr1
                addresses['ta'] = dot11.addr2
                addresses['da'] = dot11.addr3
                addresses['sa'] = dot11.addr4
            
            return addresses
        except Exception as e:
            logger.debug("Error extracting MAC addresses: %s", e)
        
        return {}


class ManagementFrameParser:
    """Parse 802.11 Management frames."""
    
    @staticmethod
    def parse_beacon(packet) -> Optional[Dict[str, Any]]:
        """Parse Beacon frame for SSID, rates, channel.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Beacon info dict or None
        """
        if not scapy or not packet or scapy.Dot11Beacon not in packet:
            return None
        
        try:
            beacon = packet[scapy.Dot11Beacon]
            info = {
                'ssid': None,
                'supported_rates': [],
                'extended_rates': [],
                'channel': None,
                'capabilities': None,
            }
            
            # Extract SSID
            if hasattr(beacon, 'info'):
                info['ssid'] = beacon.info.decode('utf-8', errors='ignore') if beacon.info else None
            
            # Extract capabilities
            if hasattr(beacon, 'cap'):
                cap = beacon.cap
                capabilities = []
                if cap & 0x0001:
                    capabilities.append('ESS')
                if cap & 0x0002:
                    capabilities.append('IBSS')
                if cap & 0x0004:
                    capabilities.append('CF-Pollable')
                if cap & 0x0008:
                    capabilities.append('CF-Poll-Request')
                if cap & 0x0010:
                    capabilities.append('Privacy')
                if cap & 0x0020:
                    capabilities.append('Short-Preamble')
                if cap & 0x0040:
                    capabilities.append('PBCC')
                if cap & 0x0080:
                    capabilities.append('Channel-Agility')
                if cap & 0x0100:
                    capabilities.append('Spectrum-Mgmt')
                if cap & 0x0200:
                    capabilities.append('QoS')
                if cap & 0x0400:
                    capabilities.append('Short-Slot')
                if cap & 0x0800:
                    capabilities.append('APSD')
                if cap & 0x1000:
                    capabilities.append('RM')
                if cap & 0x2000:
                    capabilities.append('DSSS-OFDM')
                if cap & 0x4000:
                    capabilities.append('Delayed-Block-Ack')
                if cap & 0x8000:
                    capabilities.append('Immediate-Block-Ack')
                info['capabilities'] = ', '.join(capabilities)
            
            # Extract supported rates
            if hasattr(beacon, 'rates'):
                info['supported_rates'] = [str(r) for r in beacon.rates]
            
            # Extract extended rates
            if hasattr(beacon, 'extended_rates'):
                info['extended_rates'] = [str(r) for r in beacon.extended_rates]
            
            # Extract channel from DS parameter set
            if hasattr(beacon, 'channel'):
                info['channel'] = beacon.channel
            
            return info
        except Exception as e:
            logger.debug("Error parsing beacon: %s", e)
        
        return None
    
    @staticmethod
    def parse_probe_request(packet) -> Optional[Dict[str, Any]]:
        """Parse Probe Request for SSID.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Probe request info dict or None
        """
        if not scapy or not packet or scapy.Dot11ProbeReq not in packet:
            return None
        
        try:
            probe = packet[scapy.Dot11ProbeReq]
            info = {
                'ssid': None,
            }
            
            if hasattr(probe, 'info'):
                info['ssid'] = probe.info.decode('utf-8', errors='ignore') if probe.info else None
            
            return info
        except Exception as e:
            logger.debug("Error parsing probe request: %s", e)
        
        return None
    
    @staticmethod
    def parse_probe_response(packet) -> Optional[Dict[str, Any]]:
        """Parse Probe Response (similar to beacon).
        
        Args:
            packet: Scapy packet
        
        Returns:
            Probe response info dict or None
        """
        if not scapy or not packet or scapy.Dot11ProbeResp not in packet:
            return None
        
        return ManagementFrameParser.parse_beacon(packet)


class SecurityParser:
    """Parse security information from 802.11 frames."""
    
    @staticmethod
    def parse_rsn(packet) -> Optional[Dict[str, Any]]:
        """Parse RSN Information Element for encryption details.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Security info dict or None
        """
        if not scapy or not packet:
            return None
        
        try:
            # Try to find RSN IE
            if hasattr(scapy, 'Dot11Elt') and scapy.Dot11Elt in packet:
                for elt in packet[scapy.Dot11Elt]:
                    if hasattr(elt, 'ID') and elt.ID == 48:  # RSN IE
                        security = {
                            'encryption_type': None,
                            'cipher_suite': None,
                            'akm_suite': None,
                            'version': None,
                        }
                        
                        # Try to extract RSN info
                        if hasattr(elt, 'info'):
                            # Parse RSN info (simplified)
                            info_bytes = bytes(elt.info)
                            if len(info_bytes) >= 8:
                                # Version (2 bytes)
                                security['version'] = int.from_bytes(info_bytes[0:2], 'little')
                                
                                # Group cipher (4 bytes OUI + 1 byte type)
                                if len(info_bytes) >= 8:
                                    group_cipher = int.from_bytes(info_bytes[2:6], 'little')
                                    security['cipher_suite'] = CIPHER_SUITES.get(group_cipher, f"Unknown (0x{group_cipher:08X})")
                                
                                # AKM suite (4 bytes OUI + 1 byte type)
                                if len(info_bytes) >= 14:
                                    akm_suite = int.from_bytes(info_bytes[8:12], 'little')
                                    security['akm_suite'] = AKM_SUITES.get(akm_suite, f"Unknown (0x{akm_suite:08X})")
                                    
                                    # Determine encryption type
                                    if security['akm_suite'] == 'PSK':
                                        security['encryption_type'] = 'WPA2-PSK'
                                    elif security['akm_suite'] == '802.1X':
                                        security['encryption_type'] = 'WPA2-Enterprise'
                                    elif security['akm_suite'] == 'SAE':
                                        security['encryption_type'] = 'WPA3'
                                    elif security['akm_suite'] == 'FT-SAE':
                                        security['encryption_type'] = 'WPA3-FT'
                        
                        return security if security['encryption_type'] else None
        except Exception as e:
            logger.debug("Error parsing RSN: %s", e)
        
        return None
    
    @staticmethod
    def detect_wps(packet) -> bool:
        """Detect if WPS is enabled via vendor-specific IE.
        
        Args:
            packet: Scapy packet
        
        Returns:
            True if WPS detected
        """
        if not scapy or not packet:
            return False
        
        try:
            if hasattr(scapy, 'Dot11Elt') and scapy.Dot11Elt in packet:
                for elt in packet[scapy.Dot11Elt]:
                    if hasattr(elt, 'ID') and elt.ID == 221:  # Vendor-specific
                        if hasattr(elt, 'info'):
                            info_bytes = bytes(elt.info)
                            # WPS OUI: 00:50:F2
                            if len(info_bytes) >= 4 and info_bytes[0:3] == b'\x00\x50\xf2':
                                if info_bytes[3] == 0x04:  # WPS type
                                    return True
        except Exception as e:
            logger.debug("Error detecting WPS: %s", e)
        
        return False


class WiFiIntelligence:
    """Main WiFi Intelligence engine combining all 802.11 analyzers."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        
        # Parsers
        self.radiotap_parser = RadiotapParser()
        self.frame_control_parser = FrameControlParser()
        self.mac_extractor = MACAddressExtractor()
        self.mgmt_parser = ManagementFrameParser()
        self.security_parser = SecurityParser()
        
        # State management
        self.bssid_to_ssid: Dict[str, str] = {}
        self.hidden_networks: Dict[str, Set[str]] = defaultdict(set)  # BSSID -> set of client MACs
        self.client_associations: Dict[str, str] = {}  # Client MAC -> BSSID
        
        logger.info("WiFi Intelligence module initialized")
    
    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process 802.11 packet for WiFi intelligence.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Analysis result dict or None
        """
        if not scapy or scapy.Dot11 not in packet:
            return None
        
        result = {}
        
        # Parse Radiotap metadata
        radiotap_info = self.radiotap_parser.parse_radiotap(packet)
        if radiotap_info:
            result['radiotap'] = radiotap_info
        
        # Parse frame control
        frame_control = self.frame_control_parser.parse_frame_control(packet)
        if frame_control:
            result['frame_control'] = frame_control
        
        # Extract MAC addresses
        if frame_control:
            addresses = self.mac_extractor.extract_addresses(packet, frame_control)
            result['addresses'] = addresses
            
            # Process based on frame type
            frame_type = frame_control.get('type')
            frame_subtype = frame_control.get('subtype')
            
            if frame_type == 'Management':
                self._process_management_frame(packet, frame_subtype, addresses, radiotap_info)
            elif frame_type == 'Data':
                self._process_data_frame(packet, addresses, radiotap_info)
        
        return result
    
    def _process_management_frame(
        self,
        packet,
        frame_subtype: Optional[str],
        addresses: Dict[str, Optional[str]],
        radiotap_info: Optional[Dict[str, Any]],
    ) -> None:
        """Process management frame.
        
        Args:
            packet: Scapy packet
            frame_subtype: Frame subtype
            addresses: MAC addresses
            radiotap_info: Radiotap metadata
        """
        bssid = addresses.get('bssid')
        transmitter_mac = addresses.get('ta')
        receiver_mac = addresses.get('ra')
        
        if not bssid:
            return
        
        # Log management frame
        if self.db_manager:
            try:
                self.db_manager.add_wifi_management_frame(
                    frame_type='Management',
                    frame_subtype=frame_subtype,
                    transmitter_mac=transmitter_mac,
                    receiver_mac=receiver_mac,
                    bssid=bssid,
                    rssi=radiotap_info.get('rssi') if radiotap_info else None,
                    channel=radiotap_info.get('channel') if radiotap_info else None,
                )
            except Exception as e:
                logger.debug("Error logging management frame: %s", e)
        
        # Process specific management frame types
        if frame_subtype == 'Beacon':
            self._process_beacon(packet, bssid, addresses, radiotap_info)
        elif frame_subtype == 'Probe Request':
            self._process_probe_request(packet, transmitter_mac, radiotap_info)
        elif frame_subtype == 'Probe Response':
            self._process_probe_response(packet, bssid, addresses, radiotap_info)
        elif frame_subtype in ('Association Request', 'Reassociation Request'):
            self._process_association_request(transmitter_mac, bssid)
        elif frame_subtype == 'Association Response':
            self._process_association_response(receiver_mac, bssid)
    
    def _process_beacon(
        self,
        packet,
        bssid: str,
        addresses: Dict[str, Optional[str]],
        radiotap_info: Optional[Dict[str, Any]],
    ) -> None:
        """Process Beacon frame.
        
        Args:
            packet: Scapy packet
            bssid: BSSID
            addresses: MAC addresses
            radiotap_info: Radiotap metadata
        """
        beacon_info = self.mgmt_parser.parse_beacon(packet)
        if not beacon_info:
            return
        
        ssid = beacon_info.get('ssid')
        
        # Update BSSID-to-SSID registry
        if ssid:
            self.bssid_to_ssid[bssid] = ssid
        else:
            # Hidden network
            self.hidden_networks[bssid].add(addresses.get('ra') or addresses.get('ta'))
        
        # Parse security info
        security_info = self.security_parser.parse_rsn(packet)
        wps_enabled = self.security_parser.detect_wps(packet)
        
        # Store access point
        if self.db_manager:
            try:
                self.db_manager.add_wifi_access_point(
                    bssid=bssid,
                    ssid=ssid,
                    channel=beacon_info.get('channel') or radiotap_info.get('channel') if radiotap_info else None,
                    frequency=radiotap_info.get('frequency') if radiotap_info else None,
                    rssi=radiotap_info.get('rssi') if radiotap_info else None,
                    data_rate=radiotap_info.get('data_rate') if radiotap_info else None,
                    encryption_type=security_info.get('encryption_type') if security_info else None,
                    cipher_suite=security_info.get('cipher_suite') if security_info else None,
                    akm_suite=security_info.get('akm_suite') if security_info else None,
                    wps_enabled=wps_enabled,
                    capabilities=beacon_info.get('capabilities'),
                )
            except Exception as e:
                logger.debug("Error storing access point: %s", e)
    
    def _process_probe_request(
        self,
        packet,
        client_mac: Optional[str],
        radiotap_info: Optional[Dict[str, Any]],
    ) -> None:
        """Process Probe Request frame.
        
        Args:
            packet: Scapy packet
            client_mac: Client MAC address
            radiotap_info: Radiotap metadata
        """
        if not client_mac:
            return
        
        probe_info = self.mgmt_parser.parse_probe_request(packet)
        if not probe_info:
            return
        
        ssid = probe_info.get('ssid')
        
        # Store client
        if self.db_manager:
            try:
                client_id = self.db_manager.add_wifi_client(client_mac)
                self.db_manager.add_wifi_probe_request(
                    client_mac=client_mac,
                    ssid=ssid,
                    rssi=radiotap_info.get('rssi') if radiotap_info else None,
                )
            except Exception as e:
                logger.debug("Error storing probe request: %s", e)
    
    def _process_probe_response(
        self,
        packet,
        bssid: str,
        addresses: Dict[str, Optional[str]],
        radiotap_info: Optional[Dict[str, Any]],
    ) -> None:
        """Process Probe Response frame.
        
        Args:
            packet: Scapy packet
            bssid: BSSID
            addresses: MAC addresses
            radiotap_info: Radiotap metadata
        """
        # Similar to beacon processing
        self._process_beacon(packet, bssid, addresses, radiotap_info)
    
    def _process_association_request(self, client_mac: Optional[str], bssid: str) -> None:
        """Process Association Request frame.
        
        Args:
            client_mac: Client MAC address
            bssid: BSSID
        """
        if not client_mac or not bssid:
            return
        
        self.client_associations[client_mac] = bssid
        
        # Resolve hidden network SSID if known
        if bssid in self.bssid_to_ssid:
            ssid = self.bssid_to_ssid[bssid]
            # Update AP with SSID if it was previously hidden
            if self.db_manager:
                try:
                    self.db_manager.add_wifi_access_point(bssid=bssid, ssid=ssid)
                except Exception as e:
                    logger.debug("Error updating hidden network: %s", e)
    
    def _process_association_response(self, client_mac: Optional[str], bssid: str) -> None:
        """Process Association Response frame.
        
        Args:
            client_mac: Client MAC address
            bssid: BSSID
        """
        if not client_mac or not bssid:
            return
        
        # Store association
        if self.db_manager:
            try:
                client_id = self.db_manager.add_wifi_client(client_mac)
                ap_id = self.db_manager.add_wifi_access_point(bssid=bssid)
                self.db_manager.add_wifi_association(
                    client_id=client_id,
                    ap_id=ap_id,
                    association_type='Associated',
                )
            except Exception as e:
                logger.debug("Error storing association: %s", e)
    
    def _process_data_frame(
        self,
        packet,
        addresses: Dict[str, Optional[str]],
        radiotap_info: Optional[Dict[str, Any]],
    ) -> None:
        """Process Data frame to track client-AP associations.
        
        Args:
            packet: Scapy packet
            addresses: MAC addresses
            radiotap_info: Radiotap metadata
        """
        bssid = addresses.get('bssid')
        transmitter_mac = addresses.get('ta')
        receiver_mac = addresses.get('ra')
        
        if not bssid or not transmitter_mac:
            return
        
        # Track client to AP association
        self.client_associations[transmitter_mac] = bssid
        
        # Store association
        if self.db_manager:
            try:
                client_id = self.db_manager.add_wifi_client(transmitter_mac)
                ap_id = self.db_manager.add_wifi_access_point(bssid=bssid)
                self.db_manager.add_wifi_association(
                    client_id=client_id,
                    ap_id=ap_id,
                    association_type='Data',
                )
            except Exception as e:
                logger.debug("Error storing data association: %s", e)
    
    def get_wifi_summary(self) -> Dict[str, Any]:
        """Get WiFi intelligence summary.
        
        Returns:
            Summary dict
        """
        summary = {
            'access_points': len(self.bssid_to_ssid),
            'hidden_networks': len(self.hidden_networks),
            'client_associations': len(self.client_associations),
        }
        
        if self.db_manager:
            try:
                summary['db_aps'] = len(self.db_manager.get_wifi_access_points())
                summary['db_clients'] = len(self.db_manager.get_wifi_clients())
                summary['db_associations'] = len(self.db_manager.get_wifi_associations())
            except Exception as e:
                logger.debug("Error getting WiFi summary: %s", e)
        
        return summary


if __name__ == "__main__":
    wifi = WiFiIntelligence()
    logger.info("WiFi Intelligence module initialized")
