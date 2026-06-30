"""
Device Fingerprinting Module - Milestone 5
Combines data from all milestones to identify manufacturer, device type, OS, and model
"""

import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

try:
    import scapy.all as scapy
except ImportError:
    scapy = None

logger = logging.getLogger(__name__)

# Confidence weights for different identification vectors
VECTOR_WEIGHTS = {
    'mdns_model_string': 0.95,      # High confidence - exact model string
    'dhcp_fingerprint': 0.85,       # High confidence - parameter list matching
    'http_user_agent': 0.80,        # High confidence - explicit UA string
    'tcp_stack': 0.60,              # Medium confidence - TTL/window size
    'mac_oui_category': 0.40,       # Low confidence - vendor only
    'netbios_name': 0.30,           # Low confidence - hostname only
}

# Device categories
DEVICE_CATEGORIES = {
    'Mobile': ['iPhone', 'Android', 'Phone', 'Mobile'],
    'Desktop': ['Desktop', 'Workstation', 'PC', 'Laptop', 'MacBook', 'Notebook'],
    'Tablet': ['iPad', 'Tablet', 'Kindle'],
    'IoT': ['IoT', 'Smart', 'Sensor', 'Camera', 'Thermostat', 'Switch', 'Bulb', 'Plug'],
    'Smart Home': ['HomePod', 'Echo', 'Alexa', 'Siri', 'Google', 'Nest'],
    'Network Infrastructure': ['Router', 'Switch', 'Access Point', 'AP', 'Gateway', 'Firewall'],
    'Server': ['Server', 'NAS', 'Storage'],
    'Printer': ['Printer', 'Scanner'],
    'Gaming': ['PlayStation', 'Xbox', 'Nintendo', 'Gaming'],
    'Wearable': ['Watch', 'Band', 'Fitness'],
    'TV': ['TV', 'Television', 'Roku', 'Apple TV', 'Chromecast', 'Fire TV'],
}

# Common DHCP Option 55 fingerprints (simplified)
DHCP_FINGERPRINTS = {
    '1,3,6,15,31,33,43,44,46,47,121,249,252': {'os_family': 'Windows', 'os_version': '10', 'confidence': 0.85},
    '1,3,6,15,31,33,43,44,46,47,121,249': {'os_family': 'Windows', 'os_version': '7/8', 'confidence': 0.80},
    '1,3,6,15,28,51,58,59,119': {'os_family': 'macOS', 'os_version': 'Unknown', 'confidence': 0.85},
    '1,3,6,12,15,28,42,58,59': {'os_family': 'iOS', 'os_version': 'Unknown', 'confidence': 0.85},
    '1,3,6,15,28,51,58,59': {'os_family': 'Linux', 'os_version': 'Unknown', 'confidence': 0.75},
    '1,3,6,12,15,17,28,42,58,59,119': {'os_family': 'Android', 'os_version': 'Unknown', 'confidence': 0.80},
}

# TCP TTL defaults by OS
TTL_DEFAULTS = {
    128: 'Windows',
    64: 'Linux/Android/macOS',
    255: 'Network Device',
    32: 'Windows 95/98',
    60: 'Some Linux variants',
}

# TCP window sizes by OS
WINDOW_SIZES = {
    8192: 'Windows',
    65535: 'Linux',
    5792: 'macOS',
    16384: 'Windows 10',
    64240: 'Windows 10',
}


class MACOUIDepthExpander:
    """Expand MAC OUI lookups to device categories."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.oui_cache: Dict[str, Dict[str, str]] = {}
    
    def get_oui_category(self, mac_address: str) -> Optional[Dict[str, str]]:
        """Get device category from MAC OUI.
        
        Args:
            mac_address: MAC address
        
        Returns:
            Category dict or None
        """
        # Extract OUI prefix (first 3 octets)
        oui_prefix = mac_address[:8].upper() if len(mac_address) >= 8 else None
        if not oui_prefix:
            return None
        
        # Check cache
        if oui_prefix in self.oui_cache:
            return self.oui_cache[oui_prefix]
        
        # Check database
        if self.db_manager:
            category = self.db_manager.get_mac_oui_category(oui_prefix)
            if category:
                self.oui_cache[oui_prefix] = {
                    'vendor': category['vendor'],
                    'device_category': category['device_category'],
                    'device_subcategory': category['device_subcategory'],
                }
                return self.oui_cache[oui_prefix]
        
        # Default vendor-specific mappings (simplified)
        vendor_mappings = {
            '00:1B:63': {'vendor': 'Apple', 'device_category': 'Mobile/Desktop/Tablet'},
            '00:1F:F3': {'vendor': 'Apple', 'device_category': 'Mobile/Desktop/Tablet'},
            'A4:D1:D2': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'F8:FF:C2': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'BC:D1:D3': {'vendor': 'Apple', 'device_category': 'Mobile'},
            '3C:D9:2B': {'vendor': 'Apple', 'device_category': 'Mobile'},
            '40:33:C3': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'AC:87:A3': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'D4:61:9E': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'E8:50:8B': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'F0:18:98': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'F8:1C:6D': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'CC:20:E8': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'DC:A9:04': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'E4:CE:C5': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'E0:AC:CB': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'E4:AA:5D': {'vendor': 'Apple', 'device_category': 'Mobile'},
            'FC:E9:98': {'vendor': 'Apple', 'device_category': 'Mobile'},
            '00:0C:29': {'vendor': 'VMware', 'device_category': 'Virtual Machine'},
            '00:05:69': {'vendor': 'VMware', 'device_category': 'Virtual Machine'},
            '00:50:56': {'vendor': 'VMware', 'device_category': 'Virtual Machine'},
            '08:00:27': {'vendor': 'VirtualBox', 'device_category': 'Virtual Machine'},
            '52:54:00': {'vendor': 'QEMU', 'device_category': 'Virtual Machine'},
        }
        
        if oui_prefix in vendor_mappings:
            self.oui_cache[oui_prefix] = vendor_mappings[oui_prefix]
            return self.oui_cache[oui_prefix]
        
        return None


class DHCPFingerprintEngine:
    """Match DHCP Option 55 parameter lists to operating systems."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
    
    def match_fingerprint(self, parameter_list: List[int]) -> Optional[Dict[str, Any]]:
        """Match DHCP parameter list to OS fingerprint.
        
        Args:
            parameter_list: List of DHCP parameter codes
        
        Returns:
            Fingerprint dict or None
        """
        if not parameter_list:
            return None
        
        # Convert to comma-separated string
        param_str = ','.join(map(str, sorted(parameter_list)))
        
        # Check database
        if self.db_manager:
            fingerprint = self.db_manager.get_dhcp_fingerprint(param_str)
            if fingerprint:
                return {
                    'os_family': fingerprint['os_family'],
                    'os_version': fingerprint['os_version'],
                    'confidence': fingerprint['confidence'],
                    'source': fingerprint['source'],
                }
        
        # Check built-in fingerprints
        if param_str in DHCP_FINGERPRINTS:
            return DHCP_FINGERPRINTS[param_str]
        
        return None
    
    def add_fingerprint(
        self,
        parameter_list: List[int],
        os_family: str,
        os_version: Optional[str] = None,
        confidence: float = 0.0,
        source: Optional[str] = None,
    ) -> None:
        """Add DHCP fingerprint to database.
        
        Args:
            parameter_list: List of DHCP parameter codes
            os_family: OS family
            os_version: OS version
            confidence: Confidence score
            source: Source of fingerprint
        """
        if not self.db_manager:
            return
        
        param_str = ','.join(map(str, sorted(parameter_list)))
        self.db_manager.add_dhcp_fingerprint(param_str, os_family, os_version, confidence, source)


class HTTPUserAgentParser:
    """Parse HTTP User-Agent strings for device identification."""
    
    @staticmethod
    def parse_user_agent(user_agent: str) -> Dict[str, Optional[str]]:
        """Parse User-Agent string.
        
        Args:
            user_agent: User-Agent string
        
        Returns:
            Parsed info dict
        """
        info = {
            'os_family': None,
            'os_version': None,
            'browser': None,
            'device_type': None,
        }
        
        ua_lower = user_agent.lower()
        
        # Detect OS family
        if 'windows' in ua_lower:
            info['os_family'] = 'Windows'
            if 'windows nt 10.0' in ua_lower:
                info['os_version'] = '10'
            elif 'windows nt 6.3' in ua_lower:
                info['os_version'] = '8.1'
            elif 'windows nt 6.2' in ua_lower:
                info['os_version'] = '8'
            elif 'windows nt 6.1' in ua_lower:
                info['os_version'] = '7'
        elif 'mac os x' in ua_lower or 'macos' in ua_lower:
            info['os_family'] = 'macOS'
            # Extract version
            match = re.search(r'mac os x (\d+[._]\d+)', ua_lower)
            if match:
                info['os_version'] = match.group(1).replace('_', '.')
        elif 'android' in ua_lower:
            info['os_family'] = 'Android'
            info['device_type'] = 'Mobile'
            match = re.search(r'android (\d+[.\d]*)', ua_lower)
            if match:
                info['os_version'] = match.group(1)
        elif 'iphone' in ua_lower or 'ipad' in ua_lower:
            info['os_family'] = 'iOS'
            info['device_type'] = 'Mobile' if 'iphone' in ua_lower else 'Tablet'
            match = re.search(r'os (\d+[._]\d+)', ua_lower)
            if match:
                info['os_version'] = match.group(1).replace('_', '.')
        elif 'linux' in ua_lower:
            info['os_family'] = 'Linux'
        
        # Detect browser
        if 'chrome' in ua_lower:
            info['browser'] = 'Chrome'
        elif 'firefox' in ua_lower:
            info['browser'] = 'Firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            info['browser'] = 'Safari'
        elif 'edge' in ua_lower:
            info['browser'] = 'Edge'
        
        return info


class mDNSModelStringParser:
    """Parse mDNS/Bonjour TXT records for device model information."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
    
    def parse_model_string(self, txt_records: Dict[str, str]) -> Optional[Dict[str, str]]:
        """Parse mDNS TXT records for model information.
        
        Args:
            txt_records: Dict of TXT record key-value pairs
        
        Returns:
            Model info dict or None
        """
        model_info = {}
        
        # Common mDNS model string patterns
        if 'model' in txt_records:
            model = txt_records['model']
            model_info['device_model'] = model
            
            # Apple device patterns
            if 'MacBook' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Desktop'
            elif 'Macmini' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Desktop'
            elif 'iMac' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Desktop'
            elif 'iPhone' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Mobile'
            elif 'iPad' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Tablet'
            elif 'AppleTV' in model or 'Apple TV' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'TV'
            elif 'HomePod' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Smart Home'
            elif 'Watch' in model:
                model_info['manufacturer'] = 'Apple'
                model_info['device_type'] = 'Wearable'
        
        # Amazon devices
        if 'amzn' in txt_records.get('manufacturer', '').lower():
            model_info['manufacturer'] = 'Amazon'
            if 'kindle' in str(txt_records).lower():
                model_info['device_type'] = 'Tablet'
            elif 'echo' in str(txt_records).lower():
                model_info['device_type'] = 'Smart Home'
        
        # Google devices
        if 'google' in txt_records.get('manufacturer', '').lower():
            model_info['manufacturer'] = 'Google'
            if 'chromecast' in str(txt_records).lower():
                model_info['device_type'] = 'TV'
            elif 'nest' in str(txt_records).lower():
                model_info['device_type'] = 'Smart Home'
        
        # Check database for model string
        for key, value in txt_records.items():
            if self.db_manager:
                model_mapping = self.db_manager.get_mdns_model_string(value)
                if model_mapping:
                    model_info.update({
                        'manufacturer': model_mapping['manufacturer'],
                        'device_model': model_mapping['device_model'],
                        'device_type': model_mapping['device_type'],
                    })
        
        return model_info if model_info else None


class TCPStackFingerprint:
    """Analyze TCP/IP stack characteristics for OS identification."""
    
    @staticmethod
    def analyze_packet(packet) -> Optional[Dict[str, Any]]:
        """Analyze TCP packet for stack fingerprinting.
        
        Args:
            packet: Scapy packet
        
        Returns:
            Fingerprint dict or None
        """
        if not scapy or not packet or scapy.TCP not in packet:
            return None
        
        try:
            tcp = packet[scapy.TCP]
            ip = packet[scapy.IP] if scapy.IP in packet else None
            
            fingerprint = {
                'ttl': ip.ttl if ip else None,
                'window_size': tcp.window,
                'os_family': None,
                'confidence': 0.0,
            }
            
            # TTL analysis
            if fingerprint['ttl']:
                fingerprint['os_family'] = TTL_DEFAULTS.get(fingerprint['ttl'])
                fingerprint['confidence'] = 0.60
            
            # Window size analysis
            if fingerprint['window_size']:
                window_os = WINDOW_SIZES.get(fingerprint['window_size'])
                if window_os:
                    if fingerprint['os_family']:
                        # Cross-reference TTL and window
                        if window_os == fingerprint['os_family']:
                            fingerprint['confidence'] = 0.75
                        else:
                            # Conflict, use window size (more specific)
                            fingerprint['os_family'] = window_os
                            fingerprint['confidence'] = 0.55
                    else:
                        fingerprint['os_family'] = window_os
                        fingerprint['confidence'] = 0.55
            
            return fingerprint if fingerprint['os_family'] else None
        except Exception as e:
            logger.debug("Error analyzing TCP stack: %s", e)
        
        return None


class ConfidenceScoringFramework:
    """Calculate confidence scores for device identification."""
    
    @staticmethod
    def calculate_score(vectors: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall confidence score from multiple vectors.
        
        Args:
            vectors: Dict of identification vectors
        
        Returns:
            Scored result dict
        """
        total_weight = 0.0
        weighted_confidence = 0.0
        
        results = {
            'manufacturer': None,
            'device_type': None,
            'device_model': None,
            'operating_system': None,
            'os_version': None,
            'confidence_score': 0.0,
            'vectors_used': [],
        }
        
        for vector_name, vector_data in vectors.items():
            if not vector_data:
                continue
            
            weight = VECTOR_WEIGHTS.get(vector_name, 0.5)
            confidence = vector_data.get('confidence', 0.5)
            
            total_weight += weight
            weighted_confidence += weight * confidence
            results['vectors_used'].append(vector_name)
            
            # Extract identification data
            if 'manufacturer' in vector_data and vector_data['manufacturer']:
                results['manufacturer'] = vector_data['manufacturer']
            if 'device_type' in vector_data and vector_data['device_type']:
                results['device_type'] = vector_data['device_type']
            if 'device_model' in vector_data and vector_data['device_model']:
                results['device_model'] = vector_data['device_model']
            if 'os_family' in vector_data and vector_data['os_family']:
                results['operating_system'] = vector_data['os_family']
            if 'os_version' in vector_data and vector_data['os_version']:
                results['os_version'] = vector_data['os_version']
        
        if total_weight > 0:
            results['confidence_score'] = weighted_confidence / total_weight
        
        return results


class DeviceCategorizer:
    """Categorize devices into functional categories."""
    
    @staticmethod
    def categorize_device(fingerprint: Dict[str, Any]) -> str:
        """Categorize device based on fingerprint data.
        
        Args:
            fingerprint: Device fingerprint dict
        
        Returns:
            Device category
        """
        # Check explicit device type
        if fingerprint.get('device_type'):
            device_type = fingerprint['device_type'].lower()
            for category, keywords in DEVICE_CATEGORIES.items():
                if any(keyword.lower() in device_type for keyword in keywords):
                    return category
        
        # Check device model
        if fingerprint.get('device_model'):
            model = fingerprint['device_model'].lower()
            for category, keywords in DEVICE_CATEGORIES.items():
                if any(keyword.lower() in model for keyword in keywords):
                    return category
        
        # Check manufacturer
        if fingerprint.get('manufacturer'):
            manufacturer = fingerprint['manufacturer'].lower()
            if 'apple' in manufacturer and fingerprint.get('device_type'):
                # Apple-specific categorization
                if 'iphone' in fingerprint['device_type'].lower():
                    return 'Mobile'
                elif 'ipad' in fingerprint['device_type'].lower():
                    return 'Tablet'
                elif 'watch' in fingerprint['device_type'].lower():
                    return 'Wearable'
        
        # Check OS
        if fingerprint.get('operating_system'):
            os = fingerprint['operating_system'].lower()
            if 'android' in os:
                return 'Mobile'
            elif 'ios' in os:
                return 'Mobile'
        
        return 'Unknown'


class DeviceFingerprinting:
    """Main Device Fingerprinting engine combining all analyzers."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        
        # Analyzers
        self.oui_expander = MACOUIDepthExpander(db_manager)
        self.dhcp_fingerprinter = DHCPFingerprintEngine(db_manager)
        self.ua_parser = HTTPUserAgentParser()
        self.mdns_parser = mDNSModelStringParser(db_manager)
        self.tcp_fingerprinter = TCPStackFingerprint()
        self.confidence_scoring = ConfidenceScoringFramework()
        self.categorizer = DeviceCategorizer()
        
        # Device fingerprint cache
        self.device_fingerprints: Dict[int, Dict[str, Any]] = {}
        
        logger.info("Device Fingerprinting module initialized")
    
    def analyze_device(
        self,
        device_id: int,
        mac_address: str,
        dhcp_options: Optional[List[int]] = None,
        user_agent: Optional[str] = None,
        mdns_txt_records: Optional[Dict[str, str]] = None,
        tcp_packet=None,
        netbios_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze device using all available vectors.
        
        Args:
            device_id: Device ID
            mac_address: MAC address
            dhcp_options: DHCP Option 55 parameter list
            user_agent: HTTP User-Agent string
            mdns_txt_records: mDNS TXT records
            tcp_packet: TCP packet for stack analysis
            netbios_name: NetBIOS name
        
        Returns:
            Fingerprint result dict
        """
        vectors = {}
        
        # MAC OUI analysis
        oui_category = self.oui_expander.get_oui_category(mac_address)
        if oui_category:
            vectors['mac_oui_category'] = {
                'manufacturer': oui_category.get('vendor'),
                'device_type': oui_category.get('device_category'),
                'confidence': VECTOR_WEIGHTS['mac_oui_category'],
            }
        
        # DHCP fingerprint analysis
        if dhcp_options:
            dhcp_fp = self.dhcp_fingerprinter.match_fingerprint(dhcp_options)
            if dhcp_fp:
                vectors['dhcp_fingerprint'] = dhcp_fp
                vectors['dhcp_fingerprint']['confidence'] = dhcp_fp.get('confidence', VECTOR_WEIGHTS['dhcp_fingerprint'])
        
        # HTTP User-Agent analysis
        if user_agent:
            ua_info = self.ua_parser.parse_user_agent(user_agent)
            if ua_info.get('os_family') or ua_info.get('device_type'):
                vectors['http_user_agent'] = {
                    'os_family': ua_info.get('os_family'),
                    'os_version': ua_info.get('os_version'),
                    'device_type': ua_info.get('device_type'),
                    'confidence': VECTOR_WEIGHTS['http_user_agent'],
                }
        
        # mDNS model string analysis
        if mdns_txt_records:
            mdns_info = self.mdns_parser.parse_model_string(mdns_txt_records)
            if mdns_info:
                vectors['mdns_model_string'] = {
                    'manufacturer': mdns_info.get('manufacturer'),
                    'device_model': mdns_info.get('device_model'),
                    'device_type': mdns_info.get('device_type'),
                    'confidence': VECTOR_WEIGHTS['mdns_model_string'],
                }
        
        # TCP stack analysis
        if tcp_packet:
            tcp_fp = self.tcp_fingerprinter.analyze_packet(tcp_packet)
            if tcp_fp:
                vectors['tcp_stack'] = tcp_fp
        
        # NetBIOS name analysis (low confidence)
        if netbios_name:
            vectors['netbios_name'] = {
                'hostname': netbios_name,
                'confidence': VECTOR_WEIGHTS['netbios_name'],
            }
        
        # Calculate confidence score
        result = self.confidence_scoring.calculate_score(vectors)
        
        # Categorize device
        result['device_category'] = self.categorizer.categorize_device(result)
        
        # Store in database
        if self.db_manager:
            try:
                self.db_manager.add_device_fingerprint(
                    device_id=device_id,
                    manufacturer=result.get('manufacturer'),
                    device_type=result.get('device_type'),
                    device_model=result.get('device_model'),
                    operating_system=result.get('operating_system'),
                    os_version=result.get('os_version'),
                    confidence_score=result['confidence_score'],
                )
            except Exception as e:
                logger.debug("Error storing device fingerprint: %s", e)
        
        # Cache result
        self.device_fingerprints[device_id] = result
        
        return result
    
    def get_device_fingerprint(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get device fingerprint from cache or database.
        
        Args:
            device_id: Device ID
        
        Returns:
            Fingerprint dict or None
        """
        # Check cache
        if device_id in self.device_fingerprints:
            return self.device_fingerprints[device_id]
        
        # Check database
        if self.db_manager:
            fingerprint = self.db_manager.get_device_fingerprint(device_id)
            if fingerprint:
                self.device_fingerprints[device_id] = dict(fingerprint)
                return self.device_fingerprints[device_id]
        
        return None
    
    def get_all_fingerprints(self) -> Dict[int, Dict[str, Any]]:
        """Get all device fingerprints.
        
        Returns:
            Dict of device_id -> fingerprint
        """
        if self.db_manager:
            try:
                conn = self.db_manager.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM device_fingerprints")
                rows = cursor.fetchall()
                conn.close()
                
                for row in rows:
                    fp = dict(row)
                    device_id = fp['device_id']
                    self.device_fingerprints[device_id] = fp
            except Exception as e:
                logger.debug("Error getting all fingerprints: %s", e)
        
        return self.device_fingerprints


if __name__ == "__main__":
    df = DeviceFingerprinting()
    logger.info("Device Fingerprinting module initialized")
