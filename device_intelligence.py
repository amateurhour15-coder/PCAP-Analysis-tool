"""
Device Intelligence Module - Milestone 2
Analyzes DHCP, DNS, NetBIOS, and mDNS protocols for device discovery and identification
"""

import struct
from collections import defaultdict
from datetime import datetime


class DHCPAnalyzer:
    """Analyzes DHCP packets for device information"""
    
    DHCP_MESSAGE_TYPES = {
        1: 'DISCOVER',
        2: 'OFFER',
        3: 'REQUEST',
        4: 'DECLINE',
        5: 'ACK',
        6: 'NAK',
        7: 'RELEASE',
        8: 'INFORM'
    }
    
    def __init__(self):
        self.devices = defaultdict(dict)
        self.dhcp_transactions = {}
    
    def parse_dhcp_packet(self, packet_data):
        """Parse DHCP packet and extract device information"""
        try:
            if len(packet_data) < 240:
                return None
            
            # Parse DHCP header
            op = packet_data[0]
            htype = packet_data[1]
            hlen = packet_data[2]
            hops = packet_data[3]
            xid = struct.unpack('!I', packet_data[4:8])[0]
            secs = struct.unpack('!H', packet_data[8:10])[0]
            flags = struct.unpack('!H', packet_data[10:12])[0]
            ciaddr = self._parse_ip(packet_data[12:16])
            yiaddr = self._parse_ip(packet_data[16:20])
            siaddr = self._parse_ip(packet_data[20:24])
            giaddr = self._parse_ip(packet_data[24:28])
            chaddr = packet_data[28:44].hex().upper()
            
            dhcp_info = {
                'transaction_id': xid,
                'client_ip': ciaddr,
                'assigned_ip': yiaddr,
                'server_ip': siaddr,
                'gateway_ip': giaddr,
                'client_mac': chaddr,
                'operation': 'REQUEST' if op == 1 else 'REPLY',
                'timestamp': datetime.now().isoformat()
            }
            
            # Parse DHCP options
            options = self._parse_dhcp_options(packet_data[240:])
            dhcp_info.update(options)
            
            return dhcp_info
        except Exception as e:
            print(f"Error parsing DHCP packet: {e}")
            return None
    
    def _parse_dhcp_options(self, options_data):
        """Parse DHCP options field"""
        options = {}
        offset = 0
        
        while offset < len(options_data) - 2:
            option_type = options_data[offset]
            
            if option_type == 255:  # End option
                break
            
            if option_type == 0:  # Padding
                offset += 1
                continue
            
            length = options_data[offset + 1]
            option_value = options_data[offset + 2:offset + 2 + length]
            
            if option_type == 53:  # DHCP Message Type
                msg_type = option_value[0]
                options['message_type'] = self.DHCP_MESSAGE_TYPES.get(msg_type, 'UNKNOWN')
            elif option_type == 60:  # Vendor Class Identifier
                options['vendor_class'] = option_value.decode('utf-8', errors='ignore')
            elif option_type == 61:  # Client Identifier
                options['client_id'] = option_value.hex().upper()
            elif option_type == 12:  # Host Name
                options['hostname'] = option_value.decode('utf-8', errors='ignore')
            
            offset += 2 + length
        
        return options
    
    def _parse_ip(self, ip_bytes):
        """Convert IP bytes to string format"""
        return '.'.join(map(str, ip_bytes))
    
    def get_device_list(self):
        """Return discovered devices from DHCP"""
        return self.devices


class DNSAnalyzer:
    """Analyzes DNS packets for device and service discovery"""
    
    RECORD_TYPES = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        255: 'ANY'
    }
    
    def __init__(self):
        self.dns_records = defaultdict(list)
        self.device_hostnames = {}
    
    def parse_dns_packet(self, packet_data):
        """Parse DNS packet and extract device information"""
        try:
            if len(packet_data) < 12:
                return None
            
            transaction_id = struct.unpack('!H', packet_data[0:2])[0]
            flags = struct.unpack('!H', packet_data[2:4])[0]
            questions = struct.unpack('!H', packet_data[4:6])[0]
            answers = struct.unpack('!H', packet_data[6:8])[0]
            
            dns_info = {
                'transaction_id': transaction_id,
                'is_response': bool(flags & 0x8000),
                'questions_count': questions,
                'answers_count': answers,
                'queries': [],
                'responses': [],
                'timestamp': datetime.now().isoformat()
            }
            
            offset = 12
            
            # Parse queries
            for _ in range(questions):
                query, offset = self._parse_dns_name(packet_data, offset)
                qtype = struct.unpack('!H', packet_data[offset:offset+2])[0]
                qclass = struct.unpack('!H', packet_data[offset+2:offset+4])[0]
                dns_info['queries'].append({
                    'name': query,
                    'type': self.RECORD_TYPES.get(qtype, str(qtype)),
                    'class': qclass
                })
                offset += 4
            
            # Parse answers
            for _ in range(answers):
                name, offset = self._parse_dns_name(packet_data, offset)
                rtype = struct.unpack('!H', packet_data[offset:offset+2])[0]
                rclass = struct.unpack('!H', packet_data[offset+2:offset+4])[0]
                ttl = struct.unpack('!I', packet_data[offset+4:offset+8])[0]
                rdlen = struct.unpack('!H', packet_data[offset+8:offset+10])[0]
                rdata = packet_data[offset+10:offset+10+rdlen]
                
                dns_info['responses'].append({
                    'name': name,
                    'type': self.RECORD_TYPES.get(rtype, str(rtype)),
                    'ttl': ttl,
                    'data': self._parse_rdata(rtype, rdata)
                })
                
                offset += 10 + rdlen
            
            return dns_info
        except Exception as e:
            print(f"Error parsing DNS packet: {e}")
            return None
    
    def _parse_dns_name(self, packet_data, offset):
        """Parse DNS name from packet"""
        name = []
        
        while True:
            length = packet_data[offset]
            offset += 1
            
            if length == 0:
                break
            
            if length & 0xc0:  # Pointer
                pointer = struct.unpack('!H', bytes([(length & 0x3f), packet_data[offset]]))[0]
                offset += 1
                # Follow pointer
                _, sub_name = self._parse_dns_name(packet_data, pointer)
                name.append(sub_name)
                break
            else:
                name.append(packet_data[offset:offset+length].decode('utf-8', errors='ignore'))
                offset += length
        
        return '.'.join(name), offset
    
    def _parse_rdata(self, rtype, rdata):
        """Parse DNS resource data based on type"""
        if rtype == 1:  # A record
            return '.'.join(map(str, rdata))
        elif rtype == 28:  # AAAA record
            return ':'.join(f'{int.from_bytes(rdata[i:i+2], "big"):x}' for i in range(0, 16, 2))
        elif rtype == 16:  # TXT record
            return rdata.decode('utf-8', errors='ignore')
        else:
            return rdata.hex().upper()
    
    def get_discovered_devices(self):
        """Return discovered devices from DNS"""
        return self.device_hostnames


class NetBIOSAnalyzer:
    """Analyzes NetBIOS packets for device discovery"""
    
    def __init__(self):
        self.netbios_names = {}
        self.workgroups = defaultdict(list)
    
    def parse_netbios_packet(self, packet_data):
        """Parse NetBIOS name query/response"""
        try:
            netbios_info = {
                'timestamp': datetime.now().isoformat(),
                'names': [],
                'workgroups': []
            }
            
            # NetBIOS Name Service header (simplified)
            if len(packet_data) >= 12:
                name_trn_id = struct.unpack('!H', packet_data[0:2])[0]
                flags = struct.unpack('!H', packet_data[2:4])[0]
                
                netbios_info['transaction_id'] = name_trn_id
                netbios_info['is_response'] = bool(flags & 0x8000)
                netbios_info['is_authoritative'] = bool(flags & 0x0400)
            
            return netbios_info
        except Exception as e:
            print(f"Error parsing NetBIOS packet: {e}")
            return None
    
    def get_netbios_devices(self):
        """Return discovered NetBIOS devices"""
        return self.netbios_names


class mDNSAnalyzer:
    """Analyzes mDNS (Multicast DNS) packets for device discovery"""
    
    def __init__(self):
        self.mdns_services = defaultdict(list)
        self.mdns_devices = {}
    
    def parse_mdns_packet(self, packet_data):
        """Parse mDNS packet and extract service information"""
        try:
            if len(packet_data) < 12:
                return None
            
            transaction_id = struct.unpack('!H', packet_data[0:2])[0]
            flags = struct.unpack('!H', packet_data[2:4])[0]
            questions = struct.unpack('!H', packet_data[4:6])[0]
            answers = struct.unpack('!H', packet_data[6:8])[0]
            
            mdns_info = {
                'transaction_id': transaction_id,
                'is_response': bool(flags & 0x8000),
                'questions_count': questions,
                'answers_count': answers,
                'services': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Parse mDNS records (similar to DNS but with multicast semantics)
            offset = 12
            
            # Parse questions
            for _ in range(questions):
                # Parse service name
                name = ""
                while offset < len(packet_data):
                    length = packet_data[offset]
                    offset += 1
                    if length == 0:
                        break
                    name += packet_data[offset:offset+length].decode('utf-8', errors='ignore') + '.'
                    offset += length
                
                if offset + 4 <= len(packet_data):
                    qtype = struct.unpack('!H', packet_data[offset:offset+2])[0]
                    qclass = struct.unpack('!H', packet_data[offset+2:offset+4])[0]
                    offset += 4
                    
                    mdns_info['services'].append({
                        'service': name.rstrip('.'),
                        'type': qtype,
                        'class': qclass
                    })
            
            return mdns_info
        except Exception as e:
            print(f"Error parsing mDNS packet: {e}")
            return None
    
    def get_mdns_services(self):
        """Return discovered mDNS services"""
        return self.mdns_services


class DeviceIntelligence:
    """Main Device Intelligence engine combining all protocol analyzers"""
    
    def __init__(self):
        self.dhcp_analyzer = DHCPAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.netbios_analyzer = NetBIOSAnalyzer()
        self.mdns_analyzer = mDNSAnalyzer()
        self.discovered_devices = {}
    
    def analyze_packet(self, packet, protocol):
        """Analyze packet based on protocol type"""
        protocol = protocol.upper()
        
        if protocol == 'DHCP':
            return self.dhcp_analyzer.parse_dhcp_packet(packet)
        elif protocol == 'DNS':
            return self.dns_analyzer.parse_dns_packet(packet)
        elif protocol == 'NETBIOS':
            return self.netbios_analyzer.parse_netbios_packet(packet)
        elif protocol == 'MDNS':
            return self.mdns_analyzer.parse_mdns_packet(packet)
        else:
            print(f"Unknown protocol: {protocol}")
            return None
    
    def get_device_summary(self):
        """Generate summary of all discovered devices"""
        summary = {
            'dhcp_devices': self.dhcp_analyzer.get_device_list(),
            'dns_devices': self.dns_analyzer.get_discovered_devices(),
            'netbios_devices': self.netbios_analyzer.get_netbios_devices(),
            'mdns_services': self.mdns_analyzer.get_mdns_services(),
            'total_devices': len(self.discovered_devices)
        }
        return summary
    
    def correlate_device_info(self):
        """Correlate device information across protocols"""
        correlated = {}
        
        # Correlate DHCP with DNS and NetBIOS
        for mac, dhcp_info in self.dhcp_analyzer.devices.items():
            if 'hostname' in dhcp_info:
                correlated[dhcp_info['hostname']] = {
                    'mac_address': mac,
                    'dhcp_info': dhcp_info,
                    'dns_records': self.dns_analyzer.device_hostnames.get(dhcp_info['hostname']),
                    'netbios_info': self.netbios_analyzer.netbios_names.get(dhcp_info['hostname'])
                }
        
        return correlated


if __name__ == "__main__":
    # Example usage
    print("Device Intelligence Module - Milestone 2")
    print("Protocols: DHCP, DNS, NetBIOS, mDNS")
    
    di = DeviceIntelligence()
    print("Initialized Device Intelligence analyzer")
    print(f"Available analyzers: DHCP, DNS, NetBIOS, mDNS")
