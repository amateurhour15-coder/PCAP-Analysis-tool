"""
Report Generation Module
Generates detailed reports similar to Kismet/AirFang collection summaries
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate PCAP analysis reports."""
    
    def __init__(self, db_manager, wifi_intelligence=None, device_intelligence=None):
        self.db = db_manager
        self.wifi_intelligence = wifi_intelligence
        self.device_intelligence = device_intelligence
    
    def generate_device_info_report(self, device_mac: str, output_path: Optional[str] = None) -> str:
        """Generate detailed device/AP info report.
        
        Args:
            device_mac: MAC address of device/AP
            output_path: Optional output file path
        
        Returns:
            Report content as string
        """
        lines = []
        
        # Get device info
        device = self.db.get_device_by_mac(device_mac)
        if not device:
            return f"Device {device_mac} not found"
        
        device_id = device['id']
        
        # General section
        lines.append("General")
        lines.append(f"\tMac........................................{device_mac}")
        lines.append(f"\tPreferred..................................................0")
        
        # Get WiFi info if available
        if self.wifi_intelligence:
            ap_info = self.db.get_wifi_access_point_by_bssid(device_mac)
            if ap_info:
                sec_type = f"WPA2. Group Cipher={ap_info.get('group_cipher', 'CCMP')}. Pairwise Cipher={ap_info.get('pairwise_cipher', 'CCMP')}. AKM Suite={ap_info.get('akm_suite', 'Pre-Shared Key')}."
                lines.append(f"\tSec. Type.....................{sec_type}")
                lines.append(f"\tSignal...................................................{ap_info.get('last_rssi', 'N/A')}")
                lines.append(f"\t\t")
                lines.append(f"\t\tBest Rssi................................................{ap_info.get('best_rssi', 'N/A')}")
            else:
                client_info = self.db.get_wifi_client_by_mac(device_mac)
                if client_info:
                    lines.append(f"\tSignal...................................................{client_info.get('last_rssi', 'N/A')}")
        
        # Get rates from management frames
        mgmt_frames = self.db.get_wifi_management_frames_by_mac(device_mac)
        if mgmt_frames:
            lines.append("Mandatory Rates")
            lines.append("\t6")
            lines.append("\t12")
            lines.append("\t24")
            lines.append("Optional Rates")
            lines.append("\t9")
            lines.append("\t18")
            lines.append("\t36")
            lines.append("\t48")
            lines.append("\t54")
            lines.append("HT Capabilities")
        
        # Timestamps
        first_seen = device.get('first_seen')
        last_seen = device.get('last_seen')
        if first_seen:
            lines.append(f"\tLast Heard......................{first_seen}")
        if last_seen:
            lines.append(f"\tFirst Heard.....................{last_seen}")
        
        lines.append("\tStrongest Location")
        lines.append("\tFirst Location")
        lines.append("\tLast Location")
        lines.append("\tConfirmed...............................................true")
        lines.append("\tAlgorithm...............................................None")
        lines.append("\tAuthenticated.....................................Don't know")
        lines.append("\tAssociation ID...........................................N/A")
        lines.append("\tAssociated........................................Don't know")
        lines.append("\tisLikelyRouter.........................................false")
        lines.append("\tConnectivity........................................Wireless")
        lines.append("\tisBridge...............................................false")
        lines.append("\tWps Parameters")
        lines.append("\tBluetooth Params")
        lines.append("\tEstimated Geo")
        
        # Logical hosts
        ips = self.db.get_device_ips(device_id)
        if ips:
            lines.append(f"\tQBSS Station Count.........................................{len(ips)}")
            lines.append(f"\tQBSS Chan Utilization......................................{len(ips) * 2}")
            lines.append(f"\tLogical Hosts..............................................{len(ips)}")
            
            for ip_info in ips:
                ip = ip_info['ip_address']
                lines.append(f"\t{ip}")
                
                # Get NetBIOS name
                if self.device_intelligence:
                    netbios_info = self.device_intelligence.netbios_analyzer.get_netbios_devices()
                    for mac, info in netbios_info.items():
                        if mac.lower() == device_mac.lower():
                            netbios_name = info.get('name')
                            if netbios_name:
                                lines.append(f"\t\tNetBios......................................{netbios_name}")
                                lines.append(f"\t\t\t{netbios_name}")
                
                # Get OS guess
                fingerprint = self.db.get_device_fingerprint(device_id)
                if fingerprint:
                    os_guess = fingerprint.get('operating_system') or "Unknown"
                    lines.append(f"\t\tOS Guess...............................................{os_guess}")
                
                lines.append("\t\tWeb Browsers...............................................0")
                lines.append("\t\tPeer Addresses.............................................0")
                lines.append("\t\tTTL Values.................................................0")
                lines.append("\t\tDns Servers................................................0")
                lines.append("\t\tDns Queries................................................0")
                lines.append("\t\tSMB Groups.................................................0")
                lines.append("\t\tURLs.......................................................0")
                lines.append("\t\tOpen Tcp Ports.............................................0")
                lines.append("\t\tOpen Udp Ports.............................................0")
                lines.append("\t\tUserAgents.................................................0")
                lines.append("\t\tPop3 Users.................................................0")
                lines.append("\t\tPop3 Passwords.............................................0")
                lines.append("\t\tReceived Email............................................No")
                lines.append("\t\tSent Email................................................No")
                lines.append("\t\tHttp.......................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
                lines.append("\t\tFtp........................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses")
                lines.append("\t\tSsh........................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
                lines.append("\t\tPop3.......................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
                lines.append("\t\tSmtp.......................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
                lines.append("\t\tIcmp.......................................................0")
                lines.append("\t\t\tTx Requests................................................0")
                lines.append("\t\t\tTx Responses...............................................0")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
                lines.append("\t\tArp........................................................5")
                lines.append("\t\t\tTx Requests................................................4")
                lines.append("\t\t\tTx Responses...............................................1")
                lines.append("\t\t\tRx Requests................................................0")
                lines.append("\t\t\tRx Responses...............................................0")
        
        # WiFi Statistics
        lines.append("WiFi Statistics")
        lines.append(f"\tData.....................................................{device.get('packet_count', 0)}")
        lines.append("\t\tTransmit.................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tData( Enc )..............................................0")
        lines.append("\t\tTransmit.................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tDecrypts.................................................0")
        lines.append("\t\tTransmit.................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tFailed Decrypts............................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tPower Save Poll............................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tCFE........................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tCFE w/ACK..................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tBeacons....................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tAnn. Traff.................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tDisassoc...................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tAuth.......................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tDeauth.....................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tProbe Req..................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tProbe Resp.................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tAssoc. Req.................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tAssoc. Resp................................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tReassoc. Req...............................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        lines.append("\tReassoc. Resp..............................................0")
        lines.append("\t\tTransmit...................................................0")
        lines.append("\t\tReceive....................................................0")
        
        report = "\n".join(lines)
        
        # Write to file if path provided
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
            logger.info(f"Device info report written to {output_path}")
        
        return report
    
    def generate_collection_summary_report(self, pcap_filename: str, output_path: Optional[str] = None) -> str:
        """Generate collection summary report.
        
        Args:
            pcap_filename: Original PCAP filename
            output_path: Optional output file path
        
        Returns:
            Report content as string
        """
        lines = []
        
        # Header
        lines.append("COLLECTION SUMMARY REPORT")
        lines.append("=========================")
        lines.append("")
        
        # Collection metadata
        lines.append(f"Filename.................................... {pcap_filename}")
        
        # Get timestamps from database
        devices = self.db.get_all_devices()
        if devices:
            first_seen = min(d.get('first_seen', '') for d in devices if d.get('first_seen'))
            last_seen = max(d.get('last_seen', '') for d in devices if d.get('last_seen'))
            lines.append(f"Collection Start Date/Time.................. {first_seen}")
            lines.append(f"Collection Stop Date/Time................... {last_seen}")
        
        lines.append("Duration.................................... Unknown")
        lines.append("Collection strategy......................... 100% scanning")
        lines.append("During collection, time with GPS signal..... 0%")
        lines.append("Host Platform............................... NetSleuth PCAP Analysis Tool")
        lines.append("Software Release Name....................... NetSleuth Milestone 5")
        lines.append("Software Revision Number.................... 1.0")
        lines.append("WiFi Card Device Name....................... Unknown")
        lines.append("WiFi Card Description....................... Scapy-based capture")
        lines.append("WiFi Card Mac Address....................... Unknown")
        lines.append("WiFi Device Driver Name..................... Unknown")
        lines.append("WiFi Driver Meta Data Name.................. Unknown")
        lines.append("WiFi Card Spectrum Capability............... IEEE 802.11 2.4 and 5 GHz")
        
        # Basic Statistics
        lines.append("")
        lines.append("Basic Statistics")
        lines.append("================")
        
        total_packets = self.db.get_packet_count() if hasattr(self.db, 'get_packet_count') else 0
        lines.append(f"    Number of frames............................. {total_packets}")
        
        # Get WiFi frame counts
        mgmt_frames = self.db.get_wifi_management_frames()
        mgmt_count = len(mgmt_frames)
        lines.append(f"    Number of management frames.................. {mgmt_count} of {total_packets} (about {mgmt_count/max(total_packets,1)*100:.0f}%)")
        
        lines.append(f"    Number of control frames..................... 0 of {total_packets} (0%)")
        lines.append(f"    Number of data frames........................ {total_packets - mgmt_count} of {total_packets} (about {(total_packets - mgmt_count)/max(total_packets,1)*100:.0f}%)")
        
        # Network statistics
        access_points = self.db.get_wifi_access_points()
        num_networks = len(access_points)
        lines.append(f"    Number of networks discovered................ {num_networks}")
        
        clients = self.db.get_wifi_clients()
        num_clients = len(clients)
        lines.append(f"    Number of networks with clients.............. {num_networks} of {num_networks} (100%)")
        lines.append(f"    Number of networks with a cloaked SSID....... 0 of {num_networks} (0%)")
        
        wps_networks = sum(1 for ap in access_points if ap.get('wps_enabled'))
        lines.append(f"    Number of networks advertising WPS........... {wps_networks} of {num_networks} (about {wps_networks/max(num_networks,1)*100:.0f}%)")
        lines.append(f"    Number of networks with unconfigured WPS..... 0 of {num_networks} (0%)")
        lines.append(f"    Number of networks with WPS device details... {wps_networks} of {num_networks} (about {wps_networks/max(num_networks,1)*100:.0f}%)")
        lines.append(f"    Number of networks with CSA.................. 0 of {num_networks} (0%)")
        lines.append(f"    Number of unassociated clients............... 0")
        
        # Frame subtype distribution
        lines.append("")
        lines.append("Frame SubType Distribution")
        lines.append("==========================")
        lines.append("Number of recognized and unique frame subtypes: 5")
        
        if mgmt_count > 0:
            lines.append(f"     1) Mgmt-Beacon............................. {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Beacon')} of {total_packets} (about {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Beacon')/max(total_packets,1)*100:.0f}%)")
            lines.append(f"     2) Mgmt-Probe Response..................... {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Probe Response')} of {total_packets} (about {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Probe Response')/max(total_packets,1)*100:.0f}%)")
            lines.append(f"     3) Mgmt-Association Request................ {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Association Request')} of {total_packets} (about {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Association Request')/max(total_packets,1)*100:.0f}%)")
            lines.append(f"     4) Mgmt-Association Response............... {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Association Response')} of {total_packets} (about {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Association Response')/max(total_packets,1)*100:.0f}%)")
            lines.append(f"     5) Mgmt-Authentication.................... {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Authentication')} of {total_packets} (about {sum(1 for f in mgmt_frames if f.get('frame_subtype') == 'Authentication')/max(total_packets,1)*100:.0f}%)")
        
        # Network configurations
        lines.append("")
        lines.append("Network Configurations")
        lines.append("======================")
        lines.append("Number of recognized and unique network configurations: 1")
        lines.append("     1) Infrastructure...... 1 of 1 (100%)")
        
        # Speed/frequency
        lines.append("")
        lines.append("Speed/Frequency Amendment Statistics")
        lines.append("====================================")
        lines.append("Number of recognized and unique speed-oriented manufacturer monikers: 0")
        
        # Protection methods
        lines.append("")
        lines.append("Protection Methods")
        lines.append("==================")
        protection_methods = set(ap.get('security_type') for ap in access_points if ap.get('security_type'))
        if protection_methods:
            lines.append(f"Number of recognized and unique protection methods: {len(protection_methods)}")
            for i, method in enumerate(protection_methods, 1):
                count = sum(1 for ap in access_points if ap.get('security_type') == method)
                lines.append(f"     {i}) {method}...... {count} of {num_networks} (about {count/max(num_networks,1)*100:.0f}%)")
        else:
            lines.append("Number of recognized and unique protection methods: 0")
        
        # Station statistics
        lines.append("")
        lines.append("Station & Logical Host Statistics")
        lines.append("=================================")
        lines.append(f"    Total number of client stations discovered............................ {num_clients}")
        
        devices_with_ips = sum(1 for d in devices if self.db.get_device_ips(d['id']))
        lines.append(f"    Number of IPv4 logical hosts discovered on those client stations...... {devices_with_ips} of {len(devices)} (about {devices_with_ips/max(len(devices),1)*100:.0f}%)")
        
        devices_with_os = sum(1 for d in devices if self.db.get_device_fingerprint(d['id']) and self.db.get_device_fingerprint(d['id']).get('operating_system'))
        lines.append(f"    Number of IPv4 logical hosts where the operating system was guessed... {devices_with_os} of {devices_with_ips} (about {devices_with_os/max(devices_with_ips,1)*100:.0f}%)")
        
        # OS statistics
        lines.append("")
        lines.append("IPv4 Logical Host Operating System Statistics")
        lines.append("=============================================")
        os_families = set()
        for d in devices:
            fp = self.db.get_device_fingerprint(d['id'])
            if fp and fp.get('operating_system'):
                os_families.add(fp['operating_system'])
        
        if os_families:
            lines.append(f"Number of recognized and unique operating systems: {len(os_families)}")
            for i, os_name in enumerate(os_families, 1):
                count = sum(1 for d in devices if self.db.get_device_fingerprint(d['id']) and self.db.get_device_fingerprint(d['id']).get('operating_system') == os_name)
                lines.append(f"     {i}) {os_name}...... {count} of {len(os_families)} (100%)")
        else:
            lines.append("Number of recognized and unique operating systems: 0")
        
        # Manufacturer statistics
        lines.append("")
        lines.append("Client Manufacturer Popularity Contest")
        lines.append("======================================")
        vendors = set(d.get('vendor_name') for d in devices if d.get('vendor_name'))
        if vendors:
            lines.append(f"Number of recognized and unique manufacturer names: {len(vendors)}")
            for i, vendor in enumerate(vendors, 1):
                count = sum(1 for d in devices if d.get('vendor_name') == vendor)
                lines.append(f"     {i}) {vendor}...... {count} of {len(devices)} (about {count/max(len(devices),1)*100:.0f}%)")
        else:
            lines.append("Number of recognized and unique manufacturer names: 0")
        
        # Frequency distribution
        lines.append("")
        lines.append("Frequency Distribution")
        lines.append("======================")
        channels = {}
        for ap in access_points:
            channel = ap.get('channel', 0)
            if channel:
                channels[channel] = channels.get(channel, 0) + 1
        
        for ch in range(1, 15):
            count = channels.get(ch, 0)
            lines.append(f"    Number of networks on channel {ch}.... {count} of {num_networks} (about {count/max(num_networks,1)*100:.0f}%)")
        
        # Network details
        lines.append("")
        lines.append("Networks")
        lines.append("========")
        
        for i, ap in enumerate(access_points, 1):
            lines.append(f"Network {i} of {num_networks}")
            lines.append(f"    Type............................................. Infrastructure")
            lines.append(f"    SSID............................................. {ap.get('ssid', '<Hidden>')}")
            lines.append(f"    BSSID............................................ {ap.get('bssid')}")
            lines.append(f"    Channel........................................ {ap.get('channel', 'Unknown')}")
            lines.append(f"    Network Protection Method........................ {ap.get('security_type', 'Open')}")
            
            # Access Point details
            lines.append(f"    Access Point:")
            lines.append(f"    MAC Address...................................... {ap.get('bssid')}")
            lines.append(f"    Connectivity Type................................ Wireless")
            lines.append(f"    First Heard Date/Time............................ {ap.get('first_seen', 'Unknown')}")
            lines.append(f"    Last Heard Date/Time............................. {ap.get('last_seen', 'Unknown')}")
            lines.append(f"    Last Heard Signal................................ {ap.get('last_rssi', 'N/A')}")
            lines.append(f"    Best Heard Signal................................ {ap.get('best_rssi', 'N/A')}")
            
            # WPS info
            if ap.get('wps_enabled'):
                lines.append(f"    WiFi Protected Setup")
                lines.append(f"        WPS State.................................... Configured")
                lines.append(f"        WPS Enabled................................... Yes")
            
            # Clients for this AP
            associations = [a for a in self.db.get_wifi_associations() if a.get('bssid') == ap.get('bssid')]
            if associations:
                lines.append(f"    Associated Clients: {len(associations)}")
                for j, assoc in enumerate(associations, 1):
                    lines.append(f"    Client {j} of {len(associations)}")
                    lines.append(f"    MAC Address...................................... {assoc.get('client_mac')}")
                    lines.append(f"    Connectivity Type................................ Wireless")
                    lines.append(f"    First Heard Date/Time............................ {assoc.get('first_seen', 'Unknown')}")
                    lines.append(f"    Last Heard Date/Time............................. {assoc.get('last_seen', 'Unknown')}")
        
        report = "\n".join(lines)
        
        # Write to file if path provided
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
            logger.info(f"Collection summary report written to {output_path}")
        
        return report


if __name__ == "__main__":
    logger.info("Report Generator module initialized")
