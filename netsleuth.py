#!/usr/bin/env python3
"""NetSleuth - Intelligent Network Discovery and PCAP Analysis.

Main entry point for the application.
"""

import sys
import logging
from pathlib import Path
from typing import Optional

from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Import NetSleuth modules
from utils.logger import setup_logging, get_logger
from config.settings import get_config
from core.pcap_reader import PCAPReader
from core.packet_processor import PacketProcessor
from database.db_manager import DatabaseManager
from utils.oui_lookup import OUILookup
from exporters.json_exporter import JSONExporter
from exporters.csv_exporter import CSVExporter

# Import Device Intelligence (Milestone 2)
from device_intelligence import DeviceIntelligence

# Import Internet Intelligence (Milestone 3)
from internet_intelligence import InternetIntelligence

# Import WiFi Intelligence (Milestone 4)
from wifi_intelligence import WiFiIntelligence

# Import Device Fingerprinting (Milestone 5)
from device_fingerprinting import DeviceFingerprinting

# Import Report Generator
from report_generator import ReportGenerator

# Setup logging
setup_logging("NetSleuth", logging.INFO)
logger = get_logger(__name__)
console = Console()


def get_mac_address_type(mac_address: str) -> str:
    """Determine the type of MAC address.
    
    Args:
        mac_address: MAC address string
    
    Returns:
        MAC address type string
    """
    if not mac_address:
        return "Unknown"
    
    # Normalize MAC address
    mac_clean = mac_address.replace(':', '').replace('-', '').upper()
    
    # Check for protocol/reserved addresses
    if mac_clean.startswith('3333'):
        return "IPv6 Multicast"
    elif mac_clean == 'FFFFFFFFFFFF':
        return "Broadcast"
    elif mac_clean.startswith('0180C2'):
        return "Spanning Tree"
    elif mac_clean.startswith('01005E'):
        return "IPv4 Multicast"
    elif mac_clean.startswith('0100'):
        return "Bridge Group"
    
    # Check for random (locally administered) MAC addresses
    # The second least significant bit of the first octet indicates locally administered
    # In hex, if the second character is 2, 6, A, or E, it's locally administered
    try:
        first_octet = int(mac_clean[0:2], 16)
        if first_octet & 0x02:  # Locally administered bit is set
            return "Random"
    except (ValueError, IndexError):
        pass
    
    return "Hardware (OUI)"


class NetSleuth:
    """Main NetSleuth application."""
    
    def __init__(self):
        """Initialize NetSleuth."""
        self.config = get_config()
        self.db = DatabaseManager()
        self.oui_lookup = OUILookup()
        self.device_count = 0
        self.packet_count = 0
        self._seen_macs: set[str] = set()
        
        # Initialize Internet Intelligence (Milestone 3)
        self.internet_intelligence = InternetIntelligence(db_manager=self.db, offline_mode=True)
        logger.info("Internet Intelligence module initialized")
        
        # Initialize Device Intelligence (Milestone 2) with Internet Intelligence integration
        self.device_intelligence = DeviceIntelligence(db_manager=self.db, internet_intelligence=self.internet_intelligence)
        logger.info("Device Intelligence module initialized")
        
        # Initialize WiFi Intelligence (Milestone 4)
        self.wifi_intelligence = WiFiIntelligence(db_manager=self.db)
        logger.info("WiFi Intelligence module initialized")
        
        # Initialize Device Fingerprinting (Milestone 5)
        self.device_fingerprinting = DeviceFingerprinting(db_manager=self.db)
        logger.info("Device Fingerprinting module initialized")
        
        # Initialize Report Generator
        self.report_generator = ReportGenerator(
            db_manager=self.db,
            wifi_intelligence=self.wifi_intelligence,
            device_intelligence=self.device_intelligence,
        )
        logger.info("Report Generator module initialized")
    
    def analyze_pcap(self, pcap_path: str) -> bool:
        """Analyze a PCAP file.
        
        Args:
            pcap_path: Path to PCAP file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Open PCAP
            console.print(f"\n[bold cyan]Opening PCAP:[/bold cyan] {pcap_path}")
            reader = PCAPReader(pcap_path)
            total_packets = reader.get_packet_count()
            console.print(f"[green]Packets found:[/green] {total_packets}")
            
            # Process packets
            console.print("\n[bold cyan]Processing packets...[/bold cyan]")
            
            with Progress() as progress:
                task = progress.add_task("[cyan]Analyzing...", total=total_packets)
                
                for packet in reader.read():
                    # Extract metadata
                    metadata = PacketProcessor.extract_metadata(packet)
                    if not metadata:
                        progress.advance(task)
                        continue
                    
                    # Source MAC
                    if metadata.src_mac:
                        self._seen_macs.add(metadata.src_mac)
                        vendor = self.oui_lookup.lookup(metadata.src_mac)
                        device_id = self.db.add_or_update_device(
                            metadata.src_mac, vendor
                        )
                        
                        if metadata.src_ip:
                            self.db.add_device_ip(device_id, metadata.src_ip,
                                                 metadata.protocol_version or 4)
                        
                        self.db.increment_device_stats(metadata.src_mac, metadata.packet_size)
                        
                        # Analyze with Internet Intelligence (Milestone 3)
                        self.internet_intelligence.process_packet(packet, metadata, device_id)
                    
                    # Destination MAC
                    if metadata.dst_mac:
                        self._seen_macs.add(metadata.dst_mac)
                        vendor = self.oui_lookup.lookup(metadata.dst_mac)
                        device_id = self.db.add_or_update_device(
                            metadata.dst_mac, vendor
                        )
                        
                        if metadata.dst_ip:
                            self.db.add_device_ip(device_id, metadata.dst_ip,
                                                 metadata.protocol_version or 4)
                        
                        self.db.increment_device_stats(metadata.dst_mac, metadata.packet_size)
                        
                        # Analyze with Internet Intelligence (Milestone 3)
                        self.internet_intelligence.process_packet(packet, metadata, device_id)
                    
                    # Analyze with Device Intelligence (Milestone 2)
                    self._analyze_with_device_intelligence(packet, metadata)
                    
                    # Analyze with WiFi Intelligence (Milestone 4)
                    self.wifi_intelligence.process_packet(packet)
                    
                    self.device_count = len(self._seen_macs)
                    self.packet_count += 1
                    progress.advance(task)
            
            # Perform device fingerprinting after all packets processed (Milestone 5)
            self._perform_device_fingerprinting()
            
            return True
        
        except Exception as e:
            console.print(f"[red]Error analyzing PCAP:[/red] {e}")
            logger.exception("PCAP analysis failed")
            return False
    
    def _analyze_with_device_intelligence(self, packet, metadata) -> None:
        """Analyze packet with Device Intelligence module (Milestone 2)."""
        try:
            result = self.device_intelligence.analyze_packet(packet, metadata)
            if result:
                logger.debug("Device Intelligence analysis: %s", result)
        except Exception as e:
            logger.debug("Device Intelligence analysis error: %s", e)
    
    def _perform_device_fingerprinting(self) -> None:
        """Perform device fingerprinting after PCAP analysis (Milestone 5)."""
        try:
            devices = self.db.get_all_devices()
            
            for device in devices:
                device_id = device['id']
                mac_address = device['mac_address']
                
                # Get DHCP options from device intelligence
                dhcp_info = self.device_intelligence.dhcp_analyzer.get_dhcp_devices()
                dhcp_options = None
                for mac, info in dhcp_info.items():
                    if mac.lower() == mac_address.lower():
                        dhcp_options = info.get('parameter_request_list')
                        break
                
                # Get mDNS TXT records
                mdns_info = self.device_intelligence.mdns_analyzer.get_mdns_services()
                mdns_txt_records = {}
                for service_name, records in mdns_info.items():
                    if isinstance(records, list) and records:
                        for record in records:
                            if isinstance(record, dict):
                                mdns_txt_records.update(record)
                
                # Analyze device fingerprint
                self.device_fingerprinting.analyze_device(
                    device_id=device_id,
                    mac_address=mac_address,
                    dhcp_options=dhcp_options,
                    mdns_txt_records=mdns_txt_records if mdns_txt_records else None,
                )
            
            logger.info("Device fingerprinting completed for %d devices", len(devices))
        except Exception as e:
            logger.debug("Device fingerprinting error: %s", e)
    
    def display_devices(self) -> None:
        """Display discovered devices."""
        devices = self.db.get_all_devices()
        
        if not devices:
            console.print("[yellow]No devices found[/yellow]")
            return
        
        table = Table(title="[bold]Discovered Devices[/bold]")
        table.add_column("MAC Address", style="cyan")
        table.add_column("MAC Type", style="bright_magenta")
        table.add_column("Vendor", style="magenta")
        table.add_column("IPs", style="green")
        table.add_column("Packets", style="yellow")
        table.add_column("Bytes", style="blue")
        
        for device in devices:
            device_id = device["id"]
            ips = self.db.get_device_ips(device_id)
            ip_list = ", ".join([ip["ip_address"] for ip in ips]) or "None"
            
            from utils.helpers import format_bytes
            
            mac_type = get_mac_address_type(device["mac_address"])
            
            table.add_row(
                device["mac_address"],
                mac_type,
                device["vendor_name"] or "Unknown",
                ip_list,
                str(device["packet_count"]),
                format_bytes(device["byte_count"]),
            )
        
        console.print(table)
    
    def display_device_intelligence_summary(self) -> None:
        """Display Device Intelligence (Milestone 2) analysis summary."""
        summary = self.device_intelligence.get_device_summary()
        
        console.print("\n[bold cyan]Device Intelligence Summary (Milestone 2)[/bold cyan]")
        console.print(f"  [green]DHCP Devices:[/green] {len(summary['dhcp_devices'])}")
        console.print(f"  [green]DNS Hostnames:[/green] {len(summary['dns_devices'])}")
        console.print(f"  [green]NetBIOS Entries:[/green] {len(summary['netbios_devices'])}")
        console.print(f"  [green]mDNS Services:[/green] {len(summary['mdns_services'])}")
        console.print(f"  [green]Total Unique Identifiers:[/green] {summary['total_devices']}")

        dhcp_devices = summary["dhcp_devices"]
        if dhcp_devices:
            dhcp_table = Table(title="[bold]DHCP Devices[/bold]")
            dhcp_table.add_column("Hostname", style="cyan")
            dhcp_table.add_column("MAC", style="magenta")
            dhcp_table.add_column("Assigned IP", style="green")
            dhcp_table.add_column("Vendor Class", style="yellow")
            dhcp_table.add_column("Message", style="blue")

            for mac, info in dhcp_devices.items():
                dhcp_table.add_row(
                    info.get("hostname") or "—",
                    mac,
                    info.get("assigned_ip") or info.get("client_ip") or "—",
                    info.get("vendor_class") or "—",
                    info.get("message_type") or "—",
                )
            console.print(dhcp_table)

        dns_devices = summary["dns_devices"]
        if dns_devices:
            dns_table = Table(title="[bold]DNS Hostnames[/bold]")
            dns_table.add_column("Hostname", style="cyan")
            dns_table.add_column("Type", style="green")

            for hostname, info in dns_devices.items():
                query_types = ", ".join(
                    q.get("type", "?") for q in info.get("queries", [])
                ) or "response"
                dns_table.add_row(hostname, query_types)
            console.print(dns_table)

        mdns_services = summary["mdns_services"]
        if mdns_services:
            mdns_table = Table(title="[bold]mDNS Services[/bold]")
            mdns_table.add_column("Service", style="cyan")
            mdns_table.add_column("Queries", style="green")

            for service_name in mdns_services:
                mdns_table.add_row(service_name, str(len(mdns_services[service_name])))
            console.print(mdns_table)
        
        correlated = self.device_intelligence.correlate_device_info()
        if correlated:
            corr_table = Table(title="[bold]Correlated Devices[/bold]")
            corr_table.add_column("Hostname", style="cyan")
            corr_table.add_column("MAC", style="magenta")
            corr_table.add_column("DHCP IP", style="green")

            for device_name, info in correlated.items():
                dhcp_ip = "—"
                if info.get("dhcp_info"):
                    dhcp_ip = info["dhcp_info"].get("assigned_ip") or info["dhcp_info"].get("client_ip") or "—"
                corr_table.add_row(device_name, info["mac_address"], dhcp_ip)
            console.print(corr_table)
        elif not any([dhcp_devices, dns_devices, mdns_services, summary["netbios_devices"]]):
            console.print("[yellow]No device intelligence data yet. Analyze a PCAP first.[/yellow]")
    
    def display_internet_intelligence_summary(self) -> None:
        """Display Internet Intelligence (Milestone 3) analysis summary."""
        devices = self.db.get_all_devices()
        
        if not devices:
            console.print("[yellow]No devices found. Analyze a PCAP first.[/yellow]")
            return
        
        console.print("\n[bold cyan]Internet Intelligence Summary (Milestone 3)[/bold cyan]")
        
        total_external_ips = 0
        total_domains = 0
        total_asns = 0
        total_countries = 0
        
        intel_table = Table(title="[bold]Device External Intelligence[/bold]")
        intel_table.add_column("MAC Address", style="cyan")
        intel_table.add_column("Vendor", style="magenta")
        intel_table.add_column("External IPs", style="green")
        intel_table.add_column("Domains", style="yellow")
        intel_table.add_column("ASNs", style="blue")
        intel_table.add_column("Countries", style="red")
        
        for device in devices:
            device_id = device["id"]
            summary = self.internet_intelligence.get_device_intelligence_summary(device_id)
            
            total_external_ips += summary["unique_external_ips"]
            total_domains += summary["unique_domains"]
            total_asns += summary["unique_asns"]
            total_countries += summary["unique_countries"]
            
            intel_table.add_row(
                device["mac_address"],
                device["vendor_name"] or "Unknown",
                str(summary["unique_external_ips"]),
                str(summary["unique_domains"]),
                str(summary["unique_asns"]),
                str(summary["unique_countries"]),
            )
        
        console.print(intel_table)
        console.print(f"\n[bold]Totals:[/bold]")
        console.print(f"  [green]Total External IPs:[/green] {total_external_ips}")
        console.print(f"  [green]Total Unique Domains:[/green] {total_domains}")
        console.print(f"  [green]Total Unique ASNs:[/green] {total_asns}")
        console.print(f"  [green]Total Unique Countries:[/green] {total_countries}")
        
        # Show passive DNS cache size
        passive_dns_count = len(self.internet_intelligence.passive_dns.dns_cache)
        console.print(f"  [green]Passive DNS Cache Entries:[/green] {passive_dns_count}")
    
    def display_wifi_intelligence_summary(self) -> None:
        """Display WiFi Intelligence (Milestone 4) analysis summary."""
        summary = self.wifi_intelligence.get_wifi_summary()
        
        console.print("\n[bold cyan]WiFi Intelligence Summary (Milestone 4)[/bold cyan]")
        console.print(f"  [green]Access Points (Memory):[/green] {summary['access_points']}")
        console.print(f"  [green]Hidden Networks:[/green] {summary['hidden_networks']}")
        console.print(f"  [green]Client Associations (Memory):[/green] {summary['client_associations']}")
        console.print(f"  [green]Access Points (Database):[/green] {summary.get('db_aps', 0)}")
        console.print(f"  [green]WiFi Clients (Database):[/green] {summary.get('db_clients', 0)}")
        console.print(f"  [green]Associations (Database):[/green] {summary.get('db_associations', 0)}")
        
        # Display access points
        access_points = self.db.get_wifi_access_points()
        if access_points:
            ap_table = Table(title="[bold]WiFi Access Points[/bold]")
            ap_table.add_column("BSSID", style="cyan")
            ap_table.add_column("SSID", style="magenta")
            ap_table.add_column("Channel", style="green")
            ap_table.add_column("Encryption", style="yellow")
            ap_table.add_column("WPS", style="red")
            ap_table.add_column("Beacons", style="blue")
            
            for ap in access_points[:20]:  # Limit to 20 for display
                ap_table.add_row(
                    ap['bssid'],
                    ap['ssid'] or "<Hidden>",
                    str(ap['channel']) if ap['channel'] else "—",
                    ap['encryption_type'] or "Open",
                    "Yes" if ap['wps_enabled'] else "No",
                    str(ap['beacon_count']),
                )
            console.print(ap_table)
        
        # Display client-AP associations
        associations = self.db.get_wifi_associations()
        if associations:
            assoc_table = Table(title="[bold]Client-AP Associations[/bold]")
            assoc_table.add_column("Client MAC", style="cyan")
            assoc_table.add_column("BSSID", style="magenta")
            assoc_table.add_column("SSID", style="green")
            assoc_table.add_column("Type", style="yellow")
            assoc_table.add_column("Frames", style="blue")
            
            for assoc in associations[:20]:  # Limit to 20 for display
                assoc_table.add_row(
                    assoc['client_mac'],
                    assoc['bssid'],
                    assoc['ssid'] or "<Hidden>",
                    assoc['association_type'] or "Unknown",
                    str(assoc['frame_count']),
                )
            console.print(assoc_table)
        
        if not access_points and not associations:
            console.print("[yellow]No WiFi data yet. Analyze a WiFi PCAP first.[/yellow]")
    
    def display_device_fingerprinting_summary(self) -> None:
        """Display Device Fingerprinting (Milestone 5) analysis summary."""
        fingerprints = self.device_fingerprinting.get_all_fingerprints()
        
        console.print("\n[bold cyan]Device Fingerprinting Summary (Milestone 5)[/bold cyan]")
        console.print(f"  [green]Total Devices Fingerprinted:[/green] {len(fingerprints)}")
        
        if not fingerprints:
            console.print("[yellow]No device fingerprints yet. Analyze a PCAP first.[/yellow]")
            return
        
        fp_table = Table(title="[bold]Device Fingerprints[/bold]")
        fp_table.add_column("MAC", style="cyan")
        fp_table.add_column("Manufacturer", style="magenta")
        fp_table.add_column("Device Type", style="green")
        fp_table.add_column("Device Model", style="yellow")
        fp_table.add_column("OS", style="blue")
        fp_table.add_column("OS Version", style="red")
        fp_table.add_column("Category", style="bright_cyan")
        fp_table.add_column("Confidence", style="white")
        
        for device_id, fp in fingerprints.items():
            # Get MAC address from device
            device = self.db.get_device_by_id(device_id)
            mac = device['mac_address'] if device else "Unknown"
            
            fp_table.add_row(
                mac,
                fp.get('manufacturer') or "—",
                fp.get('device_type') or "—",
                fp.get('device_model') or "—",
                fp.get('operating_system') or "—",
                fp.get('os_version') or "—",
                fp.get('device_category') or "—",
                f"{fp.get('confidence_score', 0):.2f}",
            )
        
        console.print(fp_table)
        
        # Show fingerprint statistics
        manufacturers = set(fp.get('manufacturer') for fp in fingerprints.values() if fp.get('manufacturer'))
        device_types = set(fp.get('device_type') for fp in fingerprints.values() if fp.get('device_type'))
        os_families = set(fp.get('operating_system') for fp in fingerprints.values() if fp.get('operating_system'))
        
        console.print(f"\n[bold]Statistics:[/bold]")
        console.print(f"  [green]Unique Manufacturers:[/green] {len(manufacturers)}")
        console.print(f"  [green]Unique Device Types:[/green] {len(device_types)}")
        console.print(f"  [green]Unique OS Families:[/green] {len(os_families)}")
        console.print(f"  [green]Average Confidence:[/green] {sum(fp.get('confidence_score', 0) for fp in fingerprints.values()) / len(fingerprints):.2f}")
    
    def generate_device_info_report(self, mac_address: str, output_path: Optional[str] = None) -> None:
        """Generate device info report.
        
        Args:
            mac_address: MAC address of device
            output_path: Optional output file path
        """
        try:
            if not output_path:
                output_path = f"{mac_address.replace(':', '_')}-info.txt"
            
            report = self.report_generator.generate_device_info_report(mac_address, output_path)
            console.print(f"[green]Device info report generated: {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]Error generating device info report: {e}[/red]")
    
    def generate_collection_summary_report(self, pcap_filename: str, output_path: Optional[str] = None) -> None:
        """Generate collection summary report.
        
        Args:
            pcap_filename: Original PCAP filename
            output_path: Optional output file path
        """
        try:
            if not output_path:
                output_path = f"{Path(pcap_filename).stem}_COLLECTION_SUMMARY_REPORT.txt"
            
            report = self.report_generator.generate_collection_summary_report(pcap_filename, output_path)
            console.print(f"[green]Collection summary report generated: {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]Error generating collection summary report: {e}[/red]")
    
    def export_devices(self, format: str = "json") -> bool:
        """Export devices to file.
        
        Args:
            format: Export format (json or csv)
        
        Returns:
            True if successful, False otherwise
        """
        devices = self.db.get_all_devices()
        
        if not devices:
            console.print("[yellow]No devices to export[/yellow]")
            return False
        
        # Enrich device data
        for device in devices:
            device_id = device["id"]
            ips = self.db.get_device_ips(device_id)
            device["ip_addresses"] = [ip["ip_address"] for ip in ips]
        
        # Export
        timestamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            output_path = f"exports/devices_{timestamp}.json"
            return JSONExporter.export(devices, output_path)
        elif format == "csv":
            output_path = f"exports/devices_{timestamp}.csv"
            return CSVExporter.export(devices, output_path)
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            return False
    
    def run(self) -> None:
        """Run interactive CLI."""
        console.print("[bold cyan]NetSleuth v0.2[/bold cyan]")
        console.print("[bold cyan]Intelligent Network Discovery and PCAP Analysis[/bold cyan]")
        console.print("[bold green]Milestone 2: Device Intelligence (DHCP, DNS, NetBIOS, mDNS)[/bold green]\n")
        
        while True:
            console.print("\n[bold]Menu:[/bold]")
            console.print("1. Analyze PCAP")
            console.print("2. Display Devices")
            console.print("3. Display Device Intelligence Summary (Milestone 2)")
            console.print("4. Display Internet Intelligence Summary (Milestone 3)")
            console.print("5. Display WiFi Intelligence Summary (Milestone 4)")
            console.print("6. Display Device Fingerprinting Summary (Milestone 5)")
            console.print("7. Generate Device Info Report")
            console.print("8. Generate Collection Summary Report")
            console.print("9. Export Devices (JSON)")
            console.print("10. Export Devices (CSV)")
            console.print("11. Exit")
            
            choice = input("\nSelect option (1-11): ").strip()
            
            if choice == "1":
                pcap_path = input("Enter PCAP file path: ").strip()
                if pcap_path:
                    self.analyze_pcap(pcap_path)
            
            elif choice == "2":
                self.display_devices()
            
            elif choice == "3":
                self.display_device_intelligence_summary()
            
            elif choice == "4":
                self.display_internet_intelligence_summary()
            
            elif choice == "5":
                self.display_wifi_intelligence_summary()
            
            elif choice == "6":
                self.display_device_fingerprinting_summary()
            
            elif choice == "7":
                mac_address = input("Enter MAC address (e.g., AA:BB:CC:DD:EE:FF): ").strip()
                if mac_address:
                    self.generate_device_info_report(mac_address)
            
            elif choice == "8":
                pcap_filename = input("Enter original PCAP filename: ").strip()
                if pcap_filename:
                    self.generate_collection_summary_report(pcap_filename)
            
            elif choice == "9":
                if self.export_devices("json"):
                    console.print("[green]Export successful[/green]")
                else:
                    console.print("[red]Export failed[/red]")
            
            elif choice == "10":
                if self.export_devices("csv"):
                    console.print("[green]Export successful[/green]")
                else:
                    console.print("[red]Export failed[/red]")
            
            elif choice == "11":
                console.print("[yellow]Goodbye![/yellow]")
                break
            
            else:
                console.print("[red]Invalid option[/red]")


def main():
    """Main entry point."""
    try:
        app = NetSleuth()
        app.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {e}")
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
