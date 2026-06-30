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

# Setup logging
setup_logging("NetSleuth", logging.INFO)
logger = get_logger(__name__)
console = Console()


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
        
        # Initialize Device Intelligence (Milestone 2)
        self.device_intelligence = DeviceIntelligence()
        logger.info("Device Intelligence module initialized")
    
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
                    
                    # Analyze with Device Intelligence (Milestone 2)
                    self._analyze_with_device_intelligence(packet, metadata)
                    
                    self.device_count = len(self._seen_macs)
                    self.packet_count += 1
                    progress.advance(task)
            
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
    
    def display_devices(self) -> None:
        """Display discovered devices."""
        devices = self.db.get_all_devices()
        
        if not devices:
            console.print("[yellow]No devices found[/yellow]")
            return
        
        table = Table(title="[bold]Discovered Devices[/bold]")
        table.add_column("MAC Address", style="cyan")
        table.add_column("Vendor", style="magenta")
        table.add_column("IPs", style="green")
        table.add_column("Packets", style="yellow")
        table.add_column("Bytes", style="blue")
        
        for device in devices:
            device_id = device["id"]
            ips = self.db.get_device_ips(device_id)
            ip_list = ", ".join([ip["ip_address"] for ip in ips]) or "None"
            
            from utils.helpers import format_bytes
            
            table.add_row(
                device["mac_address"],
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
            console.print("4. Export Devices (JSON)")
            console.print("5. Export Devices (CSV)")
            console.print("6. Exit")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == "1":
                pcap_path = input("Enter PCAP file path: ").strip()
                if pcap_path:
                    self.analyze_pcap(pcap_path)
            
            elif choice == "2":
                self.display_devices()
            
            elif choice == "3":
                self.display_device_intelligence_summary()
            
            elif choice == "4":
                if self.export_devices("json"):
                    console.print("[green]Export successful[/green]")
                else:
                    console.print("[red]Export failed[/red]")
            
            elif choice == "5":
                if self.export_devices("csv"):
                    console.print("[green]Export successful[/green]")
                else:
                    console.print("[red]Export failed[/red]")
            
            elif choice == "6":
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
