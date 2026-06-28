# NetSleuth - Intelligent Network Discovery and PCAP Analysis

## Overview

NetSleuth is a comprehensive network discovery and PCAP analysis tool designed to extract, correlate, and visualize network intelligence from packet captures. It identifies devices, resolves ownership information, infers network topology, and provides powerful insights into network behavior.

## Features (Milestone 1)

- **PCAP/PCAPNG Support**: Load network packet captures
- **Device Discovery**: Identify devices by MAC address, IP, and vendor
- **OUI Resolution**: Resolve MAC addresses to manufacturer names
- **Protocol Support**: Ethernet, IPv4, IPv6, ARP
- **SQLite Storage**: Persistent device inventory
- **JSON Export**: Export device data for external analysis
- **Command-line Interface**: Simple and intuitive CLI
- **Logging Framework**: Comprehensive debug and error logging
- **Configuration System**: Customizable behavior via YAML config

## Project Structure

```
NetSleuth/
├── README.md
├── LICENSE
├── requirements.txt
├── pyproject.toml
├── netsleuth.py              # Main entry point
├── config/
│   ├── __init__.py
│   ├── config.yaml           # Configuration file
│   └── settings.py           # Configuration loader
├── core/
│   ├── __init__.py
│   ├── pcap_reader.py        # PCAP/PCAPNG reader
│   ├── packet_processor.py   # Packet processing dispatcher
│   └── protocol_dispatcher.py # Protocol routing
├── database/
│   ├── __init__.py
│   ├── db_manager.py         # SQLite interface
│   └── schema.py             # Database schema definition
├── models/
│   ├── __init__.py
│   ├── device.py             # Device model
│   └── packet.py             # Packet data structures
├── protocols/
│   ├── __init__.py
│   ├── ethernet.py           # Ethernet frame parser
│   ├── ipv4.py               # IPv4 packet parser
│   ├── ipv6.py               # IPv6 packet parser
│   └── arp.py                # ARP protocol parser
├── utils/
│   ├── __init__.py
│   ├── logger.py             # Logging configuration
│   ├── oui_lookup.py         # MAC OUI resolution
│   └── helpers.py            # Utility functions
├── exporters/
│   ├── __init__.py
│   ├── json_exporter.py      # JSON export
│   └── csv_exporter.py       # CSV export
├── tests/
│   ├── __init__.py
│   ├── test_protocols.py     # Protocol parser tests
│   ├── test_device_manager.py
│   └── conftest.py           # Pytest configuration
├── docs/
│   ├── INSTALL.md
│   ├── USAGE.md
│   └── ARCHITECTURE.md
├── samples/
│   └── sample.pcap           # Sample PCAP for testing
├── install_windows.bat
├── install_linux.sh
├── run.bat
└── run.sh
```

## Quick Start

### Installation (Windows)

```bash
install_windows.bat
```

### Installation (Linux/macOS)

```bash
chmod +x install_linux.sh
./install_linux.sh
```

### Usage

```bash
# Windows
run.bat

# Linux/macOS
./run.sh
```

Then follow the CLI prompts to load a PCAP file.

## Milestones

- **Milestone 1** (Current): Core Engine - PCAP loading, device discovery, OUI resolution
- **Milestone 2**: Device Intelligence - DHCP, DNS, NetBIOS, mDNS
- **Milestone 3**: Internet Intelligence - DNS correlation, WHOIS, GeoIP
- **Milestone 4**: Wi-Fi Analysis - Beacon frames, SSIDs, WPA
- **Milestone 5**: Fingerprinting - Device Make/Model detection
- **Milestone 6**: Relationships - Network topology inference
- **Milestone 7**: Network Graph - Interactive visualization
- **Milestone 8**: Timeline - Event-based analysis
- **Milestone 9**: Security - Anomaly detection
- **Milestone 10**: Reports - PDF, HTML, CSV exports
- **Milestone 11**: GUI - Desktop application (PySide6)
- **Milestone 12**: Plugin SDK - Extensible architecture

## Requirements

- Python 3.9+
- See `requirements.txt` for dependencies

## License

MIT License - See LICENSE file

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## Author

NetSleuth Contributors
