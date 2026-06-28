# NetSleuth Architecture

## Overview

NetSleuth uses a modular architecture:

```
PCAP → PCAPReader → PacketProcessor → DatabaseManager → Exporters
                         ↓
                   ProtocolDispatcher
                   (Ethernet, IPv4, IPv6, ARP)
```

## Modules

### core/
- **pcap_reader.py** - PCAP file reading
- **packet_processor.py** - Packet metadata extraction
- **protocol_dispatcher.py** - Protocol routing

### database/
- **db_manager.py** - SQLite operations
- **schema.py** - Database schema

### utils/
- **logger.py** - Logging configuration
- **oui_lookup.py** - MAC vendor resolution
- **helpers.py** - Utility functions

### exporters/
- **json_exporter.py** - JSON export
- **csv_exporter.py** - CSV export

## Database Schema

Three main tables:
- **devices** - MAC address, vendor, stats
- **device_ips** - IP addresses per device
- **packets** - Raw packet logging
