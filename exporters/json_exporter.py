"""JSON exporter for device data."""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class JSONExporter:
    """Export device inventory to JSON."""
    
    @staticmethod
    def export(devices: List[Dict[str, Any]], output_path: str) -> bool:
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            devices_serializable = []
            for device in devices:
                device_copy = device.copy()
                for key, value in device_copy.items():
                    if isinstance(value, datetime):
                        device_copy[key] = value.isoformat()
                devices_serializable.append(device_copy)
            
            data = {
                "export_time": datetime.utcnow().isoformat(),
                "device_count": len(devices),
                "devices": devices_serializable,
            }
            
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported {len(devices)} devices to {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            return False
