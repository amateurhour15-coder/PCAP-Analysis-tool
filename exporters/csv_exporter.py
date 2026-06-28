"""CSV exporter for device data."""

import csv
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class CSVExporter:
    """Export device inventory to CSV."""
    
    @staticmethod
    def export(devices: List[Dict[str, Any]], output_path: str) -> bool:
        try:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if not devices:
                logger.warning("No devices to export")
                return False
            
            fieldnames = set()
            for device in devices:
                fieldnames.update(device.keys())
            fieldnames = sorted(list(fieldnames))
            
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(devices)
            
            logger.info(f"Exported {len(devices)} devices to {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return False
