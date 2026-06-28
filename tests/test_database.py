"""Test database operations."""

import pytest
from datetime import datetime
from database.db_manager import DatabaseManager


class TestDatabaseManager:
    def test_add_device(self, temp_db):
        device_id = temp_db.add_or_update_device(
            "00:11:22:33:44:55",
            "Apple Inc."
        )
        assert device_id > 0
    
    def test_get_device(self, temp_db):
        mac = "00:11:22:33:44:55"
        temp_db.add_or_update_device(mac, "Test Vendor")
        
        device = temp_db.get_device_by_mac(mac)
        assert device is not None
        assert device["mac_address"] == mac
        assert device["vendor_name"] == "Test Vendor"
    
    def test_add_device_ip(self, temp_db):
        device_id = temp_db.add_or_update_device("00:11:22:33:44:55")
        ip_id = temp_db.add_device_ip(device_id, "192.168.1.100", 4)
        
        assert ip_id > 0
        ips = temp_db.get_device_ips(device_id)
        assert len(ips) == 1
        assert ips[0]["ip_address"] == "192.168.1.100"
