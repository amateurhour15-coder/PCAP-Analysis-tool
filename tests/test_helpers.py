"""Test helper utilities."""

import pytest
from utils.helpers import (
    mac_to_int,
    int_to_mac,
    normalize_mac,
    is_private_ip,
    is_multicast_mac,
    is_broadcast_mac,
)


class TestMACConversion:
    def test_mac_to_int(self):
        assert mac_to_int("00:00:00:00:00:00") == 0
        assert mac_to_int("FF:FF:FF:FF:FF:FF") == 281474976710655
    
    def test_int_to_mac(self):
        assert int_to_mac(0) == "00:00:00:00:00:00"
        assert int_to_mac(281474976710655) == "ff:ff:ff:ff:ff:ff"
    
    def test_normalize_mac(self):
        assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
        assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
        assert normalize_mac("001122334455") == "00:11:22:33:44:55"


class TestIPChecks:
    def test_is_private_ip(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False


class TestMACChecks:
    def test_is_multicast_mac(self):
        assert is_multicast_mac("01:00:5E:00:00:01") is True
        assert is_multicast_mac("00:00:00:00:00:00") is False
    
    def test_is_broadcast_mac(self):
        assert is_broadcast_mac("FF:FF:FF:FF:FF:FF") is True
        assert is_broadcast_mac("00:00:00:00:00:00") is False
