"""Tests for the UDP scanner module."""

import pytest
from reconx.core.udp_scanner import (
    UDPPortResult, UDPScanResult, UDP_SERVICE_MAP, DEFAULT_UDP_PORTS,
    _dns_probe, _ntp_probe, _snmp_probe, _ssdp_probe,
)


class TestProbePayloads:
    def test_dns_probe_is_bytes(self):
        payload = _dns_probe()
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    def test_ntp_probe_is_48_bytes(self):
        payload = _ntp_probe()
        assert len(payload) == 48
        assert payload[0] == 0x1B  # LI=0, VN=3, mode=3

    def test_snmp_probe_is_bytes(self):
        payload = _snmp_probe()
        assert isinstance(payload, bytes)
        assert len(payload) > 0

    def test_ssdp_probe_contains_msearch(self):
        payload = _ssdp_probe()
        assert b"M-SEARCH" in payload


class TestUDPPortResult:
    def test_open_state(self):
        p = UDPPortResult(port=53, state="open", service="DNS")
        assert p.protocol == "udp"
        assert p.state == "open"

    def test_filtered_state(self):
        p = UDPPortResult(port=161, state="open|filtered", service="SNMP")
        assert "filtered" in p.state


class TestUDPScanResult:
    def test_defaults(self):
        r = UDPScanResult(host="example.com")
        assert r.open_ports == []
        assert r.total_scanned == 0
        assert r.error is None

    def test_with_ports(self):
        port = UDPPortResult(port=53, state="open", service="DNS")
        r = UDPScanResult(host="example.com", ip="1.2.3.4", open_ports=[port], total_scanned=9)
        assert len(r.open_ports) == 1
        assert r.total_scanned == 9


class TestServiceMap:
    def test_common_ports_mapped(self):
        assert UDP_SERVICE_MAP[53] == "DNS"
        assert UDP_SERVICE_MAP[123] == "NTP"
        assert UDP_SERVICE_MAP[161] == "SNMP"
        assert UDP_SERVICE_MAP[500] == "IKE/IPSec"

    def test_default_ports_not_empty(self):
        assert len(DEFAULT_UDP_PORTS) > 0
        assert 53 in DEFAULT_UDP_PORTS
        assert 161 in DEFAULT_UDP_PORTS
