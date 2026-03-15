"""Tests for DNS enumeration data structures."""

import pytest
from reconx.core.dns_enum import DNSRecord, DNSResult, ZoneTransferResult


class TestDNSRecord:
    def test_basic(self):
        r = DNSRecord(record_type="A", value="1.2.3.4")
        assert r.record_type == "A"
        assert r.value == "1.2.3.4"

    def test_mx_record(self):
        r = DNSRecord(record_type="MX", value="mail.example.com")
        assert r.record_type == "MX"


class TestDNSResult:
    def test_defaults(self):
        r = DNSResult(domain="example.com")
        assert r.records == {}
        assert r.zone_transfers == []
        assert r.security_findings == []
        assert r.error is None

    def test_with_records(self):
        r = DNSResult(
            domain="example.com",
            records={"A": [DNSRecord("A", "1.2.3.4")]},
        )
        assert "A" in r.records
        assert r.records["A"][0].value == "1.2.3.4"


class TestZoneTransferResult:
    def test_failed(self):
        zt = ZoneTransferResult(nameserver="ns1.example.com", success=False)
        assert not zt.success
        assert zt.records == []

    def test_success(self):
        zt = ZoneTransferResult(
            nameserver="ns1.example.com",
            success=True,
            records=["www IN A 1.2.3.4"],
        )
        assert zt.success
        assert len(zt.records) == 1
