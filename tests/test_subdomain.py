"""Tests for the subdomain enumeration module."""

import pytest
from reconx.core.subdomain import Subdomain, SubdomainResult


class TestSubdomain:
    def test_defaults(self):
        s = Subdomain(name="www.example.com")
        assert s.ips == []
        assert s.source == "bruteforce"
        assert s.cname == ""

    def test_with_ips(self):
        s = Subdomain(name="mail.example.com", ips=["1.2.3.4", "5.6.7.8"], source="crtsh")
        assert len(s.ips) == 2
        assert s.source == "crtsh"


class TestSubdomainResult:
    def test_defaults(self):
        r = SubdomainResult(domain="example.com")
        assert r.subdomains == []
        assert r.total_checked == 0
        assert r.error is None

    def test_with_subdomains(self):
        subs = [
            Subdomain(name="www.example.com", ips=["1.1.1.1"]),
            Subdomain(name="api.example.com", ips=["2.2.2.2"], source="crtsh"),
        ]
        r = SubdomainResult(domain="example.com", subdomains=subs, total_checked=150)
        assert len(r.subdomains) == 2
        assert r.total_checked == 150

    def test_error_state(self):
        r = SubdomainResult(domain="example.com", error="Network unreachable")
        assert r.error == "Network unreachable"
