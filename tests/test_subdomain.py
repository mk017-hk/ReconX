"""Tests for the subdomain enumeration module."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from reconx.core.subdomain import Subdomain, SubdomainResult, _detect_wildcard


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

    def test_wildcard_fields_default(self):
        r = SubdomainResult(domain="example.com")
        assert r.wildcard_detected is False
        assert r.wildcard_ips == []

    def test_wildcard_fields_set(self):
        r = SubdomainResult(domain="example.com", wildcard_detected=True, wildcard_ips=["9.9.9.9"])
        assert r.wildcard_detected is True
        assert r.wildcard_ips == ["9.9.9.9"]


class TestWildcardDetection:
    async def test_detect_wildcard_returns_empty_when_no_resolution(self):
        """Non-resolving random label returns []."""
        with patch("reconx.core.subdomain._resolve", new=AsyncMock(return_value=[])):
            result = await _detect_wildcard("example.com")
        assert result == []

    async def test_detect_wildcard_returns_ips_when_wildcard_active(self):
        """When the random probe resolves, we have a wildcard."""
        with patch("reconx.core.subdomain._resolve", new=AsyncMock(return_value=["1.2.3.4"])):
            result = await _detect_wildcard("wildcard.example.com")
        assert result == ["1.2.3.4"]

    async def test_wildcard_suppresses_bruteforce_hit(self):
        """
        Simulate brute-force: a subdomain whose IPs are entirely within the
        wildcard set should be filtered out.
        """
        from reconx.core.subdomain import _bruteforce_chunk
        import asyncio

        wildcard_ips = {"1.2.3.4"}
        found: list[Subdomain] = []

        async def fake_resolve(host):
            # All probes resolve to the wildcard IP
            return ["1.2.3.4"]

        with patch("reconx.core.subdomain._resolve", side_effect=fake_resolve):
            sem = asyncio.Semaphore(5)
            await _bruteforce_chunk("example.com", ["www", "api"], sem, found, wildcard_ips)

        assert found == [], "Wildcard-matching subdomains should be suppressed"

    async def test_non_wildcard_subdomain_kept(self):
        """
        If a subdomain resolves to at least one IP NOT in the wildcard set,
        it should be kept.
        """
        from reconx.core.subdomain import _bruteforce_chunk
        import asyncio

        wildcard_ips = {"1.2.3.4"}
        found: list[Subdomain] = []

        async def fake_resolve(host):
            if "api" in host:
                return ["5.5.5.5"]   # genuine — not in wildcard set
            return ["1.2.3.4"]       # wildcard match

        with patch("reconx.core.subdomain._resolve", side_effect=fake_resolve):
            sem = asyncio.Semaphore(5)
            await _bruteforce_chunk("example.com", ["www", "api"], sem, found, wildcard_ips)

        assert len(found) == 1
        assert found[0].name == "api.example.com"
