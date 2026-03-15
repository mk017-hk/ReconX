"""Mock-based tests for passive source providers."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reconx.core.passive_sources import (
    PassiveResult,
    _crtsh_subdomains,
    _otx_lookup,
    gather,
)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_mock_response(status: int, json_data):
    """Create a mock aiohttp response with a given status and JSON payload."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _make_session(response):
    """Wrap a response in a minimal mock aiohttp.ClientSession."""
    session = MagicMock()
    session.get = MagicMock(return_value=response)
    return session


# ─────────────────────────────────────────────────────────────
# crt.sh
# ─────────────────────────────────────────────────────────────

class TestCrtsh:
    def test_returns_subdomains_on_200(self):
        payload = [
            {"name_value": "mail.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
        ]
        resp = _make_mock_response(200, payload)
        session = _make_session(resp)

        result = asyncio.run(
            _crtsh_subdomains("example.com", session)
        )
        assert "mail.example.com" in result
        assert "www.example.com" in result
        # wildcard entry stripped — bare domain excluded
        assert "*.example.com" not in result
        assert "example.com" not in result

    def test_returns_empty_on_non_200(self):
        resp = _make_mock_response(429, {})
        session = _make_session(resp)

        result = asyncio.run(
            _crtsh_subdomains("example.com", session)
        )
        assert result == []

    def test_returns_empty_on_network_error(self):
        import aiohttp
        session = MagicMock()
        session.get = MagicMock(side_effect=aiohttp.ClientError("network error"))

        result = asyncio.run(
            _crtsh_subdomains("example.com", session)
        )
        assert result == []

    def test_results_sorted(self):
        payload = [
            {"name_value": "z.example.com\na.example.com\nm.example.com"},
        ]
        resp = _make_mock_response(200, payload)
        session = _make_session(resp)

        result = asyncio.run(
            _crtsh_subdomains("example.com", session)
        )
        assert result == sorted(result)


# ─────────────────────────────────────────────────────────────
# AlienVault OTX
# ─────────────────────────────────────────────────────────────

class TestOtxLookup:
    def test_returns_subdomains_on_200(self):
        payload = {
            "passive_dns": [
                {"hostname": "www.example.com"},
                {"hostname": "mail.example.com"},
                {"hostname": "other.domain.com"},  # should be excluded
            ]
        }
        resp = _make_mock_response(200, payload)
        session = _make_session(resp)

        result = asyncio.run(
            _otx_lookup("example.com", session)
        )
        assert "www.example.com" in result
        assert "mail.example.com" in result
        assert "other.domain.com" not in result

    def test_returns_empty_on_error(self):
        import aiohttp
        session = MagicMock()
        session.get = MagicMock(side_effect=asyncio.TimeoutError())

        result = asyncio.run(
            _otx_lookup("example.com", session)
        )
        assert result == []


# ─────────────────────────────────────────────────────────────
# gather() orchestrator
# ─────────────────────────────────────────────────────────────

class TestGather:
    def test_gather_no_aiohttp(self, monkeypatch):
        monkeypatch.setattr("reconx.core.passive_sources.HAS_AIOHTTP", False)
        result = asyncio.run(
            gather("example.com")
        )
        assert isinstance(result, PassiveResult)
        assert len(result.errors) > 0

    def test_gather_merges_free_providers(self, monkeypatch):
        """Free providers (crt.sh, OTX) are always called; results are merged."""
        async def fake_crtsh(domain, session):
            return ["www.example.com", "mail.example.com"]

        async def fake_otx(target, session):
            return ["vpn.example.com"]

        monkeypatch.setattr("reconx.core.passive_sources._crtsh_subdomains", fake_crtsh)
        monkeypatch.setattr("reconx.core.passive_sources._otx_lookup", fake_otx)

        result = asyncio.run(
            gather("example.com")
        )
        assert "www.example.com" in result.subdomains
        assert "mail.example.com" in result.subdomains
        assert "vpn.example.com" in result.subdomains

    def test_gather_skips_shodan_without_key(self, monkeypatch):
        """Shodan must NOT be called when no API key is provided."""
        called = {}

        async def fake_crtsh(domain, session):
            return []

        async def fake_otx(target, session):
            return []

        async def fake_shodan(target, key, session):
            called["shodan"] = True
            return None

        monkeypatch.setattr("reconx.core.passive_sources._crtsh_subdomains", fake_crtsh)
        monkeypatch.setattr("reconx.core.passive_sources._otx_lookup", fake_otx)
        monkeypatch.setattr("reconx.core.passive_sources._shodan_lookup", fake_shodan)

        asyncio.run(
            gather("example.com", shodan_key="")
        )
        assert "shodan" not in called

    def test_gather_calls_shodan_with_key(self, monkeypatch):
        """Shodan IS called when an API key is provided."""
        called = {}

        async def fake_crtsh(domain, session):
            return []

        async def fake_otx(target, session):
            return []

        async def fake_shodan(target, key, session):
            called["shodan"] = True
            return None

        async def fake_shodan_dns(domain, key, session):
            return []

        monkeypatch.setattr("reconx.core.passive_sources._crtsh_subdomains", fake_crtsh)
        monkeypatch.setattr("reconx.core.passive_sources._otx_lookup", fake_otx)
        monkeypatch.setattr("reconx.core.passive_sources._shodan_lookup", fake_shodan)
        monkeypatch.setattr("reconx.core.passive_sources._shodan_dns", fake_shodan_dns)

        asyncio.run(
            gather("example.com", shodan_key="test_key_abc")
        )
        assert called.get("shodan") is True
