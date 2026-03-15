"""Tests for config profiles."""

import pytest
from reconx.config import ScanProfile, PRESETS, load


class TestScanProfile:
    def test_defaults(self):
        p = ScanProfile()
        assert p.ports == "top100"
        assert p.concurrency == 300
        assert p.timeout == 1.5
        assert p.dns is True
        assert p.http is True
        assert p.ssl is True
        assert p.whois is True
        assert p.subdomains is False
        assert p.udp is False
        assert p.ip_intel is False
        assert p.crawl is False
        assert p.delay == 0.0
        assert p.jitter == 0.0

    def test_defaults_no_api_keys(self):
        p = ScanProfile()
        assert p.shodan_key == ""
        assert p.virustotal_key == ""


class TestPresets:
    def test_quick_preset_disables_http(self):
        p = PRESETS["quick"]
        assert p.http is False
        assert p.ssl is False
        assert p.subdomains is False

    def test_web_preset_enables_crawl(self):
        p = PRESETS["web"]
        assert p.http is True
        assert p.ssl is True
        assert p.crawl is True

    def test_full_preset_enables_everything(self):
        p = PRESETS["full"]
        assert p.dns is True
        assert p.http is True
        assert p.ssl is True
        assert p.whois is True
        assert p.subdomains is True
        assert p.udp is True
        assert p.ip_intel is True
        assert p.crawl is True
        assert p.passive_sources is True

    def test_all_presets_exist(self):
        for name in ("quick", "web", "external", "full"):
            assert name in PRESETS


class TestLoad:
    def test_load_no_args_returns_defaults(self):
        p = load()
        assert isinstance(p, ScanProfile)
        assert p.ports == "top100"

    def test_load_with_preset(self):
        p = load(preset="quick")
        assert p.http is False

    def test_load_with_full_preset(self):
        p = load(preset="full")
        assert p.subdomains is True
        assert p.udp is True

    def test_env_api_key(self, monkeypatch):
        monkeypatch.setenv("SHODAN_API_KEY", "test_key_123")
        p = load()
        assert p.shodan_key == "test_key_123"
