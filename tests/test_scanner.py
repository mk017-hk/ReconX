"""Tests for the port scanner module (including version detection)."""

import pytest
from reconx.core.scanner import (
    parse_port_range, ScanResult, PortResult, TOP_100_PORTS,
    _extract_version, _VERSION_PATTERNS,
)


class TestParsePortRange:
    def test_top100_preset(self):
        ports = parse_port_range("top100")
        assert ports == TOP_100_PORTS
        assert 80 in ports
        assert 443 in ports

    def test_all_preset(self):
        ports = parse_port_range("all")
        assert len(ports) == 65535
        assert 1 in ports
        assert 65535 in ports

    def test_top1000_preset(self):
        ports = parse_port_range("top1000")
        assert len(ports) > 1000
        assert 80 in ports

    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_range(self):
        ports = parse_port_range("1-5")
        assert ports == [1, 2, 3, 4, 5]

    def test_comma_separated(self):
        ports = parse_port_range("22,80,443")
        assert ports == [22, 80, 443]

    def test_mixed(self):
        ports = parse_port_range("22,80-82,443")
        assert ports == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        ports = parse_port_range("80,80,80")
        assert ports.count(80) == 1

    def test_sorted_output(self):
        ports = parse_port_range("443,22,80")
        assert ports == sorted(ports)


class TestVersionExtraction:
    def test_ssh_version(self):
        raw = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        version = _extract_version("SSH", raw)
        assert "OpenSSH" in version

    def test_ftp_proftpd(self):
        raw = "220 ProFTPD 1.3.6 Server (ProFTPD Default Installation)"
        version = _extract_version("FTP", raw)
        assert "ProFTPD" in version

    def test_smtp_postfix(self):
        raw = "220 mail.example.com ESMTP Postfix (Ubuntu)"
        version = _extract_version("SMTP", raw)
        assert "Postfix" in version

    def test_http_server_header(self):
        raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51 (Ubuntu)\r\n"
        version = _extract_version("HTTP", raw)
        assert "Apache" in version

    def test_redis_version(self):
        raw = "redis_version:7.0.5\r\nos:Linux"
        version = _extract_version("Redis", raw)
        assert "Redis" in version
        assert "7.0.5" in version

    def test_memcached_version(self):
        raw = "VERSION 1.6.17\r\n"
        version = _extract_version("Memcached", raw)
        assert "Memcached" in version
        assert "1.6.17" in version

    def test_empty_banner(self):
        version = _extract_version("SSH", "")
        assert version == ""


class TestScanResult:
    def test_default_fields(self):
        result = ScanResult(host="example.com")
        assert result.host == "example.com"
        assert result.ip == ""
        assert result.open_ports == []
        assert result.total_scanned == 0
        assert result.error is None

    def test_with_open_ports(self):
        port = PortResult(port=80, state="open", service="HTTP", version="Apache/2.4")
        result = ScanResult(host="example.com", ip="1.2.3.4", open_ports=[port], total_scanned=100)
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == 80
        assert result.open_ports[0].version == "Apache/2.4"

    def test_error_state(self):
        result = ScanResult(host="bad.host", error="DNS resolution failed")
        assert "DNS" in result.error


class TestPortResult:
    def test_defaults(self):
        p = PortResult(port=443, state="open")
        assert p.service == ""
        assert p.banner == ""
        assert p.version == ""
        assert p.protocol == "tcp"

    def test_full(self):
        p = PortResult(port=22, state="open", service="SSH", banner="SSH-2.0-OpenSSH_8.9", version="OpenSSH 8.9")
        assert p.port == 22
        assert p.service == "SSH"
        assert "OpenSSH" in p.banner
        assert "OpenSSH" in p.version
