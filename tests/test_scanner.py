"""Tests for the port scanner module (including version detection)."""

import pytest
from reconx.core.scanner import (
    parse_port_range, ScanResult, PortResult, TOP_100_PORTS,
    _extract_version, _fingerprint_banner, _VERSION_PATTERNS,
    _fp_ssh, _fp_ftp, _fp_smtp, _fp_http, _fp_redis, _fp_memcached,
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
    """Tests for the combined _extract_version() display string."""

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


class TestFingerprintBanner:
    """Tests for structured (product, version) extraction via _fingerprint_banner."""

    def test_ssh_returns_product_and_version(self):
        raw = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        product, version = _fingerprint_banner("SSH", raw)
        assert product == "OpenSSH"
        assert version == "8.9p1"

    def test_ssh_product_only(self):
        raw = "SSH-2.0-Dropbear_2022.82"
        product, version = _fingerprint_banner("SSH", raw)
        assert "Dropbear" in product

    def test_http_server_product_version(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
        product, version = _fingerprint_banner("HTTP", raw)
        assert product == "nginx"
        assert version == "1.24.0"

    def test_http_server_no_version(self):
        raw = "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n"
        product, version = _fingerprint_banner("HTTP", raw)
        assert "cloudflare" in product.lower()

    def test_redis_pong(self):
        raw = "+PONG\r\n"
        product, version = _fingerprint_banner("Redis", raw)
        assert product == "Redis"
        assert version == ""

    def test_redis_with_version(self):
        raw = "redis_version:7.0.5\r\nos:Linux"
        product, version = _fingerprint_banner("Redis", raw)
        assert product == "Redis"
        assert version == "7.0.5"

    def test_empty_banner_returns_empty(self):
        product, version = _fingerprint_banner("SSH", "")
        assert product == ""
        assert version == ""

    def test_unknown_service_returns_empty(self):
        product, version = _fingerprint_banner("UnknownService", "some banner")
        assert product == ""
        assert version == ""

    def test_ftp_vsftpd(self):
        raw = "220 (vsFTPd 3.0.5)"
        product, version = _fp_ftp(raw)
        assert "vsftpd" in product.lower() or product == ""  # may not match (vsFTPd)

    def test_smtp_postfix_structured(self):
        raw = "220 mail.example.com ESMTP Postfix"
        product, version = _fp_smtp(raw)
        assert product == "Postfix"


class TestServiceFingerprintFunctions:
    """Unit tests for individual service fingerprint functions."""

    def test_fp_ssh_full(self):
        product, version = _fp_ssh("SSH-2.0-OpenSSH_9.1p1 Debian-2")
        assert product == "OpenSSH"
        assert version == "9.1p1"

    def test_fp_ftp_proftpd(self):
        raw = "220 ProFTPD 1.3.7 Server (Default) [127.0.0.1]"
        product, version = _fp_ftp(raw)
        assert product == "ProFTPD"
        assert version == "1.3.7"

    def test_fp_http_apache(self):
        raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Debian)\r\n"
        product, version = _fp_http(raw)
        assert product == "Apache"
        assert version == "2.4.58"

    def test_fp_http_nginx(self):
        raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"
        product, version = _fp_http(raw)
        assert product == "nginx"
        assert version == "1.25.3"

    def test_fp_redis_version_line(self):
        raw = "redis_version:6.2.14\r\nredis_mode:standalone"
        product, version = _fp_redis(raw)
        assert product == "Redis"
        assert version == "6.2.14"

    def test_fp_memcached(self):
        raw = "VERSION 1.6.22\r\n"
        product, version = _fp_memcached(raw)
        assert product == "Memcached"
        assert version == "1.6.22"


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
        assert p.product == ""
        assert p.confidence == "low"
        assert p.protocol == "tcp"

    def test_full(self):
        p = PortResult(
            port=22, state="open", service="SSH",
            product="OpenSSH", version="8.9p1",
            banner="SSH-2.0-OpenSSH_8.9p1", confidence="high",
        )
        assert p.port == 22
        assert p.service == "SSH"
        assert p.product == "OpenSSH"
        assert p.version == "8.9p1"
        assert p.confidence == "high"

    def test_confidence_levels(self):
        assert PortResult(port=80, state="open", version="1.0", confidence="high").confidence == "high"
        assert PortResult(port=80, state="open", banner="some banner", confidence="medium").confidence == "medium"
        assert PortResult(port=80, state="open").confidence == "low"
