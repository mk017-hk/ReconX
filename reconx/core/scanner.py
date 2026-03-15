"""
Port scanner module — async TCP scanning with service-aware version detection.

Key features:
  - Concurrent async TCP port scanning
  - Protocol-aware banner grabbing (SSH, FTP, SMTP, HTTP, Redis, MySQL, etc.)
  - Structured (product, version) extraction per service type
  - Confidence scoring based on fingerprint quality
  - Rate limiting via delay/jitter parameters
"""

import asyncio
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Service map & port lists
# ─────────────────────────────────────────────────────────────

SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 2376: "Docker-TLS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 135, 139, 143, 194, 389,
    443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433,
    1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376,
    3306, 3389, 3690, 4333, 4444, 4848, 5000, 5432, 5900, 5984, 6379,
    6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 7001,
    7002, 7070, 7077, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8172,
    8443, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 11211, 27017,
    27018, 27019, 28017, 50000, 50070, 50075,
]

# Ports that should be wrapped in TLS when banner grabbing
_TLS_PORTS = {443, 8443, 465, 636, 993, 995, 2376}


# ─────────────────────────────────────────────────────────────
# Protocol-aware probes  {port: (probe_bytes, read_bytes)}
# ─────────────────────────────────────────────────────────────

_PROBES: dict[int, tuple[bytes, int]] = {
    # Connect-time banner protocols (send nothing, read banner)
    21:    (b"",                                             512),   # FTP
    22:    (b"",                                             256),   # SSH
    25:    (b"EHLO reconx\r\n",                             512),   # SMTP
    110:   (b"",                                             256),   # POP3
    143:   (b"",                                             256),   # IMAP
    587:   (b"EHLO reconx\r\n",                             512),   # SMTP submission
    465:   (b"EHLO reconx\r\n",                             512),   # SMTPS
    # HTTP
    80:    (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    8080:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    8000:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    8008:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    8081:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    8888:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",   2048),
    # Redis – inline PING
    6379:  (b"*1\r\n$4\r\nPING\r\n",                       256),
    # Memcached – stats
    11211: (b"version\r\n",                                 256),
    # MySQL – read handshake (send nothing)
    3306:  (b"",                                             512),
    # PostgreSQL – send nothing, read error banner
    5432:  (b"",                                             256),
    # MongoDB – OP_MSG isMaster
    27017: (
        b"\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\xff\xff\xff\xff\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00",
        512,
    ),
    # Telnet
    23:    (b"",                                             256),
}


# ─────────────────────────────────────────────────────────────
# Service-aware banner fingerprinting
# ─────────────────────────────────────────────────────────────
#
# Each function receives the raw banner string and returns (product, version).
# An empty string for either field means "not identified".

def _fp_ssh(raw: str) -> tuple[str, str]:
    """SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"""
    m = re.search(r"SSH-[\d.]+-(\w+)[_-]([\d]+\.[\d.a-z]+)", raw)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"SSH-[\d.]+-(\S+)", raw)
    if m:
        return m.group(1), ""
    return "", ""


def _fp_ftp(raw: str) -> tuple[str, str]:
    """220 ProFTPD 1.3.6 Server ..."""
    m = re.search(
        r"220[- ].*?(ProFTPD|vsftpd|FileZilla Server|Pure-FTPd|WU-FTPD)[/ ]?([\d.]+)?",
        raw, re.I,
    )
    if m:
        return m.group(1), (m.group(2) or "")
    return "", ""


def _fp_smtp(raw: str) -> tuple[str, str]:
    """220 mail.example.com ESMTP Postfix (Ubuntu)"""
    m = re.search(
        r"220[- ]\S+ ESMTP (Postfix|Exim|Sendmail|Microsoft Exchange)[/ ]?([\d.]+)?",
        raw, re.I,
    )
    if m:
        return m.group(1), (m.group(2) or "")
    return "", ""


def _fp_pop3(raw: str) -> tuple[str, str]:
    """+OK Dovecot ready."""
    m = re.search(r"\+OK\s+(.*?)\s+ready", raw, re.I)
    if m:
        return m.group(1), ""
    m = re.search(r"\+OK\s+(\S+)", raw, re.I)
    if m:
        return m.group(1), ""
    return "", ""


def _fp_imap(raw: str) -> tuple[str, str]:
    """* OK [CAPABILITY ...] Dovecot ready."""
    m = re.search(r"\* OK\s+(.*?)\s+ready", raw, re.I)
    if m:
        return m.group(1), ""
    return "", ""


def _fp_http(raw: str) -> tuple[str, str]:
    """Server: Apache/2.4.41 (Ubuntu)  /  Server: nginx/1.24.0"""
    # Match the product token (letters, digits, dots, dashes) then optional /version
    m = re.search(r"Server:\s*([a-zA-Z0-9._-]+)(?:/([\d.]+))?", raw, re.I)
    if m:
        return m.group(1), (m.group(2) or "")
    return "", ""


def _fp_redis(raw: str) -> tuple[str, str]:
    """redis_version:7.0.5"""
    m = re.search(r"redis_version:([\d.]+)", raw, re.I)
    if m:
        return "Redis", m.group(1)
    if "+PONG" in raw:
        return "Redis", ""
    return "", ""


def _fp_memcached(raw: str) -> tuple[str, str]:
    """VERSION 1.6.17"""
    m = re.search(r"VERSION ([\d.]+)", raw, re.I)
    if m:
        return "Memcached", m.group(1)
    return "", ""


def _fp_mysql(raw: str) -> tuple[str, str]:
    """MySQL handshake packet — 4-byte length + \x0a + version string + \x00"""
    m = re.search(rb"[\x00-\xff]{4}\x0a([\d.a-zA-Z_-]+)\x00", raw.encode("latin-1"), re.S)
    if m:
        return "MySQL", m.group(1).decode("latin-1")
    return "", ""


def _fp_postgresql(raw: str) -> tuple[str, str]:
    """PostgreSQL error banner: 'FATAL:  invalid frontend message type'"""
    if "PostgreSQL" in raw or "postgres" in raw.lower():
        m = re.search(r"PostgreSQL ([\d.]+)", raw, re.I)
        if m:
            return "PostgreSQL", m.group(1)
        return "PostgreSQL", ""
    return "", ""


def _fp_mongodb(raw: str) -> tuple[str, str]:
    """MongoDB OP_MSG response containing version string"""
    m = re.search(r'"version"\s*:\s*"([\d.]+)"', raw)
    if m:
        return "MongoDB", m.group(1)
    return "", ""


def _fp_elasticsearch(raw: str) -> tuple[str, str]:
    """Elasticsearch HTTP response with version in JSON"""
    m = re.search(r'"number"\s*:\s*"([\d.]+)"', raw)
    if m:
        return "Elasticsearch", m.group(1)
    return "", ""


# Dispatch table: service name → fingerprint function
_FINGERPRINT_FUNCS: dict[str, Callable[[str], tuple[str, str]]] = {
    "SSH":           _fp_ssh,
    "FTP":           _fp_ftp,
    "SMTP":          _fp_smtp,
    "SMTPS":         _fp_smtp,
    "POP3":          _fp_pop3,
    "POP3S":         _fp_pop3,
    "IMAP":          _fp_imap,
    "IMAPS":         _fp_imap,
    "HTTP":          _fp_http,
    "HTTPS":         _fp_http,
    "HTTP-Alt":      _fp_http,
    "HTTPS-Alt":     _fp_http,
    "Redis":         _fp_redis,
    "Memcached":     _fp_memcached,
    "MySQL":         _fp_mysql,
    "PostgreSQL":    _fp_postgresql,
    "MongoDB":       _fp_mongodb,
    "Elasticsearch": _fp_elasticsearch,
}


def _fingerprint_banner(service: str, raw: str) -> tuple[str, str]:
    """
    Return (product, version) from a raw service banner.

    Dispatches to the service-specific fingerprint function.
    Both fields may be empty strings if the banner is unrecognised.
    """
    if not raw:
        return "", ""
    func = _FINGERPRINT_FUNCS.get(service)
    if func:
        try:
            return func(raw)
        except Exception:
            log.debug("Fingerprint error for service %s", service, exc_info=True)
    return "", ""


def _extract_version(service: str, raw: str) -> str:
    """
    Return a combined 'product version' display string for a raw banner.

    Kept for backward compatibility; prefer _fingerprint_banner() for
    structured access to product and version separately.
    """
    product, version = _fingerprint_banner(service, raw)
    if product and version:
        return f"{product} {version}"
    return product or version


# Retain for tests that import _VERSION_PATTERNS
_VERSION_PATTERNS: list = []


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str              # "open" | "closed" | "filtered"
    service: str = ""       # service type from SERVICE_MAP (e.g. "SSH", "HTTP")
    product: str = ""       # identified product (e.g. "OpenSSH", "Apache", "nginx")
    version: str = ""       # version string (e.g. "8.9p1", "2.4.41")
    banner: str = ""        # first 120 chars of raw banner
    confidence: str = "low" # "high" = version identified, "medium" = banner grabbed, "low" = no banner
    protocol: str = "tcp"


@dataclass
class ScanResult:
    host: str
    ip: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    total_scanned: int = 0
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Banner grabbing
# ─────────────────────────────────────────────────────────────

async def _grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> tuple[str, str, str]:
    """
    Protocol-aware banner grab.

    Returns (raw_banner, product, version).
    All fields are empty strings on failure.
    """
    try:
        probe_entry = _PROBES.get(port)
        probe_bytes, read_bytes = probe_entry if probe_entry else (b"\r\n", 256)

        if b"{host}" in probe_bytes:
            probe_bytes = probe_bytes.replace(b"{host}", host.encode())

        if port in _TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        if probe_bytes:
            writer.write(probe_bytes)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        raw = data.decode(errors="replace").strip()
        banner = raw[:120]
        service = SERVICE_MAP.get(port, "")
        product, version = _fingerprint_banner(service, raw)
        return banner, product, version

    except Exception:
        return "", "", ""


# ─────────────────────────────────────────────────────────────
# Port scanning
# ─────────────────────────────────────────────────────────────

async def _scan_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
    grab_banners: bool,
    delay: float = 0.0,
    jitter: float = 0.0,
) -> Optional[PortResult]:
    """Scan a single TCP port and optionally grab a service banner."""
    async with semaphore:
        if delay or jitter:
            import random
            await asyncio.sleep(delay + random.uniform(0, jitter))
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service = SERVICE_MAP.get(port, "Unknown")
            banner, product, version = "", "", ""
            if grab_banners:
                banner, product, version = await _grab_banner(host, port, timeout)

            confidence: str
            if version:
                confidence = "high"
            elif banner:
                confidence = "medium"
            else:
                confidence = "low"

            return PortResult(
                port=port,
                state="open",
                service=service,
                product=product,
                version=version,
                banner=banner,
                confidence=confidence,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def scan(
    target: str,
    ports: Optional[list[int]] = None,
    concurrency: int = 300,
    timeout: float = 1.5,
    grab_banners: bool = True,
    delay: float = 0.0,
    jitter: float = 0.0,
) -> ScanResult:
    """
    Async TCP port scan with protocol-aware service/version detection.

    Args:
        target: Hostname or IP address.
        ports: List of ports to scan. Defaults to top 100 common ports.
        concurrency: Max concurrent connections.
        timeout: Per-port connection timeout in seconds.
        grab_banners: Whether to grab service banners and extract version info.
        delay: Fixed delay (seconds) between each port probe (safe/low-noise mode).
        jitter: Random additional delay 0–jitter seconds per probe.

    Returns:
        ScanResult with all open ports, identified products, and version strings.
    """
    ports = ports or TOP_100_PORTS
    log.debug("Scanning %s — %d ports (concurrency=%d)", target, len(ports), concurrency)

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return ScanResult(host=target, error=f"DNS resolution failed: {exc}")

    semaphore = asyncio.Semaphore(concurrency)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[open]} open"),
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            f"Scanning {target}", total=len(ports), open=0
        )
        open_count = 0

        async def _tracked(port: int) -> Optional[PortResult]:
            nonlocal open_count
            result = await _scan_port(target, port, semaphore, timeout, grab_banners, delay, jitter)
            if result is not None:
                open_count += 1
            progress.update(task_id, advance=1, open=open_count)
            return result

        results = await asyncio.gather(*[_tracked(p) for p in ports])

    open_ports = sorted(
        [r for r in results if r is not None],
        key=lambda r: r.port,
    )
    log.debug("Scan complete: %d/%d ports open", len(open_ports), len(ports))

    return ScanResult(
        host=target,
        ip=ip,
        open_ports=open_ports,
        total_scanned=len(ports),
    )


def parse_port_range(port_spec: str) -> list[int]:
    """
    Parse a port specification string into a sorted list of port numbers.

    Supported formats:
      top100       — built-in list of the 100 most common ports
      top1000      — top 100 + ports 1–1024
      all          — every port from 1 to 65535
      80           — single port
      1-1024       — range (inclusive)
      22,80,443    — comma-separated list
      22,80-90,443 — mixed format
    """
    if port_spec == "top100":
        return TOP_100_PORTS
    if port_spec == "all":
        return list(range(1, 65536))
    if port_spec == "top1000":
        return sorted(set(range(1, 1025)) | set(TOP_100_PORTS))

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
