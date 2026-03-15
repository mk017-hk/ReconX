"""
Port scanner module - async TCP port scanning with protocol-aware service/version detection.
"""

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn

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

# ─────────────────────────────────────────────────────────────
# Protocol-aware probes  {port: (probe_bytes, read_bytes)}
# ─────────────────────────────────────────────────────────────

_PROBES: dict[int, tuple[bytes, int]] = {
    # Connect-time banner protocols (send nothing, read banner)
    21:    (b"",                              512),   # FTP
    22:    (b"",                              256),   # SSH
    25:    (b"EHLO reconx\r\n",              512),   # SMTP
    110:   (b"",                              256),   # POP3
    143:   (b"",                              256),   # IMAP
    587:   (b"EHLO reconx\r\n",              512),   # SMTP submission
    465:   (b"EHLO reconx\r\n",              512),   # SMTPS
    # HTTP
    80:    (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    8080:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    8000:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    8008:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    8081:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    8888:  (b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",  2048),
    # Redis – inline PING
    6379:  (b"*1\r\n$4\r\nPING\r\n",        256),
    # Memcached – stats
    11211: (b"version\r\n",                  256),
    # MySQL – read handshake (send nothing)
    3306:  (b"",                              512),
    # PostgreSQL – send nothing, read error banner
    5432:  (b"",                              256),
    # MongoDB – OP_MSG isMaster
    27017: (b"\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             b"\x00\xff\xff\xff\xff\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
             b"\x00\x00\x00\x00",  512),
    # Generic fallback
    23:    (b"",                              256),   # Telnet
}

# ─────────────────────────────────────────────────────────────
# Version extraction regexes  {service: [(pattern, group_template)]}
# ─────────────────────────────────────────────────────────────

_VERSION_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    ("SSH",        re.compile(r"SSH-[\d.]+-(\S+)"),                      r"\1"),
    # FTP: "220 ProFTPD 1.3.6 Server"  /  "220 FileZilla Server 1.8.1"
    ("FTP",        re.compile(r"220[- ].*?(ProFTPD|vsftpd|FileZilla Server|Pure-FTPd|WU-FTPD)[/ ]?([\d.]+)?", re.I),  r"\1 \2"),
    # SMTP: "220 mail.example.com ESMTP Postfix (Ubuntu)"
    ("SMTP",       re.compile(r"220[- ]\S+ ESMTP (\S+)(?: \(([^)]+)\))?", re.I), r"\1 \2"),
    # POP3 / IMAP banners
    ("POP3",       re.compile(r"\+OK (.*?)\r?\n", re.I),                 r"\1"),
    ("IMAP",       re.compile(r"\* OK (.*?) ready", re.I),               r"\1"),
    # HTTP Server header
    ("HTTP",       re.compile(r"Server:\s*(.+?)[\r\n]", re.I),           r"\1"),
    # Redis: "+PONG"  or  "redis_version:7.0.5"
    ("Redis",      re.compile(r"redis_version:([\d.]+)", re.I),          r"Redis \1"),
    # Memcached: "VERSION 1.6.17"
    ("Memcached",  re.compile(r"VERSION ([\d.]+)", re.I),                r"Memcached \1"),
    # MySQL handshake starts with length + protocol version byte + version string
    ("MySQL",      re.compile(r"[\x00-\xff]{4}\x0a([\d.a-zA-Z_-]+)\x00", re.S), r"MySQL \1"),
    # MongoDB: look for "ismaster" or version string in response
    ("MongoDB",    re.compile(r'"version"\s*:\s*"([\d.]+)"'),            r"MongoDB \1"),
]


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""   # extracted version string
    protocol: str = "tcp"


@dataclass
class ScanResult:
    host: str
    ip: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    total_scanned: int = 0
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Banner / version grabbing
# ─────────────────────────────────────────────────────────────

def _extract_version(service: str, raw: str) -> str:
    """Try every version pattern and return the first match."""
    for svc, pattern, template in _VERSION_PATTERNS:
        m = pattern.search(raw)
        if m:
            try:
                version = m.expand(template).strip()
                return version
            except Exception:
                return m.group(0)[:60]
    return ""


async def _grab_banner(host: str, port: int, timeout: float = 2.0) -> tuple[str, str]:
    """
    Protocol-aware banner grab.
    Returns (raw_banner, version_string).
    """
    try:
        probe_entry = _PROBES.get(port)
        if probe_entry is None:
            probe_bytes, read_bytes = b"\r\n", 256
        else:
            probe_bytes, read_bytes = probe_entry

        # Substitute {host} placeholder in HTTP probes
        if b"{host}" in probe_bytes:
            probe_bytes = probe_bytes.replace(b"{host}", host.encode())

        # For TLS ports grab via ssl context
        use_tls = port in (443, 8443, 465, 636, 993, 995, 2376)
        if use_tls:
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
        version = _extract_version(service, raw)
        return banner, version

    except Exception:
        return "", ""


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
    """Scan a single TCP port."""
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
            banner, version = "", ""
            if grab_banners:
                banner, version = await _grab_banner(host, port, timeout)

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                version=version,
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
    Async TCP port scan with protocol-aware version detection.

    Args:
        target: Hostname or IP address.
        ports: List of ports to scan. Defaults to top 100 common ports.
        concurrency: Max concurrent connections.
        timeout: Per-port connection timeout in seconds.
        grab_banners: Whether to grab service banners / extract versions.
        delay: Fixed delay (seconds) between each port probe.
        jitter: Random additional delay 0–jitter seconds per probe.

    Returns:
        ScanResult with all open ports, services, and version strings.
    """
    ports = ports or TOP_100_PORTS

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

    return ScanResult(
        host=target,
        ip=ip,
        open_ports=open_ports,
        total_scanned=len(ports),
    )


def parse_port_range(port_spec: str) -> list[int]:
    """
    Parse a port specification string into a list of ports.

    Supports:
      - Single port: "80"
      - Range: "1-1024"
      - Comma-separated: "22,80,443"
      - Mixed: "22,80-90,443"
      - Presets: "top100", "top1000", "all"
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
