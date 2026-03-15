"""
Port scanner module - async TCP port scanning with service/banner detection.
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn

# Common service banners / port-to-service map
SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
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


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class ScanResult:
    host: str
    ip: str = ""
    open_ports: list[PortResult] = field(default_factory=list)
    total_scanned: int = 0
    error: Optional[str] = None


async def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        # Send a generic probe for common protocols
        probes = {
            21: b"",         # FTP sends banner on connect
            22: b"",         # SSH sends banner on connect
            25: b"EHLO recon\r\n",
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            8080: b"HEAD / HTTP/1.0\r\n\r\n",
        }
        probe = probes.get(port, b"\r\n")
        if probe:
            writer.write(probe)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode(errors="replace").strip()[:120]
    except Exception:
        return ""


async def _scan_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
    grab_banners: bool,
) -> Optional[PortResult]:
    """Scan a single TCP port."""
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            service = SERVICE_MAP.get(port, "Unknown")
            banner = ""
            if grab_banners:
                banner = await _grab_banner(host, port, timeout)

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def scan(
    target: str,
    ports: Optional[list[int]] = None,
    concurrency: int = 300,
    timeout: float = 1.5,
    grab_banners: bool = True,
) -> ScanResult:
    """
    Async TCP port scan.

    Args:
        target: Hostname or IP address.
        ports: List of ports to scan. Defaults to top 100 common ports.
        concurrency: Max concurrent connections.
        timeout: Per-port connection timeout in seconds.
        grab_banners: Whether to grab service banners from open ports.

    Returns:
        ScanResult with all open ports and metadata.
    """
    ports = ports or TOP_100_PORTS

    # Resolve IP
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
            result = await _scan_port(target, port, semaphore, timeout, grab_banners)
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
        # Extended common ports
        return list(range(1, 1025)) + TOP_100_PORTS

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)
