"""
UDP scanner module — probes common UDP services with protocol-specific payloads.

Supported ports:
  53  — DNS (version.bind query)
  67  — DHCP Discover
  69  — TFTP read request
  123 — NTP (client request)
  161 — SNMP v1 GetRequest (community: public)
  500 — IKE/IPSec (SA_INIT)
  1900 — SSDP/UPnP
  4500 — IKE NAT-T
  5353 — mDNS
"""

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TextColumn


# ─────────────────────────────────────────────────────────────
# UDP probe payloads
# ─────────────────────────────────────────────────────────────

def _dns_probe() -> bytes:
    """DNS query for version.bind (CHAOS class)."""
    return (
        b"\xaa\xbb"          # transaction ID
        b"\x00\x00"          # flags: standard query
        b"\x00\x01"          # questions: 1
        b"\x00\x00\x00\x00\x00\x00"  # answers/auth/additional: 0
        b"\x07version\x04bind\x00"   # QNAME: version.bind
        b"\x00\x10"          # QTYPE: TXT
        b"\x00\x03"          # QCLASS: CHAOS
    )


def _ntp_probe() -> bytes:
    """NTPv3 client request (mode 3)."""
    packet = bytearray(48)
    packet[0] = 0x1B   # LI=0, VN=3, mode=3
    return bytes(packet)


def _snmp_probe() -> bytes:
    """SNMPv1 GetRequest for sysDescr.0 with community 'public'."""
    # Minimal SNMPv1 GetRequest
    oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # 1.3.6.1.2.1.1.1.0
    varbind = b"\x30\x0b\x06\x09" + oid + b"\x05\x00"
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
    pdu = (
        b"\xa0"                          # GetRequest PDU
        + bytes([0x13 + len(varbind)])
        + b"\x02\x01\x00"               # request-id = 0
        + b"\x02\x01\x00"               # error-status = 0
        + b"\x02\x01\x00"               # error-index = 0
        + varbind_list
    )
    community = b"public"
    msg = (
        b"\x02\x01\x00"                 # version: 1
        + b"\x04" + bytes([len(community)]) + community
        + pdu
    )
    return b"\x30" + bytes([len(msg)]) + msg


def _ssdp_probe() -> bytes:
    """SSDP M-SEARCH discovery."""
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n"
        b"\r\n"
    )


def _tftp_probe() -> bytes:
    """TFTP Read Request for a nonexistent file (to trigger error response)."""
    filename = b"reconx_probe"
    return b"\x00\x01" + filename + b"\x00octet\x00"


def _dhcp_discover() -> bytes:
    """DHCP DISCOVER packet."""
    import os, time
    xid = os.urandom(4)
    mac = b"\xde\xad\xbe\xef\xca\xfe"
    packet = (
        b"\x01"         # op: BOOTREQUEST
        b"\x01"         # htype: Ethernet
        b"\x06"         # hlen: 6
        b"\x00"         # hops
        + xid           # xid
        + b"\x00\x00"   # secs
        + b"\x80\x00"   # flags: broadcast
        + b"\x00" * 4   # ciaddr
        + b"\x00" * 4   # yiaddr
        + b"\x00" * 4   # siaddr
        + b"\x00" * 4   # giaddr
        + mac + b"\x00" * 10   # chaddr (16 bytes)
        + b"\x00" * 64  # sname
        + b"\x00" * 128 # file
        + b"\x63\x82\x53\x63"  # magic cookie
        + b"\x35\x01\x01"      # DHCP option 53: DISCOVER
        + b"\xff"              # end option
    )
    return packet


def _ike_probe() -> bytes:
    """IKEv1 SA_INIT with proposed transforms."""
    return (
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # initiator SPI
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # responder SPI
        b"\x01"  # next payload: SA
        b"\x10"  # version: 1.0
        b"\x02"  # exchange: Identity Protection
        b"\x00"  # flags
        b"\x00\x00\x00\x01"  # message ID
        b"\x00\x00\x00\x84"  # length: 132
        # SA payload (minimal)
        b"\x00\x00\x00\x78\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x6c"
        b"\x01\x01\x00\x04\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x07"
        b"\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01"
        b"\x00\x0c\x00\x04\x00\x01\x51\x80\x03\x00\x00\x24\x02\x01\x00\x00"
        b"\x80\x01\x00\x07\x80\x02\x00\x02\x80\x03\x00\x03\x80\x04\x00\x02"
        b"\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\x51\x80\x03\x00\x00\x24"
        b"\x03\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01"
        b"\x80\x04\x00\x02\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\x51\x80"
        b"\x00\x00\x00\x24\x04\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02"
        b"\x80\x03\x00\x03\x80\x04\x00\x02\x80\x0b\x00\x01\x00\x0c\x00\x04"
        b"\x00\x01\x51\x80"
    )


UDP_PROBES: dict[int, bytes] = {
    53:   _dns_probe(),
    67:   _dhcp_discover(),
    69:   _tftp_probe(),
    123:  _ntp_probe(),
    161:  _snmp_probe(),
    500:  _ike_probe(),
    1900: _ssdp_probe(),
    4500: _ike_probe(),
    5353: _dns_probe(),
}

UDP_SERVICE_MAP: dict[int, str] = {
    53: "DNS", 67: "DHCP", 69: "TFTP", 123: "NTP",
    161: "SNMP", 162: "SNMP-Trap", 500: "IKE/IPSec",
    514: "Syslog", 1194: "OpenVPN", 1900: "SSDP/UPnP",
    4500: "IKE-NAT-T", 5353: "mDNS",
}

DEFAULT_UDP_PORTS = [53, 67, 69, 123, 161, 500, 1900, 4500, 5353]


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class UDPPortResult:
    port: int
    state: str   # "open" | "open|filtered" | "closed"
    service: str = ""
    banner: str = ""
    protocol: str = "udp"


@dataclass
class UDPScanResult:
    host: str
    ip: str = ""
    open_ports: list[UDPPortResult] = field(default_factory=list)
    total_scanned: int = 0
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Async UDP probe
# ─────────────────────────────────────────────────────────────

async def _probe_udp_port(
    host: str,
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> Optional[UDPPortResult]:
    """Send a UDP probe and classify the response."""
    async with semaphore:
        payload = UDP_PROBES.get(port, b"\x00")
        service = UDP_SERVICE_MAP.get(port, "Unknown")
        loop = asyncio.get_event_loop()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            await loop.sock_connect(sock, (ip, port))
            await loop.sock_sendall(sock, payload)

            try:
                data = await asyncio.wait_for(
                    loop.sock_recv(sock, 1024), timeout=timeout
                )
                banner = data[:80].decode(errors="replace").strip()
                return UDPPortResult(port=port, state="open", service=service, banner=banner)
            except asyncio.TimeoutError:
                # No response — could be open|filtered (common for UDP)
                return UDPPortResult(port=port, state="open|filtered", service=service)
            finally:
                sock.close()

        except ConnectionRefusedError:
            # ICMP port unreachable — port is closed
            return None
        except OSError:
            return None


async def scan(
    target: str,
    ports: Optional[list[int]] = None,
    concurrency: int = 50,
    timeout: float = 2.0,
) -> UDPScanResult:
    """
    UDP port scan with protocol-specific probes.

    Args:
        target: Hostname or IP address.
        ports: Ports to probe. Defaults to common UDP ports.
        concurrency: Max concurrent UDP probes.
        timeout: Per-port response timeout in seconds.

    Returns:
        UDPScanResult with open/open|filtered ports.
    """
    ports = ports or DEFAULT_UDP_PORTS

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        return UDPScanResult(host=target, error=f"DNS resolution failed: {exc}")

    semaphore = asyncio.Semaphore(concurrency)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=True,
    ) as progress:
        task_id = progress.add_task(f"UDP scan {target}", total=len(ports))

        async def _tracked(port: int) -> Optional[UDPPortResult]:
            result = await _probe_udp_port(target, ip, port, timeout, semaphore)
            progress.update(task_id, advance=1)
            return result

        results = await asyncio.gather(*[_tracked(p) for p in ports])

    open_ports = sorted(
        [r for r in results if r is not None],
        key=lambda r: r.port,
    )

    return UDPScanResult(
        host=target,
        ip=ip,
        open_ports=open_ports,
        total_scanned=len(ports),
    )
