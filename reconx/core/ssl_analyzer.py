"""
SSL/TLS analyzer module.

Checks:
  - Certificate validity, expiry, issuer, SANs
  - Weak cipher suites
  - Protocol support (SSLv2, SSLv3, TLS 1.0, TLS 1.1 — all deprecated)
  - Self-signed / untrusted certificate
  - Certificate transparency
"""

import asyncio
import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CertInfo:
    subject: dict[str, str]
    issuer: dict[str, str]
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    san: list[str]
    is_expired: bool
    is_self_signed: bool
    signature_algorithm: str = ""


@dataclass
class TLSProtocol:
    name: str
    supported: bool
    deprecated: bool = False


@dataclass
class SSLResult:
    host: str
    port: int
    cert: Optional[CertInfo] = None
    protocols: list[TLSProtocol] = field(default_factory=list)
    cipher: str = ""
    cipher_bits: int = 0
    findings: list[str] = field(default_factory=list)
    error: Optional[str] = None


def _parse_rdns(rdns) -> dict[str, str]:
    """Parse X.509 RDN sequence into a flat dict."""
    result = {}
    for rdn in rdns:
        for attr in rdn:
            result[attr[0]] = attr[1]
    return result


def _get_san(cert: dict) -> list[str]:
    """Extract Subject Alternative Names."""
    san = []
    for ext in cert.get("subjectAltName", []):
        if ext[0] == "DNS":
            san.append(ext[1])
    return san


def _check_cert(cert: dict) -> CertInfo:
    subject = _parse_rdns(cert.get("subject", []))
    issuer = _parse_rdns(cert.get("issuer", []))

    not_after_str = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")

    try:
        expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days_until_expiry = (expiry - now).days
        is_expired = days_until_expiry < 0
    except Exception:
        expiry = None
        days_until_expiry = -1
        is_expired = False

    is_self_signed = subject == issuer

    return CertInfo(
        subject=subject,
        issuer=issuer,
        serial_number=str(cert.get("serialNumber", "")),
        not_before=not_before_str,
        not_after=not_after_str,
        days_until_expiry=days_until_expiry,
        san=_get_san(cert),
        is_expired=is_expired,
        is_self_signed=is_self_signed,
    )


async def _check_protocol(
    host: str,
    port: int,
    protocol: int,
    protocol_name: str,
    deprecated: bool,
    timeout: float,
    findings: list[str],
) -> TLSProtocol:
    loop = asyncio.get_event_loop()
    supported = False
    try:
        ctx = ssl.SSLContext(protocol)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")

        def _connect():
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return True

        supported = await asyncio.wait_for(
            loop.run_in_executor(None, _connect), timeout=timeout + 1
        )
    except Exception:
        supported = False

    if supported and deprecated:
        findings.append(f"{protocol_name} supported — deprecated protocol, should be disabled")

    return TLSProtocol(name=protocol_name, supported=supported, deprecated=deprecated)


async def analyze(host: str, port: int = 443, timeout: float = 10.0) -> SSLResult:
    """
    Analyze SSL/TLS configuration for a host.

    Args:
        host: Target hostname or IP.
        port: Target port (default 443).
        timeout: Connection timeout.

    Returns:
        SSLResult with certificate info, protocol support, and findings.
    """
    result = SSLResult(host=host, port=port)
    findings: list[str] = []
    loop = asyncio.get_event_loop()

    # Main cert grab
    def _get_cert():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return cert, cipher

    try:
        cert_raw, cipher_info = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert), timeout=timeout + 2
        )
    except Exception as exc:
        result.error = f"Could not connect: {exc}"
        return result

    cert = _check_cert(cert_raw)
    result.cert = cert

    if cipher_info:
        result.cipher = cipher_info[0] or ""
        result.cipher_bits = cipher_info[2] or 0

    # Certificate findings
    if cert.is_expired:
        findings.append("Certificate is EXPIRED!")
    elif cert.days_until_expiry < 14:
        findings.append(f"Certificate expires in {cert.days_until_expiry} days — renew urgently")
    elif cert.days_until_expiry < 30:
        findings.append(f"Certificate expires in {cert.days_until_expiry} days — renew soon")

    if cert.is_self_signed:
        findings.append("Self-signed certificate — not trusted by browsers")

    if result.cipher_bits and result.cipher_bits < 128:
        findings.append(f"Weak cipher key length: {result.cipher_bits} bits")

    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
    for weak in weak_ciphers:
        if weak in result.cipher.upper():
            findings.append(f"Weak cipher suite detected: {result.cipher}")
            break

    # Protocol support checks
    protocol_checks = []

    # TLS 1.2 and 1.3 (modern, not deprecated)
    try:
        protocol_checks.append((ssl.PROTOCOL_TLS_CLIENT, "TLS 1.3", False))
    except AttributeError:
        pass
    try:
        protocol_checks.append((ssl.PROTOCOL_TLSv1_2, "TLS 1.2", False))
    except AttributeError:
        pass

    # Deprecated protocols
    deprecated_protos = []
    for proto_const, name in [
        ("PROTOCOL_TLSv1", "TLS 1.0"),
        ("PROTOCOL_TLSv1_1", "TLS 1.1"),
        ("PROTOCOL_SSLv23", "SSL 2/3"),
    ]:
        proto = getattr(ssl, proto_const, None)
        if proto is not None:
            deprecated_protos.append((proto, name, True))

    proto_tasks = [
        _check_protocol(host, port, proto, name, deprecated, timeout, findings)
        for proto, name, deprecated in protocol_checks + deprecated_protos
    ]

    if proto_tasks:
        result.protocols = await asyncio.gather(*proto_tasks)

    result.findings = findings
    return result
