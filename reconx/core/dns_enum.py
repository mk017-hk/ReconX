"""
DNS enumeration module - resolves multiple record types and detects misconfigs.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

# Common security-relevant TXT record prefixes
SECURITY_RECORD_PREFIXES = ("v=spf", "v=dmarc", "v=dkim")


@dataclass
class DNSRecord:
    record_type: str
    value: str


@dataclass
class ZoneTransferResult:
    nameserver: str
    success: bool
    records: list[str] = field(default_factory=list)


@dataclass
class DNSResult:
    domain: str
    records: dict[str, list[DNSRecord]] = field(default_factory=dict)
    zone_transfers: list[ZoneTransferResult] = field(default_factory=list)
    security_findings: list[str] = field(default_factory=list)
    error: Optional[str] = None


async def _query_record(domain: str, record_type: str) -> list[DNSRecord]:
    """Query a single DNS record type."""
    if not HAS_DNSPYTHON:
        return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        answers = await resolver.resolve(domain, record_type)
        records = []
        for rdata in answers:
            records.append(DNSRecord(record_type=record_type, value=str(rdata)))
        return records
    except (dns.exception.DNSException, Exception):
        return []


def _attempt_zone_transfer(domain: str, nameserver: str) -> ZoneTransferResult:
    """Attempt AXFR zone transfer against a specific nameserver."""
    if not HAS_DNSPYTHON:
        return ZoneTransferResult(nameserver=nameserver, success=False)
    try:
        import dns.query
        import dns.zone

        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        records = [f"{name} {rdata}" for name, node in z.nodes.items()
                   for rdataset in node.rdatasets
                   for rdata in rdataset]
        return ZoneTransferResult(nameserver=nameserver, success=True, records=records)
    except Exception:
        return ZoneTransferResult(nameserver=nameserver, success=False)


def _check_security_findings(result: DNSResult) -> None:
    """Analyse records for common misconfigurations."""
    txt_values = [r.value for r in result.records.get("TXT", [])]
    ns_values = [r.value for r in result.records.get("NS", [])]

    # SPF
    spf = [v for v in txt_values if v.lower().startswith("v=spf")]
    if not spf:
        result.security_findings.append("No SPF record found — email spoofing may be possible")
    elif "+all" in " ".join(spf):
        result.security_findings.append("SPF record uses '+all' — allows ANY server to send mail")

    # DMARC
    dmarc_domain = f"_dmarc.{result.domain}"
    # (checked separately in enumerate; flag if missing)
    dmarc_records = result.records.get("_DMARC", [])
    if not dmarc_records:
        result.security_findings.append("No DMARC record found — phishing protection absent")

    # Zone transfer
    for zt in result.zone_transfers:
        if zt.success:
            result.security_findings.append(
                f"Zone transfer SUCCESSFUL from {zt.nameserver} — CRITICAL misconfiguration"
            )

    # Multiple NS servers (good practice, flag if only 1)
    if len(ns_values) < 2:
        result.security_findings.append("Only one NS record — no DNS redundancy")


async def enumerate(domain: str, check_zone_transfer: bool = True) -> DNSResult:
    """
    Full DNS enumeration for a domain.

    Args:
        domain: Target domain name.
        check_zone_transfer: Whether to attempt AXFR zone transfers.

    Returns:
        DNSResult with all discovered records and security findings.
    """
    result = DNSResult(domain=domain)

    if not HAS_DNSPYTHON:
        result.error = "dnspython not installed. Run: pip install dnspython"
        return result

    # Query all record types concurrently
    tasks = {rt: _query_record(domain, rt) for rt in RECORD_TYPES}
    # Also query DMARC subdomain
    tasks["_DMARC"] = _query_record(f"_dmarc.{domain}", "TXT")

    gathered = await asyncio.gather(*tasks.values())
    for record_type, records in zip(tasks.keys(), gathered):
        if records:
            result.records[record_type] = records

    # Zone transfer attempts
    if check_zone_transfer:
        ns_records = result.records.get("NS", [])
        nameservers = [r.value.rstrip(".") for r in ns_records]
        loop = asyncio.get_event_loop()
        zt_results = await asyncio.gather(*[
            loop.run_in_executor(None, _attempt_zone_transfer, domain, ns)
            for ns in nameservers
        ])
        result.zone_transfers = list(zt_results)

    _check_security_findings(result)
    return result
