"""
Optional passive source integrations.

Architecture:
  Each provider is a standalone async function that returns normalised data.
  The gather() orchestrator runs all enabled providers concurrently and merges
  their results into a single PassiveResult.

Providers requiring API keys (skipped gracefully when key is absent):
  - Shodan          (SHODAN_API_KEY)
  - Censys          (CENSYS_API_ID + CENSYS_API_SECRET)
  - SecurityTrails  (SECURITYTRAILS_API_KEY)
  - VirusTotal      (VIRUSTOTAL_API_KEY)
  - AbuseIPDB       (ABUSEIPDB_API_KEY)

Free providers (always run, no key required):
  - crt.sh          — Certificate Transparency subdomain discovery
  - AlienVault OTX  — passive DNS threat intelligence
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class PassiveHost:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class PassiveResult:
    target: str
    hosts: list[PassiveHost] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    abuse_score: Optional[int] = None     # AbuseIPDB confidence score 0–100
    malicious: Optional[bool] = None      # VirusTotal verdict
    vt_detections: int = 0                # VirusTotal detection count
    findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# crt.sh  (Certificate Transparency — free, no key required)
# ─────────────────────────────────────────────────────────────

async def _crtsh_subdomains(domain: str, session: "aiohttp.ClientSession") -> list[str]:
    """
    Discover subdomains from Certificate Transparency logs via crt.sh.

    Returns a sorted list of unique subdomain names containing the target domain.
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                names: set[str] = set()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and "." in name and domain in name and name != domain:
                            names.add(name)
                log.debug("crt.sh: found %d subdomains for %s", len(names), domain)
                return sorted(names)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("crt.sh lookup failed for %s: %s", domain, exc)
    return []


# ─────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────

async def _shodan_lookup(
    target: str, api_key: str, session: "aiohttp.ClientSession"
) -> Optional[PassiveHost]:
    """Query Shodan host info for an IP/domain."""
    try:
        url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return PassiveHost(
                    ip=data.get("ip_str", target),
                    hostnames=data.get("hostnames", []),
                    ports=data.get("ports", []),
                    tags=data.get("tags", []),
                    source="shodan",
                )
            if resp.status == 404:
                return None
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("Shodan lookup failed: %s", exc)
    return None


async def _shodan_dns(
    domain: str, api_key: str, session: "aiohttp.ClientSession"
) -> list[str]:
    """Shodan DNS domain search for subdomains."""
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                subs = data.get("subdomains", [])
                return [f"{s}.{domain}" for s in subs]
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("Shodan DNS lookup failed: %s", exc)
    return []


# ─────────────────────────────────────────────────────────────
# Censys
# ─────────────────────────────────────────────────────────────

async def _censys_lookup(
    target: str, api_id: str, api_secret: str, session: "aiohttp.ClientSession"
) -> Optional[PassiveHost]:
    """Query Censys hosts API v2."""
    try:
        import base64
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        url = f"https://search.censys.io/api/v2/hosts/{target}"
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                result_data = data.get("result", {})
                services = result_data.get("services", [])
                ports = [s.get("port") for s in services if s.get("port")]
                hostnames = result_data.get("dns", {}).get("reverse_dns", {}).get("names", [])
                return PassiveHost(ip=target, hostnames=hostnames, ports=ports, source="censys")
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("Censys lookup failed: %s", exc)
    return None


# ─────────────────────────────────────────────────────────────
# SecurityTrails
# ─────────────────────────────────────────────────────────────

async def _securitytrails_subdomains(
    domain: str, api_key: str, session: "aiohttp.ClientSession"
) -> list[str]:
    """Fetch subdomains from SecurityTrails."""
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"apikey": api_key, "Content-Type": "application/json"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return [f"{s}.{domain}" for s in data.get("subdomains", [])]
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("SecurityTrails subdomains failed: %s", exc)
    return []


async def _securitytrails_emails(
    domain: str, api_key: str, session: "aiohttp.ClientSession"
) -> list[str]:
    """Fetch associated emails from SecurityTrails WHOIS history."""
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"
        headers = {"apikey": api_key}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                emails = [
                    c.get("email", "")
                    for c in data.get("contacts", [])
                    if "@" in c.get("email", "")
                ]
                return list(set(emails))
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("SecurityTrails emails failed: %s", exc)
    return []


# ─────────────────────────────────────────────────────────────
# VirusTotal
# ─────────────────────────────────────────────────────────────

async def _virustotal_lookup(
    target: str, api_key: str, session: "aiohttp.ClientSession"
) -> tuple[Optional[bool], int, list[str]]:
    """
    Check VirusTotal for malicious verdicts and subdomain data.

    Returns (is_malicious, detection_count, subdomains).
    """
    try:
        headers = {"x-apikey": api_key}
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                is_malicious = malicious > 0

                subs: list[str] = []
                subs_url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains"
                async with session.get(subs_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as sr:
                    if sr.status == 200:
                        sd = await sr.json(content_type=None)
                        subs = [item.get("id", "") for item in sd.get("data", []) if item.get("id")]

                return is_malicious, malicious, subs
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("VirusTotal lookup failed: %s", exc)
    return None, 0, []


# ─────────────────────────────────────────────────────────────
# AbuseIPDB
# ─────────────────────────────────────────────────────────────

async def _abuseipdb_check(
    ip: str, api_key: str, session: "aiohttp.ClientSession"
) -> Optional[int]:
    """Check AbuseIPDB confidence score (0–100)."""
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        async with session.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params,
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data.get("data", {}).get("abuseConfidenceScore")
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("AbuseIPDB check failed: %s", exc)
    return None


# ─────────────────────────────────────────────────────────────
# AlienVault OTX  (free, no key required)
# ─────────────────────────────────────────────────────────────

async def _otx_lookup(target: str, session: "aiohttp.ClientSession") -> list[str]:
    """
    AlienVault OTX passive DNS lookup.

    Returns a list of subdomain names associated with the target domain.
    """
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                hosts = {
                    r.get("hostname", "") for r in data.get("passive_dns", [])
                    if r.get("hostname")
                }
                return [h for h in hosts if target in h and h != target]
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.warning("OTX lookup failed: %s", exc)
    return []


# ─────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────

async def gather(
    target: str,
    ip: str = "",
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    securitytrails_key: str = "",
    virustotal_key: str = "",
    abuseipdb_key: str = "",
) -> PassiveResult:
    """
    Run all configured passive source lookups concurrently.

    Free providers (crt.sh, OTX) always run.
    Key-gated providers (Shodan, Censys, SecurityTrails, VirusTotal, AbuseIPDB)
    are silently skipped when their API key is absent.

    Args:
        target: Domain or IP address to investigate.
        ip: Pre-resolved IP address (optional, speeds up IP-based lookups).
        *_key: Provider API keys — provider is skipped when key is empty.

    Returns:
        PassiveResult aggregating findings from all providers.
    """
    result = PassiveResult(target=target)

    if not HAS_AIOHTTP:
        result.errors.append("aiohttp not installed — passive sources unavailable")
        return result

    # Passive intelligence APIs are legitimate services with valid TLS certificates.
    # SSL verification is always enabled here; ssl=None uses the system CA bundle.
    connector = aiohttp.TCPConnector()
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks: dict[str, object] = {}

        # Free providers — always run
        tasks["crtsh"] = _crtsh_subdomains(target, session)
        tasks["otx"]   = _otx_lookup(target, session)

        # Key-gated providers
        if shodan_key:
            tasks["shodan_host"] = _shodan_lookup(ip or target, shodan_key, session)
            tasks["shodan_dns"]  = _shodan_dns(target, shodan_key, session)

        if censys_id and censys_secret:
            tasks["censys"] = _censys_lookup(ip or target, censys_id, censys_secret, session)

        if securitytrails_key:
            tasks["st_subs"]   = _securitytrails_subdomains(target, securitytrails_key, session)
            tasks["st_emails"] = _securitytrails_emails(target, securitytrails_key, session)

        if virustotal_key:
            tasks["vt"] = _virustotal_lookup(target, virustotal_key, session)

        if abuseipdb_key and ip:
            tasks["abuseipdb"] = _abuseipdb_check(ip, abuseipdb_key, session)

        resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
        task_results = dict(zip(tasks.keys(), resolved))

    # ── Merge results ─────────────────────────────────────────

    subs: set[str] = set()

    if isinstance(task_results.get("crtsh"), list):
        subs.update(task_results["crtsh"])
        if task_results["crtsh"]:
            result.findings.append(f"crt.sh: {len(task_results['crtsh'])} subdomains in CT logs")

    if isinstance(task_results.get("otx"), list):
        subs.update(task_results["otx"])

    if isinstance(task_results.get("shodan_host"), PassiveHost):
        result.hosts.append(task_results["shodan_host"])
        result.findings.append(
            f"Shodan: {len(task_results['shodan_host'].ports)} open ports recorded"
        )

    if isinstance(task_results.get("shodan_dns"), list):
        subs.update(task_results["shodan_dns"])

    if isinstance(task_results.get("censys"), PassiveHost):
        result.hosts.append(task_results["censys"])
        result.findings.append(
            f"Censys: {len(task_results['censys'].ports)} services recorded"
        )

    if isinstance(task_results.get("st_subs"), list):
        subs.update(task_results["st_subs"])

    if isinstance(task_results.get("st_emails"), list):
        result.emails.extend(task_results["st_emails"])

    if isinstance(task_results.get("vt"), tuple):
        is_mal, detections, vt_subs = task_results["vt"]
        result.malicious = is_mal
        result.vt_detections = detections
        subs.update(vt_subs)
        if is_mal:
            result.findings.append(
                f"VirusTotal: {detections} engine(s) flagged this target as malicious"
            )

    if isinstance(task_results.get("abuseipdb"), int):
        result.abuse_score = task_results["abuseipdb"]
        if result.abuse_score and result.abuse_score > 25:
            result.findings.append(
                f"AbuseIPDB confidence score: {result.abuse_score}% — IP has abuse reports"
            )

    result.subdomains = sorted(subs)
    return result
