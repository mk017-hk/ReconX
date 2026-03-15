"""
Optional passive source integrations.

Supported providers (all require API keys):
  - Shodan          (SHODAN_API_KEY)
  - Censys          (CENSYS_API_ID + CENSYS_API_SECRET)
  - SecurityTrails  (SECURITYTRAILS_API_KEY)
  - VirusTotal      (VIRUSTOTAL_API_KEY)
  - AbuseIPDB       (ABUSEIPDB_API_KEY)

Free providers (no key required):
  - crt.sh          (certificate transparency)
  - HackerTarget    (passive DNS)
  - AlienVault OTX  (threat intel, limited free tier)

Each provider returns a PassiveResult with normalised findings.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


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
    abuse_score: Optional[int] = None     # AbuseIPDB confidence score 0-100
    malicious: Optional[bool] = None      # VirusTotal verdict
    vt_detections: int = 0                # VirusTotal detection count
    findings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────────────────────

async def _shodan_lookup(target: str, api_key: str, session: "aiohttp.ClientSession") -> Optional[PassiveHost]:
    """Query Shodan host info for an IP/domain."""
    try:
        url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                ports = data.get("ports", [])
                hostnames = data.get("hostnames", [])
                tags = data.get("tags", [])
                return PassiveHost(
                    ip=data.get("ip_str", target),
                    hostnames=hostnames,
                    ports=ports,
                    tags=tags,
                    source="shodan",
                )
            elif resp.status == 404:
                return None
    except Exception as exc:
        pass
    return None


async def _shodan_dns(domain: str, api_key: str, session: "aiohttp.ClientSession") -> list[str]:
    """Shodan DNS domain search for subdomains."""
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                subdomains = data.get("subdomains", [])
                return [f"{s}.{domain}" for s in subdomains]
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────────────────────
# Censys
# ─────────────────────────────────────────────────────────────

async def _censys_lookup(target: str, api_id: str, api_secret: str,
                          session: "aiohttp.ClientSession") -> Optional[PassiveHost]:
    """Query Censys hosts API."""
    try:
        import base64
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}
        url = f"https://search.censys.io/api/v2/hosts/{target}"
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                result_data = data.get("result", {})
                services = result_data.get("services", [])
                ports = [s.get("port") for s in services if s.get("port")]
                hostnames = result_data.get("dns", {}).get("reverse_dns", {}).get("names", [])
                return PassiveHost(
                    ip=target,
                    hostnames=hostnames,
                    ports=ports,
                    source="censys",
                )
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# SecurityTrails
# ─────────────────────────────────────────────────────────────

async def _securitytrails_subdomains(domain: str, api_key: str,
                                      session: "aiohttp.ClientSession") -> list[str]:
    """Fetch subdomains from SecurityTrails."""
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"apikey": api_key, "Content-Type": "application/json"}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                subs = data.get("subdomains", [])
                return [f"{s}.{domain}" for s in subs]
    except Exception:
        pass
    return []


async def _securitytrails_emails(domain: str, api_key: str,
                                  session: "aiohttp.ClientSession") -> list[str]:
    """Fetch associated emails from SecurityTrails WHOIS history."""
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"
        headers = {"apikey": api_key}
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                contacts = data.get("contacts", [])
                emails = []
                for c in contacts:
                    email = c.get("email", "")
                    if email and "@" in email:
                        emails.append(email)
                return list(set(emails))
    except Exception:
        pass
    return []


# ─────────────────────────────────────────────────────────────
# VirusTotal
# ─────────────────────────────────────────────────────────────

async def _virustotal_lookup(target: str, api_key: str,
                              session: "aiohttp.ClientSession") -> tuple[Optional[bool], int, list[str]]:
    """Check VirusTotal for malicious verdicts. Returns (malicious, detections, subdomains)."""
    try:
        import base64
        # Check if target is an IP or domain
        endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
        headers = {"x-apikey": api_key}
        async with session.get(endpoint, headers=headers, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 0
                is_malicious = malicious > 0

                # Subdomains from VT
                subs_url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains"
                subs = []
                async with session.get(subs_url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as sr:
                    if sr.status == 200:
                        sd = await sr.json(content_type=None)
                        for item in sd.get("data", []):
                            subs.append(item.get("id", ""))

                return is_malicious, malicious, [s for s in subs if s]
    except Exception:
        pass
    return None, 0, []


# ─────────────────────────────────────────────────────────────
# AbuseIPDB
# ─────────────────────────────────────────────────────────────

async def _abuseipdb_check(ip: str, api_key: str,
                            session: "aiohttp.ClientSession") -> Optional[int]:
    """Check AbuseIPDB confidence score (0-100)."""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        async with session.get(url, headers=headers, params=params,
                               timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data.get("data", {}).get("abuseConfidenceScore")
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# Free sources
# ─────────────────────────────────────────────────────────────

async def _otx_lookup(target: str, session: "aiohttp.ClientSession") -> list[str]:
    """AlienVault OTX — free threat intel, no key needed for basic lookups."""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                passive = data.get("passive_dns", [])
                hosts = list({r.get("hostname", "") for r in passive if r.get("hostname")})
                return [h for h in hosts if target in h and h != target]
    except Exception:
        pass
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

    Args:
        target: Domain or IP address.
        ip: Resolved IP (optional, used for IP-based lookups).
        *_key: API keys — sources are skipped when key is empty.

    Returns:
        PassiveResult aggregating all provider data.
    """
    result = PassiveResult(target=target)

    if not HAS_AIOHTTP:
        result.errors.append("aiohttp not installed")
        return result

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = {}

        if shodan_key:
            tasks["shodan_host"] = _shodan_lookup(ip or target, shodan_key, session)
            tasks["shodan_dns"] = _shodan_dns(target, shodan_key, session)

        if censys_id and censys_secret:
            tasks["censys"] = _censys_lookup(ip or target, censys_id, censys_secret, session)

        if securitytrails_key:
            tasks["st_subs"] = _securitytrails_subdomains(target, securitytrails_key, session)
            tasks["st_emails"] = _securitytrails_emails(target, securitytrails_key, session)

        if virustotal_key:
            tasks["vt"] = _virustotal_lookup(target, virustotal_key, session)

        if abuseipdb_key and ip:
            tasks["abuseipdb"] = _abuseipdb_check(ip, abuseipdb_key, session)

        # Always run free OTX
        tasks["otx"] = _otx_lookup(target, session)

        if tasks:
            resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
            task_results = dict(zip(tasks.keys(), resolved))
        else:
            task_results = {}

    # Merge results
    subs: set[str] = set()

    if "shodan_host" in task_results and isinstance(task_results["shodan_host"], PassiveHost):
        result.hosts.append(task_results["shodan_host"])
        result.findings.append(
            f"Shodan: {len(task_results['shodan_host'].ports)} open ports found"
        )

    if "shodan_dns" in task_results and isinstance(task_results["shodan_dns"], list):
        subs.update(task_results["shodan_dns"])

    if "censys" in task_results and isinstance(task_results["censys"], PassiveHost):
        result.hosts.append(task_results["censys"])
        result.findings.append(
            f"Censys: {len(task_results['censys'].ports)} services found"
        )

    if "st_subs" in task_results and isinstance(task_results["st_subs"], list):
        subs.update(task_results["st_subs"])

    if "st_emails" in task_results and isinstance(task_results["st_emails"], list):
        result.emails.extend(task_results["st_emails"])

    if "vt" in task_results and isinstance(task_results["vt"], tuple):
        is_mal, detections, vt_subs = task_results["vt"]
        result.malicious = is_mal
        result.vt_detections = detections
        subs.update(vt_subs)
        if is_mal:
            result.findings.append(
                f"VirusTotal: {detections} engine(s) flagged this target as malicious!"
            )

    if "abuseipdb" in task_results and isinstance(task_results["abuseipdb"], int):
        result.abuse_score = task_results["abuseipdb"]
        if result.abuse_score and result.abuse_score > 25:
            result.findings.append(
                f"AbuseIPDB confidence score: {result.abuse_score}% — IP has abuse reports"
            )

    if "otx" in task_results and isinstance(task_results["otx"], list):
        subs.update(task_results["otx"])

    result.subdomains = sorted(subs)
    return result
