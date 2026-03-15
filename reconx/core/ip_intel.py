"""
ASN and IP intelligence module.

Features:
  - ASN number, name, and description via RDAP / ipwhois
  - CIDR block / network ownership
  - Reverse DNS (PTR records)
  - Cloud provider detection from ASN names and known CIDR ranges
  - Geolocation (country, city) via ip-api.com (no key required)
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ─────────────────────────────────────────────────────────────
# Cloud provider keywords in ASN names
# ─────────────────────────────────────────────────────────────

_CLOUD_KEYWORDS: list[tuple[str, str]] = [
    ("Amazon", "AWS"),
    ("AMAZON", "AWS"),
    ("AWS", "AWS"),
    ("EC2", "AWS"),
    ("Microsoft", "Azure"),
    ("MICROSOFT-AZURE", "Azure"),
    ("Google", "GCP"),
    ("GOOGLE", "GCP"),
    ("Cloudflare", "Cloudflare"),
    ("CLOUDFLARE", "Cloudflare"),
    ("Fastly", "Fastly"),
    ("FASTLY", "Fastly"),
    ("Akamai", "Akamai"),
    ("AKAMAI", "Akamai"),
    ("DigitalOcean", "DigitalOcean"),
    ("DIGITALOCEAN", "DigitalOcean"),
    ("Linode", "Linode/Akamai"),
    ("LINODE", "Linode/Akamai"),
    ("Hetzner", "Hetzner"),
    ("HETZNER", "Hetzner"),
    ("OVH", "OVH"),
    ("Vultr", "Vultr"),
    ("VULTR", "Vultr"),
    ("Oracle", "Oracle Cloud"),
    ("ORACLE", "Oracle Cloud"),
    ("Alibaba", "Alibaba Cloud"),
    ("ALIBABA", "Alibaba Cloud"),
    ("Tencent", "Tencent Cloud"),
    ("IBM", "IBM Cloud"),
    ("Rackspace", "Rackspace"),
]


def _detect_cloud(asn_name: str, org: str) -> str:
    combined = (asn_name + " " + org).upper()
    for keyword, provider in _CLOUD_KEYWORDS:
        if keyword.upper() in combined:
            return provider
    return ""


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class ASNInfo:
    asn: str = ""
    asn_name: str = ""
    asn_description: str = ""
    cidr: str = ""
    org: str = ""
    country: str = ""
    cloud_provider: str = ""


@dataclass
class GeoInfo:
    country: str = ""
    country_code: str = ""
    city: str = ""
    region: str = ""
    isp: str = ""
    lat: float = 0.0
    lon: float = 0.0


@dataclass
class IPIntelResult:
    target: str
    ip: str = ""
    ptr_records: list[str] = field(default_factory=list)
    asn: Optional[ASNInfo] = None
    geo: Optional[GeoInfo] = None
    is_private: bool = False
    findings: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Lookups
# ─────────────────────────────────────────────────────────────

async def _reverse_dns(ip: str) -> list[str]:
    """Perform reverse DNS (PTR) lookup."""
    try:
        loop = asyncio.get_event_loop()
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return [hostname]
    except Exception:
        return []


async def _rdap_lookup(ip: str, session: "aiohttp.ClientSession") -> Optional[ASNInfo]:
    """Look up ASN/network info via RDAP (ARIN/RIPE/etc.)."""
    try:
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                asn_info = ASNInfo()

                # CIDR
                cidr = data.get("handle", "") or data.get("name", "")
                start = data.get("startAddress", "")
                end = data.get("endAddress", "")
                prefix = data.get("cidr0_cidrs", [{}])
                if prefix:
                    v4 = [p for p in prefix if "v4prefix" in p]
                    if v4:
                        cidr = f"{v4[0]['v4prefix']}/{v4[0]['length']}"
                asn_info.cidr = cidr

                # Org
                entities = data.get("entities", [])
                for ent in entities:
                    vcard = ent.get("vcardArray", [])
                    if vcard and len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                asn_info.org = item[3]
                                break

                # Country
                asn_info.country = data.get("country", "")

                # Try to get ASN from related network
                asn_info.asn_description = data.get("name", "")
                asn_info.cloud_provider = _detect_cloud(asn_info.asn_name, asn_info.org)
                return asn_info
    except Exception:
        pass
    return None


async def _bgpview_lookup(ip: str, session: "aiohttp.ClientSession") -> Optional[ASNInfo]:
    """Fallback ASN lookup via bgpview.io API."""
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                prefixes = data.get("data", {}).get("prefixes", [])
                if prefixes:
                    p = prefixes[0]
                    asn_data = p.get("asn", {})
                    asn_info = ASNInfo(
                        asn=f"AS{asn_data.get('asn', '')}",
                        asn_name=asn_data.get("name", ""),
                        asn_description=asn_data.get("description", ""),
                        cidr=p.get("prefix", ""),
                        country=asn_data.get("country_code", ""),
                    )
                    asn_info.cloud_provider = _detect_cloud(asn_info.asn_name, asn_info.asn_description)
                    return asn_info
    except Exception:
        pass
    return None


async def _geo_lookup(ip: str, session: "aiohttp.ClientSession") -> Optional[GeoInfo]:
    """Geolocation via ip-api.com (free, no key required, rate-limited)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,isp,lat,lon"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                if data.get("status") == "success":
                    return GeoInfo(
                        country=data.get("country", ""),
                        country_code=data.get("countryCode", ""),
                        city=data.get("city", ""),
                        region=data.get("regionName", ""),
                        isp=data.get("isp", ""),
                        lat=data.get("lat", 0.0),
                        lon=data.get("lon", 0.0),
                    )
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────

async def lookup(target: str) -> IPIntelResult:
    """
    Full IP intelligence lookup for a hostname or IP.

    Returns ASN, CIDR, cloud provider, geolocation, PTR records and findings.
    """
    result = IPIntelResult(target=target)

    # Resolve IP
    try:
        ip = socket.gethostbyname(target)
        result.ip = ip
    except socket.gaierror as exc:
        result.error = f"DNS resolution failed: {exc}"
        return result

    # Check private
    try:
        addr = ipaddress.ip_address(ip)
        result.is_private = addr.is_private
        if result.is_private:
            result.findings.append(f"IP {ip} is a private/RFC1918 address")
    except ValueError:
        pass

    if not HAS_AIOHTTP:
        result.error = "aiohttp not installed"
        return result

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Run lookups concurrently
        ptr_task = _reverse_dns(ip)
        rdap_task = _rdap_lookup(ip, session)
        bgpview_task = _bgpview_lookup(ip, session)
        geo_task = _geo_lookup(ip, session)

        ptr, rdap, bgpview, geo = await asyncio.gather(
            ptr_task, rdap_task, bgpview_task, geo_task,
            return_exceptions=True,
        )

    result.ptr_records = ptr if isinstance(ptr, list) else []
    result.asn = (bgpview if isinstance(bgpview, ASNInfo) else None) or \
                 (rdap if isinstance(rdap, ASNInfo) else None)
    result.geo = geo if isinstance(geo, GeoInfo) else None

    # Findings
    if result.asn and result.asn.cloud_provider:
        result.findings.append(f"Hosted on {result.asn.cloud_provider} ({result.asn.asn_name})")
    if result.asn and result.asn.asn:
        result.findings.append(f"ASN: {result.asn.asn} — {result.asn.asn_description or result.asn.asn_name}")
    if result.asn and result.asn.cidr:
        result.findings.append(f"Network CIDR: {result.asn.cidr}")
    if result.geo and result.geo.country:
        result.findings.append(f"Geolocation: {result.geo.city}, {result.geo.country} ({result.geo.isp})")
    if result.ptr_records:
        result.findings.append(f"PTR: {', '.join(result.ptr_records)}")

    return result
