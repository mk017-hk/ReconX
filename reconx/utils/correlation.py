"""
Asset correlation layer.

Correlates findings and discovered assets across all scan modules to:
  1. Cross-reference SSL SANs with enumerated subdomains
  2. Classify hosts by likely role (api, admin, staging, dev, prod)
  3. Surface cloud/CDN hosting context
  4. Deduplicate and merge findings from multiple modules
  5. Produce correlated higher-priority findings
     (e.g., admin panel + publicly reachable = elevated priority)

Usage:
    from reconx.utils.correlation import correlate
    result = correlate(collected)
    print(result.host_roles)
    print(result.ssl_confirmed_subdomains)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from reconx.core.severity import Finding, Severity, make_finding, sort_findings, deduplicate_findings


# ─────────────────────────────────────────────────────────────
# Host role classification
# ─────────────────────────────────────────────────────────────

_ROLE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("api",     re.compile(r"^(?:api|rest|graphql|gql|gateway|service|backend|ws|rpc)\.", re.I)),
    ("admin",   re.compile(r"^(?:admin|administrator|manage|management|control|portal|staff|backoffice|cms|cpanel)\.", re.I)),
    ("staging", re.compile(r"^(?:staging|stage|uat|pre-prod|preprod|demo|preview|test|qa|sandbox)\.", re.I)),
    ("dev",     re.compile(r"^(?:dev|develop|development|local|localhost|beta|alpha|rc)\.", re.I)),
    ("cdn",     re.compile(r"^(?:cdn|assets|static|media|img|images|files|storage|uploads)\.", re.I)),
    ("mail",    re.compile(r"^(?:mail|smtp|imap|pop|mx|webmail)\.", re.I)),
    ("vpn",     re.compile(r"^(?:vpn|remote|access|tunnel|sslvpn|pulse)\.", re.I)),
    ("prod",    re.compile(r"^(?:www|app|prod|production|live|web|public)\.", re.I)),
]


def _classify_host_role(hostname: str) -> str:
    """Return the likely role of a hostname based on its subdomain prefix."""
    for role, pattern in _ROLE_PATTERNS:
        if pattern.search(hostname):
            return role
    return "unknown"


# ─────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────

@dataclass
class CorrelationResult:
    # SSL SAN cross-reference
    ssl_confirmed_subdomains: list[str] = field(default_factory=list)
    subdomains_not_in_san: list[str] = field(default_factory=list)

    # Host classification
    host_roles: dict[str, str] = field(default_factory=dict)   # hostname → role

    # Cloud / hosting context
    cloud_providers: list[str] = field(default_factory=list)   # deduplicated providers

    # Asset inventory for reporting
    all_hostnames: list[str] = field(default_factory=list)
    all_ips: list[str] = field(default_factory=list)
    open_port_summary: dict[str, list[int]] = field(default_factory=dict)  # hostname/ip → ports

    # Correlated higher-priority findings
    correlated_findings: list[Finding] = field(default_factory=list)

    # Deduplicated merged findings (input findings after dedup)
    deduplicated_findings: list[Finding] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Correlation logic
# ─────────────────────────────────────────────────────────────

def correlate(collected: dict[str, Any]) -> CorrelationResult:
    """
    Analyse the full collected scan result and return a CorrelationResult
    with cross-module insights.

    Args:
        collected: The ``collected`` dict from _run_scan(), keyed by module name.

    Returns:
        CorrelationResult populated with correlated findings, host roles, and
        asset inventory data.
    """
    result = CorrelationResult()

    # ── 1. Gather all known hostnames / IPs ─────────────────
    target: str = collected.get("target", "")

    known_subs: list[str] = []
    sub_data = collected.get("subdomains")
    if sub_data:
        subs_list = getattr(sub_data, "subdomains", sub_data.get("subdomains", []) if isinstance(sub_data, dict) else [])
        for s in subs_list:
            name = getattr(s, "name", s.get("name", "") if isinstance(s, dict) else "")
            ips  = getattr(s, "ips",  s.get("ips", [])  if isinstance(s, dict) else [])
            if name:
                known_subs.append(name)
                result.all_hostnames.append(name)
            result.all_ips.extend(ips)

    if target:
        result.all_hostnames.append(target)

    # ── 2. SSL SAN cross-reference ───────────────────────────
    ssl_data = collected.get("ssl")
    san_names: list[str] = []
    if ssl_data:
        cert = getattr(ssl_data, "cert", ssl_data.get("cert", {}) if isinstance(ssl_data, dict) else {})
        if cert:
            san_names = getattr(cert, "san", cert.get("san", []) if isinstance(cert, dict) else [])

    # Strip leading '*.' from SANs for comparison
    san_clean = {s.lstrip("*.").lower() for s in san_names if s}

    for sub in known_subs:
        # A subdomain is SSL-confirmed if its bare domain appears in the SANs
        bare = sub.lower()
        if bare in san_clean or any(bare.endswith("." + s) for s in san_clean):
            result.ssl_confirmed_subdomains.append(sub)
        else:
            result.subdomains_not_in_san.append(sub)

    # ── 3. Host role classification ──────────────────────────
    all_hosts = list(dict.fromkeys(result.all_hostnames))  # preserve order, dedup
    result.all_hostnames = all_hosts
    for host in all_hosts:
        result.host_roles[host] = _classify_host_role(host)

    result.all_ips = list(dict.fromkeys(result.all_ips))

    # ── 4. Open port inventory ───────────────────────────────
    scan = collected.get("port_scan")
    if scan:
        ip = getattr(scan, "ip", scan.get("ip", target) if isinstance(scan, dict) else target)
        ports = [
            getattr(p, "port", p.get("port", 0) if isinstance(p, dict) else 0)
            for p in getattr(scan, "open_ports", scan.get("open_ports", []) if isinstance(scan, dict) else [])
        ]
        if ip and ports:
            result.open_port_summary[ip] = ports

    # ── 5. Cloud provider context from IP intel ──────────────
    ip_intel = collected.get("ip_intel")
    if ip_intel:
        asn = getattr(ip_intel, "asn", ip_intel.get("asn", None) if isinstance(ip_intel, dict) else None)
        if asn:
            provider = getattr(asn, "cloud_provider", asn.get("cloud_provider", "") if isinstance(asn, dict) else "")
            if provider and provider not in result.cloud_providers:
                result.cloud_providers.append(provider)

    # ── 6. Deduplicate incoming findings ─────────────────────
    raw_findings: list[Finding] = collected.get("_findings", [])
    result.deduplicated_findings = sort_findings(deduplicate_findings(raw_findings))

    # ── 7. Correlated / elevated findings ────────────────────
    correlated: list[Finding] = []

    # Admin hosts that are publicly reachable and have open ports
    admin_hosts = [h for h, role in result.host_roles.items() if role == "admin"]
    for host in admin_hosts:
        if host in result.open_port_summary or host == target:
            correlated.append(make_finding(
                f"Admin-role host '{host}' is internet-reachable",
                detail="Hosts with administrative naming conventions should not be publicly accessible without strong access controls.",
                module="correlation",
                category="infrastructure",
                confidence=70,
                affected=host,
            ))

    # Subdomains in CT logs but not in SANs — potential shadow IT / forgotten assets
    shadow_subs = [s for s in result.subdomains_not_in_san if s not in result.ssl_confirmed_subdomains]
    if len(shadow_subs) > 0:
        correlated.append(make_finding(
            f"{len(shadow_subs)} subdomains discovered but not present in SSL certificate SANs",
            detail=f"Subdomains not covered by the current certificate may be running on separate, potentially unmanaged infrastructure: {', '.join(shadow_subs[:5])}{'...' if len(shadow_subs) > 5 else ''}",
            module="correlation",
            category="infrastructure",
            confidence=60,
        ))

    # Staging / dev hosts reachable alongside prod
    staging_hosts = [h for h, role in result.host_roles.items() if role in ("staging", "dev")]
    if staging_hosts and any(r == "prod" for r in result.host_roles.values()):
        correlated.append(make_finding(
            f"Staging / dev hosts found alongside production: {', '.join(staging_hosts[:3])}",
            detail="Development and staging environments often have weaker security controls and may expose source code, debug endpoints, or credentials.",
            module="correlation",
            category="infrastructure",
            confidence=65,
            affected=", ".join(staging_hosts[:3]),
        ))

    result.correlated_findings = sort_findings(correlated)
    return result
