"""
Severity scoring and finding prioritisation.

Severity levels (CVSS-inspired):
  CRITICAL  — immediate exploitation risk (zone transfer, exposed secrets)
  HIGH      — significant weakness (deprecated TLS, exposed admin, weak ciphers)
  MEDIUM    — notable issue (missing security headers, weak SPF)
  LOW       — informational or low-risk finding (registrar info, open ports)
  INFO      — neutral information

Finding categories:
  network        — TCP/UDP port findings
  dns            — DNS record findings and misconfigurations
  web            — HTTP/HTTPS, crawler, and web application findings
  tls            — SSL/TLS certificate and protocol findings
  infrastructure — IP intelligence, ASN, hosting environment
  passive_intel  — findings from passive third-party sources
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER: dict["Severity", int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}

# Maps module identifiers to finding categories
_MODULE_CATEGORIES: dict[str, str] = {
    "dns":      "dns",
    "ssl":      "tls",
    "http":     "web",
    "ports":    "network",
    "udp":      "network",
    "ip_intel": "infrastructure",
    "whois":    "infrastructure",
    "passive":  "passive_intel",
    "crawl":    "web",
}


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str = ""
    module: str = ""      # "dns" | "ssl" | "http" | "ports" | "udp" | "ip_intel" | "crawl" | "passive"
    category: str = ""    # "network" | "dns" | "web" | "tls" | "infrastructure" | "passive_intel"


# ─────────────────────────────────────────────────────────────
# Classification rules  (pattern → severity)
# Applied in order; first match wins.
# ─────────────────────────────────────────────────────────────

_RULES: list[tuple[re.Pattern, Severity]] = [
    # CRITICAL
    (re.compile(r"zone transfer.{0,20}SUCCESSFUL",  re.I),   Severity.CRITICAL),
    (re.compile(r"GIT REPO EXPOSED",                re.I),   Severity.CRITICAL),
    (re.compile(r"ENV FILE EXPOSED",                re.I),   Severity.CRITICAL),
    (re.compile(r"EXPIRED",                         re.I),   Severity.CRITICAL),
    (re.compile(r"Spring Actuator exposed",         re.I),   Severity.CRITICAL),

    # HIGH
    (re.compile(r"GraphQL.{0,10}found",             re.I),   Severity.HIGH),
    (re.compile(r"deprecated",                      re.I),   Severity.HIGH),
    (re.compile(r"weak cipher",                     re.I),   Severity.HIGH),
    (re.compile(r"self.signed",                     re.I),   Severity.HIGH),
    (re.compile(r"SSLv[23]|TLS ?1\.[01]",           re.I),   Severity.HIGH),
    (re.compile(r"Server status page exposed",      re.I),   Severity.HIGH),
    (re.compile(r"admin.*path|path.*admin",         re.I),   Severity.HIGH),
    (re.compile(r"SPF.{0,20}\+all",                 re.I),   Severity.HIGH),
    (re.compile(r"SNMP.*open|open.*SNMP",           re.I),   Severity.HIGH),
    (re.compile(r"Docker.*open|Docker API",         re.I),   Severity.HIGH),
    (re.compile(r"MongoDB.*open|Elasticsearch.*open", re.I), Severity.HIGH),
    (re.compile(r"Redis.*open",                     re.I),   Severity.HIGH),
    (re.compile(r"telnet.*open|open.*telnet",       re.I),   Severity.HIGH),

    # MEDIUM
    (re.compile(r"missing.*header|header.*missing", re.I),   Severity.MEDIUM),
    (re.compile(r"HSTS.*disables|HSTS missing",     re.I),   Severity.MEDIUM),
    (re.compile(r"CSP missing|Clickjacking",        re.I),   Severity.MEDIUM),
    (re.compile(r"MIME.type sniffing",              re.I),   Severity.MEDIUM),
    (re.compile(r"No SPF",                          re.I),   Severity.MEDIUM),
    (re.compile(r"No DMARC",                        re.I),   Severity.MEDIUM),
    (re.compile(r"expir.{0,20}(30|7) days",         re.I),   Severity.MEDIUM),
    (re.compile(r"single NS|redundancy",            re.I),   Severity.MEDIUM),
    (re.compile(r"IKE.*open|IPSec.*open",           re.I),   Severity.MEDIUM),

    # LOW
    (re.compile(r"registrar|creation date|name server", re.I), Severity.LOW),
    (re.compile(r"expir",                           re.I),   Severity.LOW),
    (re.compile(r"PTR|Geolocation|ASN|CIDR",        re.I),   Severity.LOW),
    (re.compile(r"Referrer-Policy|Permissions-Policy", re.I), Severity.LOW),
    (re.compile(r"cookie.*missing|missing.*cookie", re.I),   Severity.LOW),
    (re.compile(r"open\|filtered",                  re.I),   Severity.LOW),

    # Default
    (re.compile(r".*"),                                       Severity.INFO),
]


def classify(text: str) -> Severity:
    """Return the severity for a free-text finding string."""
    for pattern, severity in _RULES:
        if pattern.search(text):
            return severity
    return Severity.INFO


def make_finding(
    title: str,
    detail: str = "",
    module: str = "",
    category: Optional[str] = None,
) -> Finding:
    """Create a Finding with auto-classified severity and inferred category."""
    inferred_category = category or _MODULE_CATEGORIES.get(module, "")
    return Finding(
        severity=classify(title + " " + detail),
        title=title,
        detail=detail,
        module=module,
        category=inferred_category,
    )


def score_findings(findings: list[Finding]) -> dict[str, int]:
    """Return a count per severity level."""
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (critical first)."""
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))


def aggregate_findings(collected: dict) -> list[Finding]:
    """
    Walk the entire scan result dict and promote all string findings
    to typed Finding objects with severity scores and categories.
    """
    findings: list[Finding] = []

    def _add(texts: list[str], module: str) -> None:
        for t in texts:
            if isinstance(t, str) and t.strip():
                findings.append(make_finding(t, module=module))

    # DNS
    dns = collected.get("dns")
    if dns:
        _add(
            getattr(dns, "security_findings", dns.get("security_findings", []) if isinstance(dns, dict) else []),
            "dns",
        )
        for zt in (getattr(dns, "zone_transfers", None) or (dns.get("zone_transfers", []) if isinstance(dns, dict) else [])):
            zt_dict = zt if isinstance(zt, dict) else {}
            if zt_dict.get("success"):
                findings.append(make_finding(
                    f"Zone transfer SUCCESSFUL from {zt_dict.get('nameserver', '?')}",
                    module="dns",
                ))

    # SSL/TLS
    ssl_r = collected.get("ssl")
    if ssl_r:
        ssl_findings = getattr(ssl_r, "findings", ssl_r.get("findings", []) if isinstance(ssl_r, dict) else [])
        _add(ssl_findings, "ssl")

    # HTTP
    for hr in (collected.get("http") or []):
        missing = getattr(hr, "missing_security_headers", hr.get("missing_security_headers", []) if isinstance(hr, dict) else [])
        _add(missing, "http")
        for ip_path in (getattr(hr, "interesting_paths", hr.get("interesting_paths", []) if isinstance(hr, dict) else [])):
            note = getattr(ip_path, "note", ip_path.get("note", "") if isinstance(ip_path, dict) else "")
            if note:
                findings.append(make_finding(note, module="http"))

    # UDP
    udp = collected.get("udp")
    if udp:
        for p in (getattr(udp, "open_ports", udp.get("open_ports", []) if isinstance(udp, dict) else [])):
            svc = getattr(p, "service", p.get("service", "") if isinstance(p, dict) else "")
            port = getattr(p, "port", p.get("port", 0) if isinstance(p, dict) else 0)
            if svc in ("SNMP", "IKE/IPSec", "TFTP"):
                findings.append(make_finding(f"{svc} open on UDP/{port}", module="udp"))

    # TCP port scan — flag risky services
    scan = collected.get("port_scan")
    if scan:
        for p in (getattr(scan, "open_ports", scan.get("open_ports", []) if isinstance(scan, dict) else [])):
            svc = getattr(p, "service", p.get("service", "") if isinstance(p, dict) else "")
            port = getattr(p, "port", p.get("port", 0) if isinstance(p, dict) else 0)
            if svc in ("Telnet", "FTP"):
                findings.append(make_finding(
                    f"{svc} open on TCP/{port} — unencrypted protocol",
                    module="ports",
                ))
            elif svc in ("Docker", "MongoDB", "Redis", "Elasticsearch"):
                findings.append(make_finding(
                    f"{svc} open on TCP/{port} — may lack authentication",
                    module="ports",
                ))

    # IP intelligence
    ip_intel = collected.get("ip_intel")
    if ip_intel:
        _add(
            getattr(ip_intel, "findings", ip_intel.get("findings", []) if isinstance(ip_intel, dict) else []),
            "ip_intel",
        )

    return sort_findings(findings)
