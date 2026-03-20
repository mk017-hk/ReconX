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
from dataclasses import dataclass, field
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

    # v1.4.0 — richer context
    confidence: int = 75              # 0–100; derived from evidence quality
    description: str = ""            # Full human-readable explanation
    evidence: list[str] = field(default_factory=list)   # Supporting evidence snippets
    affected: str = ""               # Specific affected URL / host / path
    remediation: str = ""            # Actionable fix guidance
    references: list[str] = field(default_factory=list) # OWASP / RFC / CVE links


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
    (re.compile(r"backup file exposed",             re.I),   Severity.CRITICAL),

    # HIGH
    (re.compile(r"GraphQL.{0,10}(found|endpoint)",  re.I),   Severity.HIGH),
    (re.compile(r"introspection.*enabled",          re.I),   Severity.HIGH),
    (re.compile(r"deprecated",                      re.I),   Severity.HIGH),
    (re.compile(r"weak cipher",                     re.I),   Severity.HIGH),
    (re.compile(r"self.signed",                     re.I),   Severity.HIGH),
    (re.compile(r"SSLv[23]|TLS ?1\.[01]",           re.I),   Severity.HIGH),
    (re.compile(r"Server status page exposed",      re.I),   Severity.HIGH),
    (re.compile(r"admin.*panel|admin.*exposed",     re.I),   Severity.HIGH),
    (re.compile(r"SPF.{0,20}\+all",                 re.I),   Severity.HIGH),
    (re.compile(r"SNMP.*open|open.*SNMP",           re.I),   Severity.HIGH),
    (re.compile(r"Docker.*open|Docker API",         re.I),   Severity.HIGH),
    (re.compile(r"MongoDB.*open|Elasticsearch.*open", re.I), Severity.HIGH),
    (re.compile(r"Redis.*open",                     re.I),   Severity.HIGH),
    (re.compile(r"telnet.*open|open.*telnet",       re.I),   Severity.HIGH),
    (re.compile(r"CORS.*wildcard|\* origin",        re.I),   Severity.HIGH),
    (re.compile(r"Swagger|OpenAPI.*exposed",        re.I),   Severity.HIGH),
    (re.compile(r"directory listing",               re.I),   Severity.HIGH),

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
    (re.compile(r"cloud bucket",                    re.I),   Severity.MEDIUM),

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


# ─────────────────────────────────────────────────────────────
# Remediation hints — first match wins
# ─────────────────────────────────────────────────────────────

_REMEDIATION: list[tuple[re.Pattern, str]] = [
    (re.compile(r"zone transfer", re.I),
     "Restrict zone transfers to authorised secondary nameservers only. "
     "In BIND use 'allow-transfer'; in Microsoft DNS set zone transfer restrictions on each zone."),
    (re.compile(r"GIT REPO EXPOSED", re.I),
     "Remove the .git directory from the web root or block access with a server rule "
     "(e.g., 'location ~ /\\.git { deny all; }' in Nginx). "
     "Restructure deployments so the repository is above document root. "
     "Rotate any credentials that may have been exposed."),
    (re.compile(r"ENV FILE EXPOSED", re.I),
     "Remove .env files from the web root. Add server rules to deny access to dot-files. "
     "Rotate all credentials and secrets that may have been exposed immediately."),
    (re.compile(r"Spring Actuator", re.I),
     "Restrict Actuator endpoints to localhost or a management network. "
     "Disable sensitive endpoints (/env, /heapdump, /shutdown) in production via "
     "'management.endpoints.web.exposure.include' in application.properties."),
    (re.compile(r"backup file", re.I),
     "Remove backup and temporary files from the web root. Exclude them in your deployment "
     "pipeline. Add server rules to block common backup file extensions (.bak, .old, .backup, .orig)."),
    (re.compile(r"deprecated|TLS ?1\.[01]|SSLv", re.I),
     "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2 as the minimum, "
     "prefer TLS 1.3. Use Mozilla SSL Config Generator for server-specific settings."),
    (re.compile(r"weak cipher", re.I),
     "Remove NULL, RC4, DES, 3DES, EXPORT, and MD5-based cipher suites from your TLS configuration. "
     "Use Mozilla SSL Config Generator to build a modern cipher list."),
    (re.compile(r"self.signed", re.I),
     "Replace the self-signed certificate with one from a trusted CA. "
     "Use Let's Encrypt with Certbot for automated free certificate issuance."),
    (re.compile(r"EXPIRED", re.I),
     "Renew the certificate immediately. Automate renewal with Certbot / ACME "
     "to prevent future expiry. Set calendar reminders 30 days before expiry."),
    (re.compile(r"CSP missing", re.I),
     "Implement a Content-Security-Policy header. Start with 'default-src \\'self\\'' "
     "and progressively allow trusted sources. Use report-only mode first to identify breakages."),
    (re.compile(r"HSTS missing", re.I),
     "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. "
     "Submit to the HSTS preload list after validation."),
    (re.compile(r"Clickjacking|X-Frame-Options", re.I),
     "Set 'X-Frame-Options: DENY' or use 'Content-Security-Policy: frame-ancestors \\'none\\''."
     " This prevents your pages from being framed for clickjacking attacks."),
    (re.compile(r"MIME.type", re.I),
     "Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-type sniffing."),
    (re.compile(r"No SPF", re.I),
     "Publish an SPF TXT record. Example: 'v=spf1 include:_spf.google.com -all'. "
     "Use -all (reject) rather than +all or ~all to enforce strict sending policy."),
    (re.compile(r"No DMARC", re.I),
     "Create a _dmarc TXT record. Start with p=none and an rua address to collect reports, "
     "then progress to p=quarantine and p=reject once you have validated your mail flows."),
    (re.compile(r"SNMP.*open", re.I),
     "Restrict SNMP with firewall rules. Use SNMPv3 with authentication and encryption. "
     "Change default community strings. Disable SNMP if it is not operationally required."),
    (re.compile(r"Redis.*open", re.I),
     "Bind Redis to 127.0.0.1 or a trusted internal interface. Enable authentication "
     "(requirepass). Disable dangerous commands (FLUSHALL, CONFIG, DEBUG) in production."),
    (re.compile(r"CORS.*wildcard|Access-Control.*\*", re.I),
     "Replace 'Access-Control-Allow-Origin: *' with an explicit list of trusted origins. "
     "Never combine wildcard CORS with 'Access-Control-Allow-Credentials: true'."),
    (re.compile(r"directory listing", re.I),
     "Disable directory listing in your web server configuration. "
     "In Apache set 'Options -Indexes'; in Nginx remove 'autoindex on'."),
    (re.compile(r"GraphQL.*introspection", re.I),
     "Disable introspection in production. Implement query depth and complexity limits. "
     "Require authentication before accepting GraphQL queries."),
    (re.compile(r"Swagger|OpenAPI", re.I),
     "Restrict Swagger UI and OpenAPI spec endpoints to authenticated users or "
     "development environments only. Never expose API documentation publicly in production."),
    (re.compile(r"Telnet.*open", re.I),
     "Disable Telnet. Replace with SSH for all remote administration."),
    (re.compile(r"FTP.*open", re.I),
     "Replace FTP with SFTP or FTPS. Restrict to known IPs. Disable anonymous access."),
    (re.compile(r"cloud bucket", re.I),
     "Audit referenced cloud storage bucket ACLs. Disable public access unless explicitly "
     "required. Use signed URLs for controlled access to private assets."),
    (re.compile(r"Referrer-Policy", re.I),
     "Add 'Referrer-Policy: strict-origin-when-cross-origin' to prevent referrer leakage."),
    (re.compile(r"Permissions-Policy", re.I),
     "Add a Permissions-Policy header to disable browser features not required by your application."),
]


# ─────────────────────────────────────────────────────────────
# OWASP / RFC references keyed by finding pattern
# ─────────────────────────────────────────────────────────────

_REFERENCES: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"CSP missing", re.I),
     ["https://owasp.org/www-community/attacks/xss/", "https://content-security-policy.com/"]),
    (re.compile(r"HSTS", re.I),
     ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"]),
    (re.compile(r"DMARC", re.I),
     ["https://dmarc.org/overview/", "https://www.rfc-editor.org/rfc/rfc7489"]),
    (re.compile(r"SPF", re.I),
     ["https://www.rfc-editor.org/rfc/rfc7208"]),
    (re.compile(r"zone transfer", re.I),
     ["https://owasp.org/www-community/attacks/DNS_Zone_Transfer"]),
    (re.compile(r"deprecated|TLS ?1\.[01]", re.I),
     ["https://www.rfc-editor.org/rfc/rfc8996", "https://ssl-config.mozilla.org/"]),
    (re.compile(r"weak cipher", re.I),
     ["https://ssl-config.mozilla.org/", "https://ciphersuite.info/"]),
    (re.compile(r"SNMP", re.I),
     ["https://www.cisa.gov/news-events/alerts/2017/06/05/reducing-risk-snmp-abuse"]),
    (re.compile(r"GraphQL", re.I),
     ["https://owasp.org/CheatSheetSeries/cheatsheets/GraphQL_Cheat_Sheet.html"]),
    (re.compile(r"CORS", re.I),
     ["https://portswigger.net/web-security/cors", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"]),
    (re.compile(r"Clickjacking|X-Frame", re.I),
     ["https://owasp.org/www-community/attacks/Clickjacking"]),
    (re.compile(r"GIT.*EXPOSED|ENV.*EXPOSED", re.I),
     ["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"]),
    (re.compile(r"Redis.*open", re.I),
     ["https://redis.io/docs/management/security/"]),
    (re.compile(r"Swagger|OpenAPI", re.I),
     ["https://owasp.org/www-project-api-security/"]),
]


def _lookup_remediation(text: str) -> str:
    for pattern, hint in _REMEDIATION:
        if pattern.search(text):
            return hint
    return ""


def _lookup_references(text: str) -> list[str]:
    for pattern, refs in _REFERENCES:
        if pattern.search(text):
            return refs
    return []


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
    *,
    confidence: int = 75,
    description: str = "",
    evidence: Optional[list[str]] = None,
    affected: str = "",
    remediation: str = "",
    references: Optional[list[str]] = None,
) -> "Finding":
    """
    Create a Finding with auto-classified severity, inferred category,
    and auto-populated remediation hints and references.

    Args:
        title:       Short finding title (used for severity classification).
        detail:      Optional additional detail string.
        module:      Source module identifier (e.g. "http", "ssl").
        category:    Override category. Auto-inferred from module if omitted.
        confidence:  Evidence confidence 0–100 (default 75).
        description: Full human-readable explanation.
        evidence:    List of supporting evidence snippets.
        affected:    Specific affected URL / path / host.
        remediation: Fix guidance. Auto-populated from remediation table if omitted.
        references:  OWASP / RFC / CVE links. Auto-populated if omitted.
    """
    combined = f"{title} {detail}"
    inferred_category = category or _MODULE_CATEGORIES.get(module, "")
    return Finding(
        severity=classify(combined),
        title=title,
        detail=detail,
        module=module,
        category=inferred_category,
        confidence=confidence,
        description=description,
        evidence=evidence or [],
        affected=affected,
        remediation=remediation or _lookup_remediation(combined),
        references=references or _lookup_references(combined),
    )


def score_findings(findings: list["Finding"]) -> dict[str, int]:
    """Return a count per severity level."""
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def sort_findings(findings: list["Finding"]) -> list["Finding"]:
    """Sort findings by severity (critical first), then by confidence descending."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )


def deduplicate_findings(findings: list["Finding"]) -> list["Finding"]:
    """
    Remove duplicate findings based on (title, module, affected) key.
    When duplicates exist, keep the one with the highest confidence.
    """
    seen: dict[tuple, "Finding"] = {}
    for f in findings:
        key = (f.title.lower().strip(), f.module, f.affected)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    return list(seen.values())


def aggregate_findings(collected: dict) -> list["Finding"]:
    """
    Walk the entire scan result dict and promote all string findings
    to typed Finding objects with severity scores and categories.
    """
    findings: list[Finding] = []

    def _add(texts: list[str], module: str, affected: str = "") -> None:
        for t in texts:
            if isinstance(t, str) and t.strip():
                findings.append(make_finding(t, module=module, affected=affected))

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
                ns = zt_dict.get("nameserver", "?")
                findings.append(make_finding(
                    f"Zone transfer SUCCESSFUL from {ns}",
                    module="dns",
                    affected=ns,
                    confidence=100,
                ))

    # SSL/TLS
    ssl_r = collected.get("ssl")
    if ssl_r:
        ssl_findings = getattr(ssl_r, "findings", ssl_r.get("findings", []) if isinstance(ssl_r, dict) else [])
        host = getattr(ssl_r, "host", ssl_r.get("host", "") if isinstance(ssl_r, dict) else "")
        _add(ssl_findings, "ssl", affected=host)

    # HTTP
    for hr in (collected.get("http") or []):
        url = getattr(hr, "url", hr.get("url", "") if isinstance(hr, dict) else "")
        missing = getattr(hr, "missing_security_headers", hr.get("missing_security_headers", []) if isinstance(hr, dict) else [])
        _add(missing, "http", affected=url)
        # CORS issues
        cors_issues = getattr(hr, "cors_issues", hr.get("cors_issues", []) if isinstance(hr, dict) else [])
        _add(cors_issues, "http", affected=url)
        # Validation findings
        validation = getattr(hr, "validation_findings", hr.get("validation_findings", []) if isinstance(hr, dict) else [])
        _add(validation, "http", affected=url)
        for ip_path in (getattr(hr, "interesting_paths", hr.get("interesting_paths", []) if isinstance(hr, dict) else [])):
            note = getattr(ip_path, "note", ip_path.get("note", "") if isinstance(ip_path, dict) else "")
            path = getattr(ip_path, "path", ip_path.get("path", "") if isinstance(ip_path, dict) else "")
            if note:
                findings.append(make_finding(
                    note,
                    module="http",
                    affected=f"{url}{path}" if url else path,
                    confidence=95,
                ))

    # UDP
    udp = collected.get("udp")
    if udp:
        for p in (getattr(udp, "open_ports", udp.get("open_ports", []) if isinstance(udp, dict) else [])):
            svc = getattr(p, "service", p.get("service", "") if isinstance(p, dict) else "")
            port = getattr(p, "port", p.get("port", 0) if isinstance(p, dict) else 0)
            if svc in ("SNMP", "IKE/IPSec", "TFTP"):
                findings.append(make_finding(
                    f"{svc} open on UDP/{port}",
                    module="udp",
                    affected=f"UDP/{port}",
                    confidence=90,
                ))

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
                    affected=f"TCP/{port}",
                    confidence=95,
                ))
            elif svc in ("Docker", "MongoDB", "Redis", "Elasticsearch"):
                findings.append(make_finding(
                    f"{svc} open on TCP/{port} — may lack authentication",
                    module="ports",
                    affected=f"TCP/{port}",
                    confidence=85,
                ))

    # IP intelligence
    ip_intel = collected.get("ip_intel")
    if ip_intel:
        _add(
            getattr(ip_intel, "findings", ip_intel.get("findings", []) if isinstance(ip_intel, dict) else []),
            "ip_intel",
        )

    return sort_findings(deduplicate_findings(findings))
