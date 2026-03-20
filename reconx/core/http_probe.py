"""
HTTP probing & technology fingerprinting module.

v1.4 — layered fingerprinting engine:
  Each technology is matched against multiple independent signal sources:
    header   — HTTP response headers
    body     — response body content (first 8 KB)
    cookie   — Set-Cookie values

  A confidence score (0–100) is accumulated from per-signal weights.
  Only technologies meeting the minimum confidence threshold are reported,
  reducing single-signal false positives.

Safe validation checks (v1.4):
  - CORS policy analysis
  - Backup / temporary file exposure
  - Cloud storage bucket reference discovery
  - Robots.txt sensitive path disclosure
  - Directory listing detection
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ──────────────────────────────────────────────────────────────
# Layered technology fingerprint signatures
#
# signals: list of (source, pattern, weight)
#   source  = "header" | "body" | "cookie"
#   weight  = points added when pattern matches (budget: 0–100)
#
# Weight guidance:
#   60 — highly specific single-source signature (unique header)
#   40 — moderately specific pattern
#   25 — corroborating signal
#   15 — weak / noisy pattern (only useful alongside others)
#
# min_conf: minimum accumulated confidence to report (default 30)
# ──────────────────────────────────────────────────────────────

_TECH_SIGNATURES: list[dict] = [
    # Servers
    {
        "category": "Server", "name": "Apache",
        "signals": [
            ("header", r"Server:\s*Apache",           60),
            ("body",   r"Apache Software Foundation", 25),
            ("body",   r"<address>Apache",            30),
        ],
        "version": r"Apache/([\d.]+)",
    },
    {
        "category": "Server", "name": "Nginx",
        "signals": [
            ("header", r"Server:\s*nginx",            60),
            ("body",   r"<center>nginx</center>",     40),
        ],
        "version": r"nginx/([\d.]+)",
    },
    {
        "category": "Server", "name": "IIS",
        "signals": [
            ("header", r"Server:\s*Microsoft-IIS",    60),
            ("header", r"X-Powered-By:\s*ASP\.NET",   30),
            ("body",   r"IIS Windows Server",         25),
        ],
        "version": r"Microsoft-IIS/([\d.]+)",
    },
    {
        "category": "Server", "name": "LiteSpeed",
        "signals": [("header", r"Server:\s*LiteSpeed", 65)],
    },
    {
        "category": "Server", "name": "Caddy",
        "signals": [("header", r"Server:\s*Caddy",    65)],
    },
    {
        "category": "Server", "name": "Tomcat",
        "signals": [
            ("header", r"Server:\s*(Apache-Coyote|Tomcat)", 60),
            ("body",   r"Apache Tomcat",              30),
        ],
        "version": r"Apache Tomcat/([\d.]+)",
    },
    # WAF
    {
        "category": "WAF", "name": "Cloudflare",
        "signals": [
            ("header", r"(?i)cf-ray",                 55),
            ("header", r"(?i)Server:\s*cloudflare",   55),
        ],
        "min_conf": 40,
    },
    {
        "category": "WAF", "name": "AWS WAF",
        "signals": [
            ("header", r"(?i)x-amzn-requestid",       50),
            ("header", r"(?i)x-amz-apigw-id",         50),
        ],
        "min_conf": 40,
    },
    {
        "category": "WAF", "name": "Imperva",
        "signals": [
            ("cookie", r"incap_ses|visid_incap",      55),
            ("header", r"(?i)x-iinfo",                50),
        ],
        "min_conf": 40,
    },
    {
        "category": "WAF", "name": "ModSecurity",
        "signals": [
            ("header", r"(?i)mod_security|modsecurity", 60),
        ],
    },
    # CDN
    {
        "category": "CDN", "name": "Fastly",
        "signals": [
            ("header", r"(?i)x-fastly",               60),
            ("header", r"(?i)x-cache.*fastly",        50),
        ],
    },
    {
        "category": "CDN", "name": "Varnish",
        "signals": [
            ("header", r"(?i)x-varnish",              60),
            ("header", r"(?i)via:.*varnish",          50),
        ],
    },
    {
        "category": "CDN", "name": "AWS CloudFront",
        "signals": [
            ("header", r"(?i)x-amz-cf-id",            60),
            ("header", r"(?i)via:.*cloudfront",       50),
        ],
    },
    {
        "category": "CDN", "name": "Akamai",
        "signals": [
            ("header", r"(?i)x-akamai-transformed",   60),
            ("header", r"(?i)x-check-cacheable",      45),
        ],
    },
    # Frameworks
    {
        "category": "Framework", "name": "PHP",
        "signals": [
            ("header", r"X-Powered-By:\s*PHP",        55),
        ],
        "version": r"PHP/([\d.]+)",
    },
    {
        "category": "Framework", "name": "ASP.NET",
        "signals": [
            ("header", r"X-Powered-By:\s*ASP\.NET",   55),
            ("header", r"X-AspNet-Version",           50),
            ("cookie", r"ASP\.NET_SessionId",         45),
        ],
    },
    {
        "category": "Framework", "name": "Django",
        "signals": [
            ("cookie", r"csrftoken",                  45),
            ("body",   r"csrfmiddlewaretoken",        35),
        ],
        "min_conf": 40,
    },
    {
        "category": "Framework", "name": "Laravel",
        "signals": [
            ("cookie", r"laravel_session",            55),
            ("cookie", r"XSRF-TOKEN",                 25),
        ],
        "min_conf": 40,
    },
    {
        "category": "Framework", "name": "Express.js",
        "signals": [("header", r"X-Powered-By:\s*Express", 65)],
    },
    {
        "category": "Framework", "name": "Spring / Java",
        "signals": [
            ("cookie", r"JSESSIONID",                 50),
            ("header", r"(?i)X-Application-Context", 55),
        ],
    },
    # CMS
    {
        "category": "CMS", "name": "WordPress",
        "signals": [
            ("body",   r"/wp-content/",               50),
            ("body",   r"/wp-includes/",              50),
            ("header", r"(?i)X-Pingback:.*xmlrpc\.php", 40),
            ("cookie", r"wordpress_",                 40),
        ],
        "min_conf": 40,
    },
    {
        "category": "CMS", "name": "Drupal",
        "signals": [
            ("header", r"X-Generator:\s*Drupal",      65),
            ("body",   r"sites/default/files",        40),
            ("body",   r"Drupal\.settings",           45),
        ],
        "min_conf": 40,
    },
    {
        "category": "CMS", "name": "Shopify",
        "signals": [
            ("body",   r"cdn\.shopify\.com",          60),
            ("header", r"(?i)X-ShopId",               65),
        ],
    },
    # JavaScript
    {
        "category": "JavaScript", "name": "React",
        "signals": [
            ("body",   r"react(?:\.min)?\.js",        50),
            ("body",   r"data-reactroot|data-reactid",50),
        ],
        "min_conf": 40,
    },
    {
        "category": "JavaScript", "name": "Vue.js",
        "signals": [
            ("body",   r"vue(?:\.min)?\.js",          50),
            ("body",   r"__vue__|v-bind:|v-model",    45),
        ],
        "min_conf": 40,
    },
    {
        "category": "JavaScript", "name": "Angular",
        "signals": [
            ("body",   r"angular(?:\.min)?\.js",      50),
            ("body",   r"ng-version=|angular/core",  55),
        ],
        "min_conf": 40,
    },
    {
        "category": "JavaScript", "name": "jQuery",
        "signals": [
            ("body",   r"jquery(?:\.min)?\.js",       40),
            ("body",   r"jQuery v[\d.]+",             45),
        ],
        "version": r"jquery[- /]v?([\d.]+)",
        "min_conf": 35,
    },
]

# Security headers that SHOULD be present
EXPECTED_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS missing — HTTPS downgrade attacks possible",
    "X-Frame-Options":           "Clickjacking protection missing",
    "X-Content-Type-Options":    "MIME-type sniffing protection missing",
    "Content-Security-Policy":   "CSP missing — XSS protection absent",
    "Referrer-Policy":           "Referrer-Policy missing",
    "Permissions-Policy":        "Permissions-Policy missing",
}

# Common interesting paths to probe
INTERESTING_PATHS: list[str] = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/admin/",
    "/login",
    "/wp-admin/",
    "/phpmyadmin/",
    "/.git/HEAD",
    "/.env",
    "/config.json",
    "/api/",
    "/api/v1/",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api-docs",
    "/graphql",
    "/.htaccess",
    "/server-status",
    "/server-info",
    "/_profiler/",
    "/actuator",
    "/actuator/health",
    "/debug",
    "/trace",
    "/.DS_Store",
    "/web.config",
    "/elmah.axd",
]

# Backup / temp file candidates
_BACKUP_PATHS: list[str] = [
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php.bak",
    "/config.php.old",
    "/config.bak",
    "/wp-config.php.bak",
    "/.env.bak",
    "/.env.old",
    "/.env.backup",
    "/settings.py.bak",
]

# Cloud bucket URL patterns (found in HTML/JS body)
_CLOUD_BUCKET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS S3",      re.compile(r"https?://[a-z0-9.\-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.I)),
    ("Azure Blob",  re.compile(r"https?://[a-z0-9]+\.blob\.core\.windows\.net", re.I)),
    ("GCP Storage", re.compile(r"https?://storage\.googleapis\.com/[a-z0-9.\-_]+", re.I)),
    ("DO Spaces",   re.compile(r"https?://[a-z0-9.\-]+\.digitaloceanspaces\.com", re.I)),
]

# Robots.txt Disallow patterns worth flagging
_SENSITIVE_ROBOTS: re.Pattern = re.compile(
    r"Disallow:\s*/(admin|administrator|dashboard|api|internal|private|secret|backup|db|database|config|staff|manage)",
    re.I,
)


@dataclass
class Technology:
    category: str
    name: str
    version: str = ""
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)


@dataclass
class SecurityHeader:
    name: str
    value: Optional[str]    # None = missing
    finding: Optional[str] = None


@dataclass
class InterestingPath:
    path: str
    status_code: int
    content_length: int = 0
    note: str = ""


@dataclass
class CloudBucketRef:
    provider: str
    bucket_url: str


@dataclass
class HTTPResult:
    url: str
    status_code: int = 0
    title: str = ""
    server: str = ""
    technologies: list[Technology] = field(default_factory=list)
    security_headers: list[SecurityHeader] = field(default_factory=list)
    missing_security_headers: list[str] = field(default_factory=list)
    interesting_paths: list[InterestingPath] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    cors_issues: list[str] = field(default_factory=list)
    cloud_bucket_refs: list[CloudBucketRef] = field(default_factory=list)
    robots_disallowed: list[str] = field(default_factory=list)
    validation_findings: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ──────────────────────────────────────────────────────────────
# Fingerprinting helpers
# ──────────────────────────────────────────────────────────────

def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:200]
    return ""


def _fingerprint_technologies(
    headers: dict[str, str],
    body: str,
    cookie_header: str,
) -> list[Technology]:
    """
    Multi-signal technology detection with confidence scoring.

    Each signature is tested against all signal sources; points from each
    matching signal are accumulated. The technology is only reported when
    accumulated confidence meets the signature's min_conf threshold.
    """
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    body_chunk  = body[:8000]

    results: list[Technology] = []

    for sig in _TECH_SIGNATURES:
        total = 0
        evidence: list[str] = []
        version = ""

        for source, pattern, weight in sig["signals"]:
            target = {"header": header_str, "body": body_chunk, "cookie": cookie_header}.get(source, "")
            m = re.search(pattern, target, re.I)
            if m:
                total += weight
                evidence.append(f"{source}: {pattern[:50]}")
                if not version and sig.get("version"):
                    vm = re.search(sig["version"], target, re.I)
                    if vm:
                        version = vm.group(1)

        if total >= sig.get("min_conf", 30):
            results.append(Technology(
                category=sig["category"],
                name=sig["name"],
                version=version,
                confidence=min(total, 100),
                evidence=evidence,
            ))

    # Deduplicate by (category, name), keep highest confidence
    seen: dict[tuple, Technology] = {}
    for t in results:
        key = (t.category, t.name)
        if key not in seen or t.confidence > seen[key].confidence:
            seen[key] = t
    return sorted(seen.values(), key=lambda t: -t.confidence)


def _analyse_security_headers(headers: dict[str, str]) -> tuple[list[SecurityHeader], list[str]]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    present: list[SecurityHeader] = []
    missing: list[str] = []

    for header, warning in EXPECTED_SECURITY_HEADERS.items():
        val = headers_lower.get(header.lower())
        if val:
            sh = SecurityHeader(name=header, value=val)
            if header == "Strict-Transport-Security" and "max-age=0" in val:
                sh.finding = "HSTS max-age=0 effectively disables HSTS"
            if header == "X-Frame-Options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                sh.finding = f"X-Frame-Options value '{val}' may be weak"
            present.append(sh)
        else:
            missing.append(warning)

    return present, missing


def _analyse_cors(headers: dict[str, str]) -> list[str]:
    """Detect CORS policy issues."""
    issues: list[str] = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        if acac == "true":
            issues.append(
                "CORS wildcard with credentials — Access-Control-Allow-Origin: * combined "
                "with Access-Control-Allow-Credentials: true is exploitable from any origin"
            )
        else:
            issues.append("CORS * origin — Access-Control-Allow-Origin: * (overly permissive)")
    elif acao == "null":
        issues.append(
            "CORS allows null origin — exploitable via sandboxed iframes in some browsers"
        )
    return issues


def _find_cloud_bucket_refs(body: str) -> list[CloudBucketRef]:
    """Scan response body for cloud storage bucket URLs."""
    refs: list[CloudBucketRef] = []
    seen: set[str] = set()
    for provider, pat in _CLOUD_BUCKET_PATTERNS:
        for m in pat.finditer(body):
            url = m.group(0)
            if url not in seen:
                seen.add(url)
                refs.append(CloudBucketRef(provider=provider, bucket_url=url))
    return refs


def _check_directory_listing(body: str) -> bool:
    return bool(re.search(r"<title>Index of /|<h1>Index of /", body, re.I))


def _check_cookies(cookies: list) -> list[dict]:
    results = []
    for cookie in cookies:
        info = {
            "name": cookie.key,
            "secure": cookie.get("secure", False) or "secure" in str(cookie).lower(),
            "httponly": "httponly" in str(cookie).lower(),
            "samesite": cookie.get("samesite", "Not set"),
        }
        issues = []
        if not info["secure"]:
            issues.append("Missing Secure flag")
        if not info["httponly"]:
            issues.append("Missing HttpOnly flag")
        if info["samesite"] == "Not set":
            issues.append("Missing SameSite attribute")
        info["issues"] = issues
        results.append(info)
    return results


def _classify_path_note(path: str, status: int, body: str) -> str:
    if path == "/.git/HEAD" and status == 200:
        return "GIT REPO EXPOSED — source code may be accessible!"
    if path == "/.env" and status == 200:
        return "ENV FILE EXPOSED — credentials/secrets may be leaked!"
    if path in ("/server-status", "/server-info") and status == 200:
        return "Server status page exposed"
    if "graphql" in path and status == 200:
        return "GraphQL endpoint found"
    if "actuator" in path and status == 200:
        return "Spring Actuator exposed — admin endpoint!"
    if path in ("/swagger-ui.html", "/swagger-ui/", "/api-docs") and status == 200:
        return "Swagger / OpenAPI docs exposed — API surface visible"
    if path in ("/admin", "/admin/", "/wp-admin/", "/phpmyadmin/") and status == 200:
        return "Admin panel exposed"
    if path in ("/admin", "/admin/", "/wp-admin/", "/phpmyadmin/") and status == 403:
        return "Admin panel path exists (403 — access denied)"
    if path == "/.DS_Store" and status == 200:
        return ".DS_Store exposed — may reveal directory structure"
    if path == "/web.config" and status == 200:
        return "web.config exposed — may reveal server configuration"
    if path == "/elmah.axd" and status == 200:
        return "ELMAH error log exposed"
    if _check_directory_listing(body) and status == 200:
        return "Directory listing enabled"
    return ""


async def _probe_path(
    session: "aiohttp.ClientSession",
    base_url: str,
    path: str,
    timeout: float,
    verify_ssl: bool = True,
) -> Optional[InterestingPath]:
    url = base_url.rstrip("/") + path
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
            ssl=None if verify_ssl else False,
        ) as resp:
            if resp.status in (200, 301, 302, 307, 308, 401, 403):
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except (aiohttp.ClientError, UnicodeDecodeError):
                    pass
                note = _classify_path_note(path, resp.status, body)
                return InterestingPath(
                    path=path,
                    status_code=resp.status,
                    content_length=len(body),
                    note=note,
                )
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return None


async def _fetch_robots(
    session: "aiohttp.ClientSession",
    base_url: str,
    timeout: float,
    verify_ssl: bool = True,
) -> list[str]:
    """Parse robots.txt and return sensitive Disallow paths."""
    url = base_url.rstrip("/") + "/robots.txt"
    sensitive: list[str] = []
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=None if verify_ssl else False,
        ) as resp:
            if resp.status == 200:
                text = await resp.text(errors="replace")
                for line in text.splitlines():
                    if _SENSITIVE_ROBOTS.search(line):
                        path = line.split(":", 1)[-1].strip()
                        if path:
                            sensitive.append(path)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return sensitive


async def probe(
    target: str,
    ports: Optional[list[int]] = None,
    probe_paths: bool = True,
    timeout: float = 10.0,
    verify_ssl: bool = True,
) -> list[HTTPResult]:
    """
    HTTP probe a target across multiple ports/protocols.

    Args:
        target:      Hostname or IP.
        ports:       Ports to probe. Defaults to [80, 443, 8080, 8443].
        probe_paths: Whether to check interesting paths (includes backup files).
        timeout:     Request timeout in seconds.
        verify_ssl:  Whether to verify TLS certificates (set False via --insecure).

    Returns:
        List of HTTPResult, one per responding endpoint.
    """
    if not HAS_AIOHTTP:
        return [HTTPResult(url=target, error="aiohttp not installed. Run: pip install aiohttp")]

    ports = ports or [80, 443, 8080, 8443]
    urls: list[str] = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        urls.append(f"{scheme}://{target}:{port}")

    ssl_ctx: bool | None = None if verify_ssl else False
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=50)
    ua_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    results: list[HTTPResult] = []

    async with aiohttp.ClientSession(connector=connector, headers=ua_headers) as session:
        for url in urls:
            result = HTTPResult(url=url)
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as resp:
                    result.status_code = resp.status
                    result.raw_headers  = dict(resp.headers)
                    result.server       = resp.headers.get("Server", "")
                    result.redirect_chain = [str(h.url) for h in resp.history]

                    body = ""
                    try:
                        body = await resp.text(errors="replace")
                    except (aiohttp.ClientError, UnicodeDecodeError):
                        pass

                    result.title = _extract_title(body)

                    # Layered technology fingerprinting
                    cookie_hdr = resp.headers.get("Set-Cookie", "")
                    result.technologies = _fingerprint_technologies(
                        dict(resp.headers), body, cookie_hdr
                    )

                    # Security header analysis
                    result.security_headers, result.missing_security_headers = (
                        _analyse_security_headers(dict(resp.headers))
                    )

                    # CORS analysis
                    result.cors_issues = _analyse_cors(dict(resp.headers))

                    # Cloud bucket references
                    result.cloud_bucket_refs = _find_cloud_bucket_refs(body)
                    for ref in result.cloud_bucket_refs:
                        result.validation_findings.append(
                            f"Cloud bucket reference ({ref.provider}): {ref.bucket_url}"
                        )

                    # Directory listing
                    if _check_directory_listing(body):
                        result.validation_findings.append(
                            f"Directory listing enabled at {url}"
                        )

                    # Cookie analysis
                    result.cookies = _check_cookies(list(resp.cookies.values()))

                    # Interesting paths + backup files
                    if probe_paths:
                        all_paths = INTERESTING_PATHS + _BACKUP_PATHS
                        path_coros = [
                            _probe_path(session, url, p, timeout / 2, verify_ssl)
                            for p in all_paths
                        ]
                        path_results = await asyncio.gather(*path_coros)
                        result.interesting_paths = [r for r in path_results if r is not None]

                        # Flag backup file hits that don't already have a note
                        for ip in result.interesting_paths:
                            if ip.path in _BACKUP_PATHS and ip.status_code == 200 and not ip.note:
                                ip.note = f"Backup file exposed: {ip.path}"
                                result.validation_findings.append(ip.note)

                        # Robots.txt analysis
                        sensitive_paths = await _fetch_robots(session, url, timeout / 2, verify_ssl)
                        result.robots_disallowed = sensitive_paths
                        if sensitive_paths:
                            result.validation_findings.append(
                                f"robots.txt discloses sensitive paths: {', '.join(sensitive_paths[:5])}"
                            )

            except aiohttp.ClientConnectorError:
                result.error = "Connection refused"
            except asyncio.TimeoutError:
                result.error = "Timeout"
            except aiohttp.ClientSSLError as exc:
                result.error = f"SSL error: {exc} (use --insecure to skip verification)"
            except aiohttp.ClientError as exc:
                result.error = str(exc)

            if not result.error:
                results.append(result)

    return results
