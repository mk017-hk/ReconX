"""
HTTP probing & technology fingerprinting module.

Detects:
  - Server, framework, CMS, CDN, WAF
  - Security headers (or absence thereof)
  - Interesting paths (robots.txt, sitemap.xml, admin panels)
  - Cookie flags
  - Redirect chains
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ──────────────────────────────────────────────
# Technology fingerprint signatures
# ──────────────────────────────────────────────

TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # (category, tech_name, regex_pattern_in_headers_or_body)
    # Servers
    ("Server", "Apache", r"Apache(?:/[\d.]+)?"),
    ("Server", "Nginx", r"nginx(?:/[\d.]+)?"),
    ("Server", "IIS", r"Microsoft-IIS(?:/[\d.]+)?"),
    ("Server", "LiteSpeed", r"LiteSpeed"),
    ("Server", "Caddy", r"Caddy"),
    ("Server", "Tomcat", r"Apache-Coyote|Tomcat"),
    # WAF
    ("WAF", "Cloudflare", r"cloudflare|cf-ray"),
    ("WAF", "AWS WAF", r"awswaf|x-amzn-requestid"),
    ("WAF", "Sucuri", r"sucuri|x-sucuri"),
    ("WAF", "Akamai", r"akamai|x-akamai"),
    ("WAF", "Imperva", r"incapsula|x-iinfo"),
    ("WAF", "ModSecurity", r"mod_security|modsecurity"),
    # CDN
    ("CDN", "Cloudflare", r"cf-cache-status|cf-ray"),
    ("CDN", "Fastly", r"x-fastly|fastly"),
    ("CDN", "Varnish", r"x-varnish|Via.*varnish"),
    ("CDN", "AWS CloudFront", r"x-amz-cf-id|cloudfront"),
    # Frameworks/Languages
    ("Framework", "PHP", r"X-Powered-By:.*PHP|\.php"),
    ("Framework", "ASP.NET", r"X-Powered-By:.*ASP\.NET|x-aspnet"),
    ("Framework", "Django", r"csrftoken|django"),
    ("Framework", "Laravel", r"laravel_session|XSRF-TOKEN"),
    ("Framework", "Rails", r"X-Powered-By:.*Phusion|_rails_session"),
    ("Framework", "Express.js", r"X-Powered-By:.*Express"),
    ("Framework", "Spring", r"JSESSIONID"),
    # CMS
    ("CMS", "WordPress", r"/wp-content/|/wp-includes/|wp-json"),
    ("CMS", "Drupal", r"Drupal|drupal|X-Generator:.*Drupal"),
    ("CMS", "Joomla", r"Joomla|joomla"),
    ("CMS", "Magento", r"Magento|magento|mage-"),
    ("CMS", "Shopify", r"shopify|cdn\.shopify"),
    # JS Libraries (body)
    ("JavaScript", "jQuery", r"jquery(?:\.min)?\.js|jQuery v[\d.]+"),
    ("JavaScript", "React", r"react(?:\.min)?\.js|__REACT"),
    ("JavaScript", "Vue.js", r"vue(?:\.min)?\.js|__vue"),
    ("JavaScript", "Angular", r"angular(?:\.min)?\.js|ng-version"),
    ("JavaScript", "Bootstrap", r"bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js"),
]

# Security headers that SHOULD be present
EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — HTTPS downgrade attacks possible",
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME-type sniffing protection missing",
    "Content-Security-Policy": "CSP missing — XSS protection absent",
    "Referrer-Policy": "Referrer-Policy missing",
    "Permissions-Policy": "Permissions-Policy missing",
}

# Common interesting paths to probe
INTERESTING_PATHS = [
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
]


@dataclass
class Technology:
    category: str
    name: str


@dataclass
class SecurityHeader:
    name: str
    value: Optional[str]  # None = missing
    finding: Optional[str] = None


@dataclass
class InterestingPath:
    path: str
    status_code: int
    content_length: int = 0
    note: str = ""


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
    error: Optional[str] = None


def _extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:200]
    return ""


def _fingerprint_technologies(headers: dict[str, str], body: str) -> list[Technology]:
    """Match tech signatures against headers and body."""
    found: dict[str, Technology] = {}
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower() + "\n" + body[:8000].lower()

    for category, name, pattern in TECH_SIGNATURES:
        key = f"{category}:{name}"
        if key not in found and re.search(pattern, combined, re.IGNORECASE):
            found[key] = Technology(category=category, name=name)

    return list(found.values())


def _analyse_security_headers(headers: dict[str, str]) -> tuple[list[SecurityHeader], list[str]]:
    headers_lower = {k.lower(): v for k, v in headers.items()}
    present: list[SecurityHeader] = []
    missing: list[str] = []

    for header, warning in EXPECTED_SECURITY_HEADERS.items():
        val = headers_lower.get(header.lower())
        if val:
            sh = SecurityHeader(name=header, value=val)
            # Flag weak values
            if header == "Strict-Transport-Security" and "max-age=0" in val:
                sh.finding = "HSTS max-age=0 effectively disables HSTS"
            if header == "X-Frame-Options" and val.upper() not in ("DENY", "SAMEORIGIN"):
                sh.finding = f"X-Frame-Options value '{val}' may be weak"
            present.append(sh)
        else:
            missing.append(warning)

    return present, missing


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
            ssl=verify_ssl or None,
        ) as resp:
            if resp.status in (200, 301, 302, 307, 308, 401, 403):
                body = ""
                try:
                    body = await resp.text(errors="replace")
                except (aiohttp.ClientError, UnicodeDecodeError):
                    pass
                note = ""
                if path == "/.git/HEAD" and resp.status == 200:
                    note = "GIT REPO EXPOSED — source code may be accessible!"
                elif path == "/.env" and resp.status == 200:
                    note = "ENV FILE EXPOSED — credentials/secrets may be leaked!"
                elif path in ("/server-status", "/server-info") and resp.status == 200:
                    note = "Server status page exposed"
                elif "graphql" in path and resp.status == 200:
                    note = "GraphQL endpoint found"
                elif "actuator" in path and resp.status == 200:
                    note = "Spring Actuator exposed — admin endpoint!"
                return InterestingPath(
                    path=path,
                    status_code=resp.status,
                    content_length=len(body),
                    note=note,
                )
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return None


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
        target: Hostname or IP.
        ports: Ports to probe. Defaults to [80, 443, 8080, 8443].
        probe_paths: Whether to check interesting paths.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify TLS certificates. Set False for targets
                    with self-signed or internal certificates (--insecure).

    Returns:
        List of HTTPResult, one per responding endpoint.
    """
    if not HAS_AIOHTTP:
        return [HTTPResult(url=target, error="aiohttp not installed. Run: pip install aiohttp")]

    ports = ports or [80, 443, 8080, 8443]
    urls = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        urls.append(f"{scheme}://{target}:{port}")

    # ssl=False disables verification; ssl=None uses the system CA bundle (verify=True behaviour).
    ssl_ctx: bool | None = None if verify_ssl else False
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=50)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    results: list[HTTPResult] = []

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        for url in urls:
            result = HTTPResult(url=url)
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True,
                ) as resp:
                    result.status_code = resp.status
                    result.raw_headers = dict(resp.headers)
                    result.server = resp.headers.get("Server", "")

                    # Redirect chain
                    result.redirect_chain = [str(h.url) for h in resp.history]

                    # Body
                    body = ""
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        pass

                    result.title = _extract_title(body)

                    # Tech fingerprinting
                    result.technologies = _fingerprint_technologies(
                        dict(resp.headers), body
                    )

                    # Security headers
                    result.security_headers, result.missing_security_headers = (
                        _analyse_security_headers(dict(resp.headers))
                    )

                    # Cookies
                    result.cookies = _check_cookies(list(resp.cookies.values()))

                    # Interesting path discovery
                    if probe_paths:
                        path_tasks = [
                            _probe_path(session, url, path, timeout / 2, verify_ssl)
                            for path in INTERESTING_PATHS
                        ]
                        path_results = await asyncio.gather(*path_tasks)
                        result.interesting_paths = [
                            r for r in path_results if r is not None
                        ]

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
