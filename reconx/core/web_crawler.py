"""
Web crawler and endpoint discovery module.

Features:
  - Crawls all reachable pages up to a configurable depth
  - Collects JavaScript file URLs
  - Extracts API routes, endpoints, and paths from JS source
  - Discovers subdomains referenced in JS/HTML
  - Identifies hidden/interesting paths
  - Reports unique endpoints with status codes
"""

import asyncio
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

from rich.progress import Progress, SpinnerColumn, BarColumn, MofNCompleteColumn, TextColumn

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ─────────────────────────────────────────────────────────────
# Patterns for extracting routes / endpoints from JS
# ─────────────────────────────────────────────────────────────

_JS_ENDPOINT_PATTERNS = [
    # fetch("/api/users") / axios.get('/api/v1/resource')
    re.compile(r"""(?:fetch|axios\.\w+|http\.\w+|this\.\w+)\s*\(\s*['"`]([/][^'"`\s]{2,100})['"`]"""),
    # "/api/endpoint"  or  '/internal/path'
    re.compile(r"""['"` ](/(?:api|v\d|rest|graphql|internal|admin|auth|user|account|data|service|endpoint)[^'"`\s<>]{0,80})"""),
    # path: '/some/path'
    re.compile(r"""path\s*:\s*['"`]([/][^'"`\s]{2,80})['"`]"""),
    # url: "/endpoint"
    re.compile(r"""url\s*:\s*['"`]([/][^'"`\s]{2,80})['"`]"""),
    # href="/path"
    re.compile(r"""href=["']([/][^"'?\s]{2,100})["']"""),
    # action="/path"
    re.compile(r"""action=["']([/][^"'?\s]{2,100})["']"""),
    # src="/path/file.js"
    re.compile(r"""src=["']([/][^"'?\s]{2,100}\.(?:js|json|php|asp|aspx|jsp))["']"""),
]

# Patterns to find JS file URLs
_JS_FILE_PATTERN = re.compile(
    r"""(?:src|href)=["']([^"']*?\.js(?:\?[^"']*?)?)["']""", re.I
)

# Pattern to find subdomains / external hosts in JS
_SUBDOMAIN_PATTERN = re.compile(
    r"""['"`]((?:https?://)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,})['"`]""",
    re.I,
)

# Interesting path keywords that are high-value
_HIGH_VALUE_PATHS = {
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/api/v1", "/api/v2", "/graphql", "/swagger", "/openapi",
    "/.env", "/.git", "/config", "/debug", "/actuator",
    "/console", "/dashboard", "/login", "/auth",
}


# ─────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class CrawledEndpoint:
    url: str
    status_code: int
    source: str = "crawl"    # "crawl" | "js_extract" | "form" | "link"
    content_type: str = ""
    note: str = ""


@dataclass
class JSFile:
    url: str
    endpoints_found: list[str] = field(default_factory=list)
    subdomains_found: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    target: str
    base_url: str
    endpoints: list[CrawledEndpoint] = field(default_factory=list)
    js_files: list[JSFile] = field(default_factory=list)
    discovered_subdomains: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    total_pages_crawled: int = 0
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _is_same_origin(url: str, base_host: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc == base_host or parsed.netloc == ""


def _normalise(url: str, base: str) -> str:
    return urllib.parse.urljoin(base, url)


def _extract_links(html: str, base_url: str, base_host: str) -> list[str]:
    links = []
    for m in re.finditer(r"""href=["']([^"'#?\s]+)["']""", html, re.I):
        link = _normalise(m.group(1), base_url)
        if _is_same_origin(link, base_host):
            links.append(link)
    return links


def _extract_js_files(html: str, base_url: str) -> list[str]:
    return [
        _normalise(m.group(1), base_url)
        for m in _JS_FILE_PATTERN.finditer(html)
    ]


def _extract_forms(html: str, base_url: str) -> list[dict]:
    forms = []
    for m in re.finditer(
        r"<form[^>]*action=[\"']?([^\"'>\s]*)[\"']?[^>]*>(.*?)</form>",
        html, re.I | re.DOTALL
    ):
        action = _normalise(m.group(1) or "", base_url)
        inputs = re.findall(r"""<input[^>]*name=["']([^"']+)["']""", m.group(2), re.I)
        forms.append({"action": action, "fields": inputs})
    return forms


def _analyse_js(js_content: str, base_url: str, domain: str) -> tuple[list[str], list[str]]:
    """Return (endpoints, subdomains) found in a JS file."""
    endpoints: set[str] = set()
    subdomains: set[str] = set()

    for pattern in _JS_ENDPOINT_PATTERNS:
        for m in pattern.finditer(js_content):
            path = m.group(1)
            if len(path) > 2:
                endpoints.add(path)

    for m in _SUBDOMAIN_PATTERN.finditer(js_content):
        host = m.group(2) if m.group(2) else m.group(1)
        host = host.strip("./")
        if domain in host and host != domain:
            subdomains.add(host)

    return list(endpoints), list(subdomains)


# ─────────────────────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────────────────────

async def _fetch(
    session: "aiohttp.ClientSession",
    url: str,
    timeout: float,
) -> tuple[int, str, str, dict]:
    """Fetch a URL, return (status, body, content_type, headers)."""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
        ) as resp:
            ct = resp.headers.get("Content-Type", "")
            body = ""
            if "html" in ct or "javascript" in ct or "json" in ct:
                body = await resp.text(errors="replace")
            return resp.status, body, ct, dict(resp.headers)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return 0, "", "", {}


async def crawl(
    target: str,
    max_depth: int = 2,
    max_pages: int = 50,
    concurrency: int = 10,
    timeout: float = 10.0,
    port: int = 443,
    verify_ssl: bool = True,
) -> CrawlResult:
    """
    Crawl a target website and extract endpoints, JS files, and API routes.

    Args:
        target: Domain or IP to crawl.
        max_depth: Maximum link depth from the root page.
        max_pages: Hard cap on pages to visit.
        concurrency: Max concurrent HTTP requests.
        timeout: Per-request timeout in seconds.
        port: Starting port (443 = https, 80 = http).
        verify_ssl: Whether to verify TLS certificates. Set False for targets
                    with self-signed or internal certificates (--insecure).

    Returns:
        CrawlResult with all discovered endpoints, JS files, and subdomains.
    """
    if not HAS_AIOHTTP:
        return CrawlResult(
            target=target, base_url="",
            error="aiohttp not installed. Run: pip install aiohttp"
        )

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}" if "://" not in target else target
    parsed_base = urllib.parse.urlparse(base_url)
    base_host = parsed_base.netloc or target
    domain = base_host.split(":")[0]

    result = CrawlResult(target=target, base_url=base_url)

    visited: set[str] = set()
    endpoints: dict[str, CrawledEndpoint] = {}
    js_urls: set[str] = set()
    all_subdomains: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]

    ssl_ctx: bool | None = None if verify_ssl else False
    connector = aiohttp.TCPConnector(ssl=ssl_ctx, limit=concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ReconX/1.2)"}

    semaphore = asyncio.Semaphore(concurrency)

    async def _visit(url: str, depth: int) -> None:
        if url in visited or len(visited) >= max_pages:
            return
        visited.add(url)

        status, body, ct, resp_headers = await _fetch(session, url, timeout)
        if not status:
            return

        result.total_pages_crawled += 1

        # Record endpoint
        path = urllib.parse.urlparse(url).path
        note = ""
        if any(path.startswith(h) for h in _HIGH_VALUE_PATHS):
            note = "High-value path"
        ep = CrawledEndpoint(url=url, status_code=status, content_type=ct, note=note)
        endpoints[url] = ep

        if depth >= max_depth or "html" not in ct:
            return

        # Extract links, JS files, forms
        new_links = _extract_links(body, url, base_host)
        new_js = _extract_js_files(body, url)
        js_urls.update(new_js)
        result.forms.extend(_extract_forms(body, url))

        for link in new_links:
            if link not in visited:
                queue.append((link, depth + 1))

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            transient=True,
        ) as progress:
            task_id = progress.add_task(f"Crawling {target}", total=max_pages)

            while queue and len(visited) < max_pages:
                batch = []
                while queue and len(batch) < concurrency:
                    url, depth = queue.pop(0)
                    if url not in visited:
                        batch.append((url, depth))

                if not batch:
                    break

                async with semaphore:
                    await asyncio.gather(*[_visit(url, depth) for url, depth in batch])
                progress.update(task_id, completed=len(visited))

            # Analyse JS files
            js_task = progress.add_task(f"Analysing {len(js_urls)} JS files", total=len(js_urls))
            for js_url in js_urls:
                status, body, ct, _ = await _fetch(session, js_url, timeout)
                if body:
                    extracted_endpoints, subs = _analyse_js(body, base_url, domain)
                    js_file = JSFile(
                        url=js_url,
                        endpoints_found=extracted_endpoints,
                        subdomains_found=subs,
                    )
                    result.js_files.append(js_file)
                    all_subdomains.update(subs)

                    # Add JS-discovered endpoints
                    for path in extracted_endpoints:
                        full = urllib.parse.urljoin(base_url, path)
                        if full not in endpoints:
                            endpoints[full] = CrawledEndpoint(
                                url=full, status_code=0, source="js_extract"
                            )
                progress.update(js_task, advance=1)

    result.endpoints = list(endpoints.values())
    result.discovered_subdomains = sorted(all_subdomains)
    return result
