"""
Subdomain enumeration module.

Combines:
  1. DNS brute-force from a wordlist
  2. Certificate Transparency log lookup (crt.sh)
  3. (Optional) passive source: HackerTarget
"""

import asyncio
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import dns.asyncresolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

_WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"

# Public passive sources
_CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
_HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"


@dataclass
class Subdomain:
    name: str
    ips: list[str] = field(default_factory=list)
    source: str = "bruteforce"  # "bruteforce" | "crtsh" | "hackertarget"
    cname: str = ""


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    total_checked: int = 0
    error: Optional[str] = None


async def _resolve(hostname: str) -> list[str]:
    """Resolve A records for hostname, return list of IPs."""
    if not HAS_DNSPYTHON:
        try:
            return [socket.gethostbyname(hostname)]
        except Exception:
            return []
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        answers = await resolver.resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


async def _bruteforce_chunk(
    domain: str,
    words: list[str],
    semaphore: asyncio.Semaphore,
    results: list[Subdomain],
) -> None:
    for word in words:
        async with semaphore:
            hostname = f"{word}.{domain}"
            ips = await _resolve(hostname)
            if ips:
                results.append(Subdomain(name=hostname, ips=ips, source="bruteforce"))


async def _crtsh_lookup(domain: str, timeout: int = 15) -> list[str]:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    if not HAS_AIOHTTP:
        return []
    url = _CRTSH_URL.format(domain=domain)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    names: set[str] = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lstrip("*.")
                            if n and domain in n:
                                names.add(n)
                    return list(names)
    except Exception:
        pass
    return []


async def _hackertarget_lookup(domain: str, timeout: int = 15) -> list[str]:
    """Fetch subdomains from HackerTarget passive DNS."""
    if not HAS_AIOHTTP:
        return []
    url = _HACKERTARGET_URL.format(domain=domain)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "error" in text.lower() and "API" in text:
                        return []
                    names = []
                    for line in text.strip().splitlines():
                        if "," in line:
                            names.append(line.split(",")[0].strip())
                    return names
    except Exception:
        pass
    return []


async def enumerate(
    domain: str,
    wordlist_path: Optional[str] = None,
    concurrency: int = 200,
    use_passive: bool = True,
) -> SubdomainResult:
    """
    Enumerate subdomains via bruteforce + passive sources.

    Args:
        domain: Target domain.
        wordlist_path: Path to subdomain wordlist. Defaults to built-in list.
        concurrency: Max concurrent DNS lookups.
        use_passive: Whether to query crt.sh and HackerTarget.

    Returns:
        SubdomainResult with all discovered subdomains.
    """
    result = SubdomainResult(domain=domain)

    # Load wordlist
    wl_path = Path(wordlist_path) if wordlist_path else _WORDLIST_PATH
    words: list[str] = []
    if wl_path.exists():
        words = [
            line.strip()
            for line in wl_path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    result.total_checked = len(words)

    found: list[Subdomain] = []
    semaphore = asyncio.Semaphore(concurrency)

    # Run bruteforce + passive lookups concurrently
    passive_tasks = []
    if use_passive:
        passive_tasks = [_crtsh_lookup(domain), _hackertarget_lookup(domain)]

    brute_task = _bruteforce_chunk(domain, words, semaphore, found)

    if passive_tasks:
        brute_result, *passive_results = await asyncio.gather(
            brute_task, *passive_tasks, return_exceptions=True
        )
        passive_names: set[str] = set()
        for pr in passive_results:
            if isinstance(pr, list):
                passive_names.update(pr)

        # Resolve passive results
        seen = {s.name for s in found}
        resolve_tasks = [
            _resolve(name)
            for name in passive_names
            if name not in seen and domain in name
        ]
        if resolve_tasks:
            resolved = await asyncio.gather(*resolve_tasks)
            for name, ips in zip(
                [n for n in passive_names if n not in seen and domain in n],
                resolved,
            ):
                source = "crtsh"
                found.append(Subdomain(name=name, ips=ips, source=source))
    else:
        await brute_task

    # Deduplicate by name
    seen_names: set[str] = set()
    unique: list[Subdomain] = []
    for s in found:
        if s.name not in seen_names:
            seen_names.add(s.name)
            unique.append(s)

    result.subdomains = sorted(unique, key=lambda s: s.name)
    return result
