"""
WHOIS lookup module.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WhoisResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    registrant_country: str = ""
    status: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    dnssec: str = ""
    raw: str = ""
    error: Optional[str] = None


def _fmt_date(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0]
    try:
        return val.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(val)


async def lookup(domain: str) -> WhoisResult:
    """
    Perform a WHOIS lookup for a domain.

    Args:
        domain: Target domain name.

    Returns:
        WhoisResult with registration details.
    """
    result = WhoisResult(domain=domain)
    loop = asyncio.get_event_loop()

    def _do_whois():
        try:
            import whois as pythonwhois
            return pythonwhois.whois(domain)
        except ImportError:
            return None
        except Exception as exc:
            return exc

    try:
        w = await asyncio.wait_for(
            loop.run_in_executor(None, _do_whois), timeout=20
        )
    except asyncio.TimeoutError:
        result.error = "WHOIS lookup timed out"
        return result

    if w is None:
        result.error = "python-whois not installed. Run: pip install python-whois"
        return result

    if isinstance(w, Exception):
        result.error = str(w)
        return result

    result.registrar = str(w.registrar or "")
    result.creation_date = _fmt_date(w.creation_date)
    result.expiration_date = _fmt_date(w.expiration_date)
    result.updated_date = _fmt_date(w.updated_date)
    result.registrant_country = str(w.country or "")
    result.dnssec = str(w.dnssec or "")

    ns = w.name_servers or []
    result.name_servers = sorted({n.lower() for n in ns if n})

    status = w.status or []
    if isinstance(status, str):
        status = [status]
    result.status = list(status)

    emails = w.emails or []
    if isinstance(emails, str):
        emails = [emails]
    result.emails = list(emails)

    try:
        result.raw = str(w.text or "")[:3000]
    except Exception:
        pass

    return result
