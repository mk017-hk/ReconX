"""
Configuration profiles for ReconX.

Supports YAML or TOML config files, and built-in named presets:
  quick     — fast port scan + DNS only
  web       — HTTP/HTTPS probing + SSL + DNS
  external  — full external recon without subdomain brute-force
  full      — everything enabled

Config file locations (searched in order):
  1. Path supplied via --config flag
  2. ./reconx.yml  /  ./reconx.yaml  /  ./reconx.toml
  3. ~/.config/reconx/config.yml
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────
# Profile dataclass
# ─────────────────────────────────────────────────────────────

@dataclass
class ScanProfile:
    # Port scan
    ports: str = "top100"
    concurrency: int = 300
    timeout: float = 1.5
    grab_banners: bool = True
    udp: bool = False
    udp_ports: str = "53,67,69,123,161,500"

    # Modules
    dns: bool = True
    subdomains: bool = False
    http: bool = True
    ssl: bool = True
    whois: bool = True
    ip_intel: bool = False
    crawl: bool = False
    passive_sources: bool = False

    # Subdomain options
    wordlist: Optional[str] = None
    passive_subdomain: bool = True

    # HTTP options
    http_ports: str = "80,443,8080,8443"
    path_probe: bool = True
    crawl_depth: int = 2
    crawl_max_pages: int = 50

    # Rate limiting / safe mode
    delay: float = 0.0       # seconds between probes
    jitter: float = 0.0      # max random jitter seconds
    rate_limit: int = 0      # max requests/sec (0 = unlimited)

    # Reporting
    output_dir: str = "reports"
    report_formats: list[str] = field(default_factory=lambda: ["json", "html"])

    # SSL / TLS verification
    verify_ssl: bool = True   # False → skip cert verification (--insecure)

    # API keys (optional integrations)
    shodan_key: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    securitytrails_key: str = ""
    virustotal_key: str = ""
    abuseipdb_key: str = ""


# ─────────────────────────────────────────────────────────────
# Built-in presets
# ─────────────────────────────────────────────────────────────

PRESETS: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        ports="top100",
        concurrency=500,
        timeout=1.0,
        grab_banners=False,
        dns=True,
        subdomains=False,
        http=False,
        ssl=False,
        whois=False,
        ip_intel=False,
        crawl=False,
    ),
    "standard": ScanProfile(
        ports="top1000",
        concurrency=300,
        timeout=1.5,
        grab_banners=True,
        dns=True,
        subdomains=False,
        http=True,
        ssl=True,
        whois=True,
        ip_intel=False,
        crawl=False,
        passive_sources=False,
        path_probe=True,
        http_ports="80,443,8080,8443",
    ),
    "web": ScanProfile(
        ports="80,443,8080,8443,8000,8888",
        concurrency=100,
        timeout=2.0,
        grab_banners=True,
        dns=True,
        subdomains=False,
        http=True,
        ssl=True,
        whois=False,
        ip_intel=False,
        crawl=True,
        path_probe=True,
        http_ports="80,443,8080,8443",
    ),
    "external": ScanProfile(
        ports="top1000",
        concurrency=300,
        timeout=1.5,
        grab_banners=True,
        dns=True,
        subdomains=False,
        http=True,
        ssl=True,
        whois=True,
        ip_intel=True,
        crawl=False,
        passive_sources=True,
    ),
    "full": ScanProfile(
        ports="top1000",
        concurrency=200,
        timeout=2.0,
        grab_banners=True,
        udp=True,
        dns=True,
        subdomains=True,
        http=True,
        ssl=True,
        whois=True,
        ip_intel=True,
        crawl=True,
        passive_sources=True,
        path_probe=True,
        crawl_depth=3,
        crawl_max_pages=100,
    ),
}


# ─────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────

def _find_config_file() -> Optional[Path]:
    candidates = [
        Path("reconx.yml"),
        Path("reconx.yaml"),
        Path("reconx.toml"),
        Path.home() / ".config" / "reconx" / "config.yml",
        Path.home() / ".config" / "reconx" / "config.toml",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def load(config_path: Optional[str] = None, preset: Optional[str] = None) -> ScanProfile:
    """
    Load a ScanProfile.

    Priority:
      1. preset name (quick/web/external/full) — overrides file defaults
      2. config file values
      3. built-in defaults

    API keys are also read from environment variables:
      SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
      SECURITYTRAILS_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
    """
    profile = ScanProfile()

    # Apply config file first
    path = Path(config_path) if config_path else _find_config_file()
    if path and path.exists():
        try:
            if path.suffix in (".yml", ".yaml"):
                try:
                    import yaml
                    raw: dict = yaml.safe_load(path.read_text()) or {}
                except ImportError:
                    raw = {}
            elif path.suffix == ".toml":
                try:
                    import tomllib  # Python 3.11+
                    raw = tomllib.loads(path.read_text())
                except ImportError:
                    try:
                        import tomli
                        raw = tomli.loads(path.read_text())
                    except ImportError:
                        raw = {}
            else:
                raw = {}

            for key, value in raw.items():
                if hasattr(profile, key):
                    setattr(profile, key, value)
        except Exception:
            pass  # Silently ignore malformed config

    # Apply preset (overrides file)
    if preset and preset in PRESETS:
        preset_profile = PRESETS[preset]
        for key in vars(preset_profile):
            setattr(profile, key, getattr(preset_profile, key))

    # Read API keys from environment
    profile.shodan_key = os.getenv("SHODAN_API_KEY", profile.shodan_key)
    profile.censys_id = os.getenv("CENSYS_API_ID", profile.censys_id)
    profile.censys_secret = os.getenv("CENSYS_API_SECRET", profile.censys_secret)
    profile.securitytrails_key = os.getenv("SECURITYTRAILS_API_KEY", profile.securitytrails_key)
    profile.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", profile.virustotal_key)
    profile.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", profile.abuseipdb_key)

    return profile


def write_example(path: str = "reconx.yml") -> None:
    """Write an example config file to disk."""
    example = """\
# ReconX configuration file
# All settings are optional — omit to use defaults.

# Preset to base this config on (quick / web / external / full)
# preset: external

# ── Port scan ──────────────────────────────────────────────
ports: top100           # top100 | top1000 | all | 1-1024 | 22,80,443
concurrency: 300
timeout: 1.5
grab_banners: true
udp: false
udp_ports: "53,67,69,123,161,500"

# ── Modules ────────────────────────────────────────────────
dns: true
subdomains: false
http: true
ssl: true
whois: true
ip_intel: false
crawl: false
passive_sources: false

# ── HTTP ───────────────────────────────────────────────────
http_ports: "80,443,8080,8443"
path_probe: true
crawl_depth: 2
crawl_max_pages: 50

# ── Rate limiting ──────────────────────────────────────────
delay: 0.0    # fixed delay between probes (seconds)
jitter: 0.0   # max random additional delay (seconds)
rate_limit: 0 # max requests/sec (0 = unlimited)

# ── Reporting ──────────────────────────────────────────────
output_dir: reports
report_formats:
  - json
  - html

# ── Optional API keys ──────────────────────────────────────
# Prefer setting via environment variables instead of this file.
# shodan_key: ""
# censys_id: ""
# censys_secret: ""
# securitytrails_key: ""
# virustotal_key: ""
# abuseipdb_key: ""
"""
    Path(path).write_text(example)
