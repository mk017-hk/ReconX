# Changelog

All notable changes to ReconX are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.0] — 2026-03-15

### Added
- **Structured service fingerprinting** — `PortResult` now carries separate `product`, `version`, and `confidence` fields; product/version are extracted by dedicated per-service functions (`_fp_ssh`, `_fp_ftp`, `_fp_smtp`, `_fp_http`, `_fp_redis`, `_fp_mysql`, `_fp_postgresql`, `_fp_mongodb`, `_fp_elasticsearch`, and more)
- **`standard` scan profile** — new preset between `quick` and `full`: top-1000 TCP ports with banner grabbing, DNS, HTTP probing, SSL/TLS, and WHOIS enabled
- **Finding categories** — `Finding` dataclass gains a `category` field: `network`, `dns`, `web`, `tls`, `infrastructure`, `passive_intel`; displayed in terminal output and HTML reports
- **crt.sh passive source** — Certificate Transparency subdomain discovery now runs automatically (no API key required) inside the passive sources module
- **Logging** — `logging` module wired throughout scanner, passive sources, and all new fingerprint functions; debug-level output available with standard Python logging configuration
- **`pyyaml` promoted to core dependency** — was optional; required at runtime for YAML config support

### Changed
- `_extract_version(service, raw)` is now backed by service-specific fingerprint functions instead of a linear pattern list; the old `_VERSION_PATTERNS` list is retained as an empty stub for backward compatibility
- `display_scan_result()` terminal table now shows `Product` and `Version` as separate columns with confidence-based colour coding
- `display_severity_summary()` now shows `[category]` tags instead of `[module]` tags
- `_findings_html()` in the HTML report now accepts plain dicts (`{"sev", "title", "module"}`) in addition to Finding objects and strings — no more anonymous class creation
- `_serialise()` in report.py now handles `Enum` values correctly (was silently serialising the Enum object rather than its `.value`)
- `subdomenum` CLI command: fixed parameter name mismatch (`domain` → `target`)
- `passive_sources.gather()` always runs crt.sh and OTX regardless of whether other API keys are present

### Fixed
- `PortResult` serialisation in HTML reports: `Severity` enum values now render as strings rather than `<Severity.HIGH: 'HIGH'>` literals
- `subdomenum` command crashed when invoked because the click argument name `target` did not match the Python parameter name `domain`

---

## [1.1.0] — 2026-03-15

### Added
- **Progress bars** — real-time `rich` progress bars during port scanning and subdomain brute-force
- **Multi-target batch mode** — `--targets-file` flag on `scan` command accepts a file of newline-separated targets; runs a full scan per target and saves individual reports
- **Shell tab-completion** — `reconx --install-completion` installs bash/zsh/fish completion scripts
- **Expanded subdomain wordlist** — built-in wordlist grown from 150 → 5 000 entries
- **`pyproject.toml`** — modern PEP 517/518 packaging replacing legacy `setup.py`
- **Docker support** — `Dockerfile` and `.dockerignore` for containerised usage
- **GitHub Actions CI** — automated test matrix across Python 3.10 / 3.11 / 3.12
- **pytest test suite** — unit tests for core modules (`tests/`)
- **`CONTRIBUTING.md`** — guidelines for contributors

### Changed
- Version bumped `1.0.0 → 1.1.0`
- `setup.py` retained for compatibility but `pyproject.toml` is now primary

---

## [1.0.0] — 2026-03-01

### Added
- Port scanner with async TCP scanning, banner grabbing, and service detection
- DNS enumeration (A / AAAA / MX / NS / TXT / SOA / CAA, zone-transfer detection, SPF / DMARC checks)
- Subdomain enumeration via DNS brute-force, crt.sh CT logs, and HackerTarget passive DNS
- HTTP probing with technology fingerprinting (30+ signatures), security-header analysis, and interesting-path discovery
- SSL/TLS analysis (cert validity, SANs, deprecated protocol detection, weak ciphers)
- WHOIS lookup
- JSON + self-contained HTML report generation
- `rich`-powered terminal output with colour-coded tables and severity-level findings
- MIT licence
