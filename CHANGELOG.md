# Changelog

All notable changes to ReconX are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] — 2026-03-20

### Added
- **Finding confidence model** — `Finding` dataclass gains `confidence` (0-100), `evidence: list[str]`, `affected: str`, `remediation: str`, and `references: list[str]` fields; auto-populated remediation hints and OWASP/RFC reference links via lookup tables in `severity.py`
- **Layered fingerprinting engine** — `http_probe.py` now uses multi-signal detection for every technology signature (headers + body + cookies); each signal carries an individual weight; a technology is only reported when accumulated confidence meets its threshold; `Technology.confidence` and `Technology.evidence` fields added
- **Safe validation checks** — HTTP probing now includes: CORS policy analysis (`_analyse_cors`), cloud bucket reference scanning (`_find_cloud_bucket_refs`), robots.txt sensitive path disclosure (`_fetch_robots`), backup file probing (`_BACKUP_PATHS`), and directory listing detection (`_check_directory_listing`); results stored in `HTTPResult.cors_issues`, `cloud_bucket_refs`, `robots_disallowed`, `validation_findings`
- **Asset correlation layer** — new `reconx/utils/correlation.py`: cross-references SSL SANs with discovered subdomains, classifies host roles by subdomain prefix (api, admin, staging, dev, cdn, mail, vpn, prod), builds asset inventory (all IPs, open port summary, cloud providers), and generates correlated findings (admin host reachable, shadow subdomains, staging alongside prod)
- **Wildcard DNS detection** — `subdomain.enumerate()` probes a random UUID subdomain before brute-force; hits whose IPs are a subset of the wildcard set are suppressed; `SubdomainResult` gains `wildcard_detected` and `wildcard_ips` fields
- **Plugin architecture** — `reconx/plugins/base.py` introduces a `@runtime_checkable` `ReconPlugin` Protocol (name, version, category, description, author, async run()); `PluginRegistry` with `register`, `unregister`, `get`, `all`, and `run_all` (concurrent, per-plugin `asyncio.wait_for` timeout); module-level `registry` singleton
- **Retry utility** — `reconx/utils/retry.py`: `@retry_async` decorator and `run_with_retry` function; exponential back-off with configurable retries, base delay, max delay, jitter, and exception filter
- **Report upgrades**:
  - `schema_version: "1.4"` field in JSON output
  - Executive summary block (risk badge, key stats grid, top critical/high findings)
  - Confidence percentage badge per finding row
  - Collapsible evidence list per finding
  - Collapsible remediation + reference links per finding
  - Asset Correlation & Inventory section (host roles, SSL-confirmed subdomains, IPs, cloud providers)
  - Correlation findings rendered in reports
- **CLI wiring** — `_run_scan()` now calls `correlate(collected)` and `plugin_registry.run_all()` after findings aggregation; results stored under `collected["correlation"]` and `collected["plugin_results"]`

### Changed
- `deduplicate_findings()` added to `severity.py`; keeps highest-confidence duplicate per `(title.lower(), module, affected)` key
- `sort_findings()` now uses `(severity_order, -confidence)` as sort key
- `make_finding()` gains keyword-only args: `confidence`, `description`, `evidence`, `affected`, `remediation`, `references`
- Version bumped to `1.4.0` in `reconx/__init__.py` and `pyproject.toml`

### Tests
- `tests/test_correlation.py` — host role classification, SSL SAN cross-reference, correlated finding generation, deduplication
- `tests/test_fingerprint.py` — multi-signal fingerprinting, CORS analysis, cloud bucket detection, directory listing detection
- `tests/test_plugins.py` — protocol conformance, registry CRUD, `run_all()` concurrency, timeout isolation, error handling
- `tests/test_subdomain.py` — wildcard detection, wildcard suppression, non-wildcard kept
- `tests/test_severity.py` — extended Finding fields, `deduplicate_findings()`, confidence sort

---

## [1.3.1] — 2026-03-15

### Security
- **SSL verification restored** — passive intelligence APIs (Shodan, Censys, VirusTotal, SecurityTrails, AbuseIPDB, crt.sh, OTX) now use verified TLS connections; removed `ssl=False` from all provider HTTP clients and the shared `TCPConnector`
- **`--insecure` flag added** — `reconx scan --insecure` disables certificate verification for *target* scanning only (HTTP probing and web crawling); useful for internal targets with self-signed certificates
- **`verify_ssl: bool = True`** added to `ScanProfile`; `http_probe.probe()` and `web_crawler.crawl()` accept and respect this parameter

### Changed
- `subdomenum` command renamed to `subdomains` (`reconx subdomains example.com`); the old name is retained as a hidden deprecated alias for backward compatibility
- `datetime.utcnow()` (deprecated since Python 3.12) replaced with `datetime.now(timezone.utc)` in `state.py`, `cli.py`, and `report.py`
- `except Exception` blocks in `passive_sources.py` narrowed to `(aiohttp.ClientError, asyncio.TimeoutError, ValueError)` with `log.warning()` instead of silent `log.debug()`
- `_probe_path()` in `http_probe.py` now catches `(aiohttp.ClientError, asyncio.TimeoutError)` instead of bare `except Exception`; main loop narrows to `aiohttp.ClientSSLError` (reported as actionable SSL error with `--insecure` hint) and `aiohttp.ClientError`
- `_fetch()` in `web_crawler.py` narrows to `(aiohttp.ClientError, asyncio.TimeoutError)`

### Fixed
- `aiohttp.ClientSSLError` on target scanning now surfaces a helpful message: `SSL error: ... (use --insecure to skip verification)` rather than a generic exception string

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
