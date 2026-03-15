# Changelog

All notable changes to ReconX are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
