# ReconX

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**All-in-one Reconnaissance & Pentesting Toolkit for Authorised Security Assessments**

[![CI](https://github.com/mk017-hk/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/mk017-hk/ReconX/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.3.1-green)](CHANGELOG.md)

> **For authorised penetration testing and security research only.**
> Always obtain written permission before scanning any system you do not own.

---

## Overview

ReconX is a modern Python reconnaissance framework built for security professionals.
It combines multiple OSINT and active enumeration techniques into a single coherent toolkit,
producing structured findings with severity ratings and self-contained HTML reports.

Key design principles:

- **Async-first** — fully `asyncio`-based core for high-throughput concurrent scanning
- **Modular** — every capability is an independent module; enable only what you need
- **Structured output** — typed dataclasses throughout; no unstructured text blobs
- **Severity-aware** — findings are classified CRITICAL → INFO and surfaced in reports
- **Production quality** — type hints, logging, graceful error handling, test coverage

---

## Capabilities

| Module | What it does |
|---|---|
| **TCP Port Scanner** | Async port scanning (top100/top1000/all/custom); protocol-aware banner grabbing; identifies product and version for SSH, FTP, SMTP, HTTP, Redis, MySQL, PostgreSQL, MongoDB, and more |
| **UDP Scanner** | Protocol-specific probes for DNS, NTP, SNMP, IKE/IPSec, DHCP, TFTP, SSDP, mDNS |
| **DNS Enumeration** | A/AAAA/MX/NS/TXT/SOA/CAA/SRV records; zone transfer attempts; SPF/DMARC analysis; NS redundancy checks |
| **Subdomain Enumeration** | DNS brute-force with a 5 000-entry wordlist; Certificate Transparency (crt.sh); HackerTarget passive DNS |
| **HTTP Probing** | Technology fingerprinting (30+ signatures: server/CMS/WAF/CDN/framework/JS libs); security header analysis; interesting path discovery (admin panels, git repos, env files, API docs) |
| **SSL/TLS Analysis** | Certificate validity, expiry, SANs, issuer; deprecated protocol detection (SSLv3, TLS 1.0/1.1); weak cipher identification; HSTS check |
| **WHOIS Lookup** | Registrar, creation/expiry dates, registrant country, name servers, DNSSEC |
| **Web Crawler** | BFS crawl with depth/page limits; form extraction; JavaScript file discovery; static JS analysis for hardcoded API routes, fetch/axios calls, GraphQL references |
| **IP & ASN Intelligence** | IP resolution; PTR reverse DNS; ASN lookup via RDAP + BGPView; geolocation via ip-api.com; cloud provider detection (AWS, Azure, GCP, Cloudflare, and more) |
| **Passive Sources** | Certificate Transparency (crt.sh, free); AlienVault OTX (free); Shodan, Censys, SecurityTrails, VirusTotal, AbuseIPDB (API key required, skipped gracefully when absent) |
| **Severity Scoring** | All findings classified CRITICAL/HIGH/MEDIUM/LOW/INFO with module category tagging (network, dns, web, tls, infrastructure, passive_intel) |
| **HTML Reports** | Self-contained single-file report: summary cards, severity bar charts, collapsible sections, severity-coloured finding rows, service distribution chart |
| **JSON Export** | Machine-readable structured output for pipeline integration |
| **Scan Profiles** | Built-in presets: `quick`, `standard`, `web`, `external`, `full`; override any setting with CLI flags or a YAML/TOML config file |
| **Batch Mode** | Scan multiple targets from a file; resume interrupted batch scans with `--resume` |
| **Rate Limiting** | `--delay`, `--jitter`, `--rate-limit` for low-noise / authorised assessment modes |

---

## Installation

### Standard install (editable)

```bash
git clone https://github.com/mk017-hk/ReconX.git
cd ReconX
pip install -e .
```

### With optional YAML config support

```bash
pip install -e ".[config]"
```

### Development (includes pytest, coverage)

```bash
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t reconx .

# Run a scan
docker run --rm reconx scan example.com --profile standard

# Save reports to the host filesystem
docker run --rm -v $(pwd)/reports:/reports \
  reconx scan example.com --all --report example --output-dir /reports
```

---

## Quick Start

### Run a standard scan

```bash
reconx scan example.com
```

### Full scan with all modules

```bash
reconx scan example.com --all --report example_recon
```

### Use a scan profile

```bash
reconx scan example.com --profile standard --report output
reconx scan example.com --profile full --report full_recon
```

### Low-noise mode (authorised assessments)

```bash
reconx scan example.com --delay 0.5 --jitter 0.2 --report safe_scan
```

### Batch scan from file

```bash
# targets.txt — one domain or IP per line, # for comments
reconx scan placeholder --targets-file targets.txt --all --report batch_recon

# Resume an interrupted batch
reconx scan placeholder --targets-file targets.txt --resume --report batch_recon
```

---

## Scan Profiles

Profiles provide sensible defaults for common assessment scenarios.
Any profile setting can be overridden with individual CLI flags.

| Profile | Ports | Banner grab | DNS | HTTP | SSL | WHOIS | Subdomain | UDP | Crawl | IP Intel | Passive |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `quick` | top100 | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `standard` | top1000 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `web` | web ports | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ |
| `external` | top1000 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ |
| `full` | top1000 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Standalone Commands

Each module can be invoked independently:

```bash
# TCP port scan only
reconx portscan 192.168.1.1 --ports 22,80,443,3306,5432

# UDP scan
reconx udpscan example.com --ports 53,161,500

# DNS enumeration
reconx dnsenum example.com

# Subdomain enumeration
reconx subdomains example.com --wordlist /path/to/wordlist.txt

# SSL/TLS analysis
reconx sslcheck example.com --port 443

# WHOIS
reconx whoislookup example.com

# HTTP probing and tech fingerprinting
reconx httpprobe example.com --ports 80,443,8080

# Web crawl
reconx crawl example.com --depth 3 --max-pages 100

# IP / ASN intelligence
reconx ipintel example.com
```

---

## Configuration

### Generate an example config file

```bash
reconx init-config --output reconx.yml
```

### Example `reconx.yml`

```yaml
# Scan profile base (quick | standard | web | external | full)
# preset: standard

# Port scan
ports: top1000
concurrency: 300
timeout: 1.5
grab_banners: true

# UDP scan
udp: false
udp_ports: "53,67,69,123,161,500"

# Module toggles
dns: true
subdomains: false
http: true
ssl: true
whois: true
ip_intel: false
crawl: false
passive_sources: false

# HTTP options
http_ports: "80,443,8080,8443"
path_probe: true

# Crawl options
crawl_depth: 2
crawl_max_pages: 50

# Rate limiting (safe / low-noise mode)
delay: 0.0     # fixed seconds between probes
jitter: 0.0    # max random additional delay
rate_limit: 0  # max requests/sec (0 = unlimited)

# Reporting
output_dir: reports
report_formats:
  - json
  - html

# API keys — prefer environment variables over config files
# shodan_key: ""
# censys_id: ""
# censys_secret: ""
# securitytrails_key: ""
# virustotal_key: ""
# abuseipdb_key: ""
```

### Use a config file

```bash
reconx scan example.com --config reconx.yml
```

---

## Passive Source Integrations

Passive sources enrich results without active scanning.
Free providers run automatically; paid providers activate when their API key is set.

| Provider | Capability | Key required |
|---|---|---|
| **crt.sh** | Certificate Transparency subdomain discovery | No |
| **AlienVault OTX** | Passive DNS threat intelligence | No |
| **Shodan** | Host/port history, subdomain enumeration | `SHODAN_API_KEY` |
| **Censys** | Service records, reverse DNS | `CENSYS_API_ID` + `CENSYS_API_SECRET` |
| **SecurityTrails** | Subdomain enumeration, WHOIS history, email addresses | `SECURITYTRAILS_API_KEY` |
| **VirusTotal** | Malicious verdict, subdomain list | `VIRUSTOTAL_API_KEY` |
| **AbuseIPDB** | IP abuse confidence score | `ABUSEIPDB_API_KEY` |

### Setting API keys

Prefer environment variables — never commit keys to version control:

```bash
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export CENSYS_API_ID="your_id_here"
export CENSYS_API_SECRET="your_secret_here"
```

Or set them in `reconx.yml` under `shodan_key`, `virustotal_key`, etc.

---

## CLI Reference

```
Usage: reconx scan [OPTIONS] TARGET

  Run a full or selective reconnaissance scan against TARGET.

Options:
  -P, --profile TEXT        Preset: quick | standard | web | external | full
  --config TEXT             Path to YAML/TOML config file
  -p, --ports TEXT          Port spec: top100, top1000, all, 1-1024, 22,80,443
  -c, --concurrency INT     Max concurrent TCP connections [default: 300]
  -t, --timeout FLOAT       Per-port timeout (seconds) [default: 1.5]
  --no-banners              Skip banner grabbing (faster scan)
  --delay FLOAT             Fixed delay between probes (seconds)
  --jitter FLOAT            Max random jitter added to delay (seconds)
  --rate-limit INT          Max requests per second (0 = unlimited)
  --udp / --no-udp          Run UDP scan on common ports
  --udp-ports TEXT          UDP ports to probe [default: 53,67,69,123,161,500]
  --dns / --no-dns          DNS enumeration [default: on]
  --subdomains              Enable subdomain enumeration [default: off]
  -w, --wordlist PATH       Custom subdomain wordlist path
  --no-passive              Disable passive subdomain sources
  --http / --no-http        HTTP probing and tech fingerprinting [default: on]
  --http-ports TEXT         HTTP ports to probe [default: 80,443,8080,8443]
  --no-path-probe           Skip interesting path discovery
  --ssl / --no-ssl          SSL/TLS certificate analysis [default: on]
  --ssl-port INT            Port for SSL analysis [default: 443]
  --whois / --no-whois      WHOIS lookup [default: on]
  --ip-intel / --no-ip-intel  ASN, cloud provider, geolocation lookup
  --crawl / --no-crawl      Web crawl and JS endpoint discovery
  --crawl-depth INT         Max crawl depth [default: 2]
  --crawl-pages INT         Max pages to crawl [default: 50]
  --passive / --no-passive-sources  Passive source integrations
  -a, --all                 Enable all modules
  --insecure                Disable TLS certificate verification for target scanning
                            (use for internal targets or self-signed certificates;
                             passive intelligence APIs always use verified TLS)
  -r, --report TEXT         Report base name (saves JSON + HTML)
  -o, --output-dir TEXT     Report output directory [default: reports]
  -q, --quiet               Suppress banner and progress output
  -T, --targets-file PATH   File of newline-separated targets (batch mode)
  --resume                  Resume a previous interrupted batch scan
  --help                    Show this message and exit.
```

---

## Example Output

```
  → Target: example.com
  → Started: 2026-03-15 12:00:00 UTC

──────────────── 🔍  Port Scan ────────────────
Scanning example.com ━━━━━━━━━━━━━━━━━━━━ 100%  3 open

 Port    Service    Product      Version    Banner
 22      SSH        OpenSSH      8.9p1      SSH-2.0-OpenSSH_8.9p1 Ubuntu
 80      HTTP       Apache       2.4.58     Apache/2.4.58 (Ubuntu)
 443     HTTPS      nginx        1.24.0     nginx/1.24.0
 Scanned 1000 ports · Found 3 open

──────────────── 📡  DNS Enumeration ────────────────
 Type    Value
 A       93.184.216.34
 MX      0 .
 NS      a.iana-servers.net.
 TXT     v=spf1 -all

  Security Findings:
  ⚠  No DMARC record found — phishing protection absent

──────────────── ⚠️  Findings Summary ────────────────
    MEDIUM      2
    INFO        3

  MEDIUM     [dns]    No DMARC record found — phishing protection absent
  MEDIUM     [http]   CSP missing — XSS protection absent
  INFO       [ports]  SSH open on TCP/22
```

---

## Project Structure

```
ReconX/
├── pyproject.toml              # PEP 517/518 packaging, dependencies, tool config
├── Dockerfile                  # Multi-stage Docker image
├── CHANGELOG.md
├── CONTRIBUTING.md
├── reconx/
│   ├── __init__.py             # Version string
│   ├── cli.py                  # Click CLI — all commands and options
│   ├── config.py               # Scan profiles, YAML/TOML config loader
│   ├── core/
│   │   ├── scanner.py          # Async TCP port scanner + service fingerprinting
│   │   ├── udp_scanner.py      # UDP scanner with protocol-specific probes
│   │   ├── dns_enum.py         # DNS record enumeration + zone transfer detection
│   │   ├── subdomain.py        # Subdomain brute-force + passive sources
│   │   ├── http_probe.py       # HTTP probing + technology fingerprinting
│   │   ├── ssl_analyzer.py     # SSL/TLS certificate and protocol analysis
│   │   ├── whois_lookup.py     # WHOIS lookup
│   │   ├── web_crawler.py      # BFS web crawler + JavaScript endpoint extraction
│   │   ├── ip_intel.py         # ASN, geolocation, cloud provider detection
│   │   ├── passive_sources.py  # crt.sh, OTX, Shodan, Censys, VT, AbuseIPDB
│   │   └── severity.py         # Finding classification and severity scoring
│   ├── utils/
│   │   ├── display.py          # Rich terminal output
│   │   ├── report.py           # JSON + HTML report generation
│   │   └── state.py            # Scan state persistence (resume support)
│   └── wordlists/
│       └── subdomains.txt      # 5 000-entry built-in subdomain wordlist
└── tests/                      # pytest test suite
```

---

## Architecture

ReconX is built on a small set of well-chosen dependencies:

| Library | Role |
|---|---|
| `asyncio` | Fully async core for concurrent scanning |
| `aiohttp` | Async HTTP client for probing and passive API calls |
| `dnspython` | DNS resolution and zone transfer attempts |
| `rich` | Terminal output: progress bars, tables, colour |
| `click` | CLI framework with subcommands and shell completion |
| `cryptography` | TLS certificate parsing |
| `python-whois` | WHOIS data retrieval |
| `pyyaml` | YAML config file support |

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run the test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=reconx --cov-report=term-missing
```

### Shell completion

```bash
reconx install-completion bash   # or zsh / fish
```

---

## Ethical Use

This tool is provided for **authorised security testing and research only**.

- Always obtain explicit written permission before scanning any system.
- Do not use this tool against systems you do not own or have permission to test.
- The authors accept no liability for misuse of this software.
- Comply with all applicable laws and regulations in your jurisdiction.
