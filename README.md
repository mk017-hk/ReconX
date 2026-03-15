# ReconX

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**All-in-one Reconnaissance & Pentesting Toolkit**

[![CI](https://github.com/mk017-hk/ReconX/actions/workflows/ci.yml/badge.svg)](https://github.com/mk017-hk/ReconX/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> For authorised security testing only.

---

## Features

| Module | Capability |
|---|---|
| **Port Scanner** | Async TCP scanning with real-time progress bar, banner grabbing, service detection |
| **DNS Enumeration** | A/AAAA/MX/NS/TXT/SOA/CAA records, zone transfer attempts, SPF/DMARC checks |
| **Subdomain Enumeration** | DNS bruteforce (5 000-entry wordlist) + Certificate Transparency (crt.sh) + HackerTarget passive DNS |
| **HTTP Probing** | Tech fingerprinting (server/CMS/WAF/CDN/framework/JS libs), security header analysis, interesting path discovery |
| **SSL/TLS Analysis** | Certificate validity, expiry, SANs, deprecated protocol detection, weak cipher detection |
| **WHOIS** | Registrar, dates, name servers, registrant info |
| **Report Generator** | Self-contained HTML report + JSON export |
| **Batch Mode** | Scan multiple targets from a file with `--targets-file` |

---

## Quick Start

### Install

```bash
pip install -e .
```

### Docker

```bash
docker build -t reconx .
docker run --rm reconx scan example.com --all
# save reports to host:
docker run --rm -v $(pwd)/reports:/reports reconx scan example.com --all --report example --output-dir /reports
```

### Run a full scan

```bash
reconx scan example.com --all --report example_recon
```

### Scan multiple targets at once

```bash
# targets.txt — one target per line
reconx scan placeholder --targets-file targets.txt --all --report batch
```

### Run specific modules

```bash
# Port scan only
reconx scan example.com --no-dns --no-http --no-ssl --no-whois

# Full scan with subdomain enumeration + report
reconx scan example.com --all --subdomains --report my_report

# Custom port range
reconx scan example.com --ports 1-1024 --concurrency 500

# Quick port scan
reconx portscan 192.168.1.1 --ports 22,80,443,3306,5432
```

### Standalone commands

```bash
reconx dnsenum example.com
reconx subdomenum example.com --wordlist /path/to/wordlist.txt
reconx sslcheck example.com --port 443
reconx whoislookup example.com
reconx httpprobe example.com --ports 80,443,8080
```

### Shell tab-completion

```bash
reconx install-completion bash   # or zsh / fish
```

---

## Usage Reference

```
Usage: reconx scan [OPTIONS] TARGET

Options:
  -p, --ports TEXT          Port spec: top100, top1000, all, 1-1024, 22,80,443
  -c, --concurrency INT     Max concurrent connections [default: 300]
  -t, --timeout FLOAT       Per-port timeout in seconds [default: 1.5]
  --no-banners              Skip banner grabbing (faster)
  --dns / --no-dns          DNS enumeration [default: on]
  --subdomains              Enable subdomain enumeration [default: off]
  -w, --wordlist PATH       Custom subdomain wordlist
  --no-passive              Disable passive subdomain sources
  --http / --no-http        HTTP probing [default: on]
  --http-ports TEXT         HTTP ports to probe [default: 80,443,8080,8443]
  --no-path-probe           Skip interesting path discovery
  --ssl / --no-ssl          SSL/TLS analysis [default: on]
  --ssl-port INT            SSL port [default: 443]
  --whois / --no-whois      WHOIS lookup [default: on]
  -a, --all                 Enable all modules
  -r, --report TEXT         Report base name (saves JSON + HTML)
  -o, --output-dir TEXT     Report output directory [default: reports]
  -q, --quiet               Suppress banner output
  -T, --targets-file PATH   File of newline-separated targets (batch mode)
  --help                    Show this message and exit.
```

---

## Project Structure

```
ReconX/
├── Dockerfile
├── pyproject.toml
├── CHANGELOG.md
├── CONTRIBUTING.md
├── reconx/
│   ├── cli.py                  # Click CLI — all commands
│   ├── core/
│   │   ├── scanner.py          # Async TCP port scanner
│   │   ├── dns_enum.py         # DNS record enumeration + zone transfer
│   │   ├── subdomain.py        # Subdomain brute-force + passive sources
│   │   ├── http_probe.py       # HTTP probing + tech fingerprinting
│   │   ├── ssl_analyzer.py     # SSL/TLS certificate analysis
│   │   └── whois_lookup.py     # WHOIS lookup
│   ├── utils/
│   │   ├── display.py          # Rich terminal display
│   │   └── report.py           # JSON + HTML report generator
│   └── wordlists/
│       └── subdomains.txt      # 5 000-entry built-in subdomain list
└── tests/                      # pytest test suite
```

---

## Architecture

ReconX is built on:

- **`asyncio`** — fully async core for high-performance concurrent scanning
- **`aiohttp`** — async HTTP client for probing and passive recon sources
- **`dnspython`** — DNS resolution and zone transfer attempts
- **`rich`** — beautiful terminal output with progress bars, tables, and colour
- **`click`** — composable CLI with subcommands and shell completion

---

## Example Output

```
  → Target: example.com
  → Started: 2026-03-15 12:00:00 UTC

──────────────── 🔍  Port Scan ────────────────
Scanning example.com ━━━━━━━━━━━━━━━━━━━━ 100%  3 open

 Port    Service    Banner
 22      SSH        SSH-2.0-OpenSSH_8.9p1 Ubuntu
 80      HTTP
 443     HTTPS
 Scanned 86 ports · Found 3 open

──────────────── 📡  DNS Enumeration ────────────────
 Type    Value
 A       93.184.216.34
 MX      0 .
 NS      a.iana-servers.net.
 TXT     v=spf1 -all
```

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Requirements

- Python 3.10+
- See `pyproject.toml`

---

## Legal

This tool is for **authorised penetration testing and security research only**.
Always obtain written permission before scanning any system you do not own.
The authors accept no liability for misuse.
