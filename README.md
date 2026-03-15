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

> For authorised security testing only.

---

## Features

| Module | Capability |
|---|---|
| **Port Scanner** | Async TCP scanning, banner grabbing, service detection |
| **DNS Enumeration** | A/AAAA/MX/NS/TXT/SOA/CAA records, zone transfer attempts, SPF/DMARC checks |
| **Subdomain Enumeration** | DNS bruteforce + Certificate Transparency (crt.sh) + HackerTarget passive DNS |
| **HTTP Probing** | Tech fingerprinting (server/CMS/WAF/CDN/framework/JS libs), security header analysis, interesting path discovery |
| **SSL/TLS Analysis** | Certificate validity, expiry, SANs, deprecated protocol detection, weak cipher detection |
| **WHOIS** | Registrar, dates, name servers, registrant info |
| **Report Generator** | Self-contained HTML report + JSON export |

---

## Quick Start

### Install

```bash
pip install -r requirements.txt
# or install as a package:
pip install -e .
```

### Run a full scan

```bash
python main.py scan example.com --all --report example_recon
```

### Run specific modules

```bash
# Port scan only
python main.py scan example.com --no-dns --no-http --no-ssl --no-whois

# Full scan with subdomain enumeration + report
python main.py scan example.com --all --subdomains --report my_report

# Custom port range
python main.py scan example.com --ports 1-1024 --concurrency 500

# Quick port scan
python main.py portscan 192.168.1.1 --ports 22,80,443,3306,5432
```

### Standalone commands

```bash
python main.py dnsenum example.com
python main.py subdomenum example.com --wordlist /path/to/wordlist.txt
python main.py sslcheck example.com --port 443
python main.py whoislookup example.com
python main.py httpprobe example.com --ports 80,443,8080
```

---

## Usage Reference

```
Usage: python main.py scan [OPTIONS] TARGET

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
  --help                    Show this message and exit.
```

---

## Project Structure

```
reconx/
├── cli.py                  # Click CLI — all commands
├── core/
│   ├── scanner.py          # Async TCP port scanner
│   ├── dns_enum.py         # DNS record enumeration + zone transfer
│   ├── subdomain.py        # Subdomain brute-force + passive sources
│   ├── http_probe.py       # HTTP probing + tech fingerprinting
│   ├── ssl_analyzer.py     # SSL/TLS certificate analysis
│   └── whois_lookup.py     # WHOIS lookup
├── utils/
│   ├── display.py          # Rich terminal display
│   └── report.py           # JSON + HTML report generator
└── wordlists/
    └── subdomains.txt      # Built-in subdomain list
```

---

## Architecture

ReconX is built on:

- **`asyncio`** — fully async core for high-performance concurrent scanning
- **`aiohttp`** — async HTTP client for probing and passive recon sources
- **`dnspython`** — DNS resolution and zone transfer attempts
- **`rich`** — beautiful terminal output with tables, colours, and panels
- **`click`** — composable CLI with subcommands
- **Dataclasses** — typed result objects throughout

---

## Example Output

```
Recon X  v1.0.0
  All-in-one Reconnaissance & Pentesting Toolkit

  → Target: example.com
  → Started: 2024-01-15 14:30:00 UTC

──────────────── 🔍  Port Scan ────────────────
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
 NS      b.iana-servers.net.
 TXT     v=spf1 -all
 ...
```

---

## Requirements

- Python 3.10+
- See `requirements.txt`

---

## Legal

This tool is for **authorised penetration testing and security research only**.
Always obtain written permission before scanning any system you do not own.
The authors accept no liability for misuse.
