"""
ReconX CLI — main entry point.

Usage:
    reconx scan example.com --all
    reconx scan example.com --profile full --report my_report
    reconx scan placeholder --targets-file hosts.txt --resume --report batch
    reconx udpscan example.com
    reconx crawl example.com
    reconx ipintel example.com
"""

import asyncio
import datetime
from datetime import timezone
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from reconx import __version__
from reconx.utils.display import (
    console,
    print_banner,
    print_error,
    print_info,
    print_section,
    print_success,
    print_warning,
    display_dns_result,
    display_http_results,
    display_scan_result,
    display_ssl_result,
    display_subdomain_result,
    display_whois_result,
    display_udp_result,
    display_crawl_result,
    display_ip_intel_result,
    display_passive_result,
    display_severity_summary,
)

from reconx.core import scanner, dns_enum, subdomain, http_probe, ssl_analyzer, whois_lookup
from reconx.core import udp_scanner, web_crawler, ip_intel, passive_sources
from reconx.core.severity import aggregate_findings
from reconx.utils import report
from reconx.utils.state import ScanState, state_file_for
from reconx.utils.correlation import correlate
from reconx.plugins import registry as plugin_registry
from reconx import config as config_module


# ─────────────────────────────────────────────────────────────
# CLI group
# ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="ReconX")
def cli() -> None:
    """ReconX — All-in-one Reconnaissance & Pentesting Toolkit."""


# ─────────────────────────────────────────────────────────────
# scan command
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
# Core
@click.option("--profile", "-P", default=None,
              help="Config preset: quick | standard | web | external | full")
@click.option("--config", default=None,
              help="Path to YAML/TOML config file")
# Port scan
@click.option("--ports", "-p", default=None, show_default=True,
              help="Port spec: top100, top1000, all, 1-1024, 22,80,443")
@click.option("--concurrency", "-c", default=None, type=int,
              help="Max concurrent connections for port scan [default: 300]")
@click.option("--timeout", "-t", default=None, type=float,
              help="Per-port timeout (seconds) [default: 1.5]")
@click.option("--no-banners", is_flag=True, default=False,
              help="Skip banner grabbing (faster)")
# Rate limiting
@click.option("--delay", default=None, type=float,
              help="Fixed delay between probes (seconds) for safe/low-noise mode")
@click.option("--jitter", default=None, type=float,
              help="Max random jitter added to delay (seconds)")
@click.option("--rate-limit", default=None, type=int,
              help="Max requests per second (0 = unlimited)")
# UDP
@click.option("--udp/--no-udp", default=None,
              help="Run UDP scan on common ports")
@click.option("--udp-ports", default=None,
              help="UDP ports to scan [default: 53,67,69,123,161,500]")
# Modules
@click.option("--dns/--no-dns", default=None,
              help="Run DNS enumeration [default: on]")
@click.option("--subdomains/--no-subdomains", default=None,
              help="Run subdomain enumeration [default: off]")
@click.option("--wordlist", "-w", default=None,
              help="Custom subdomain wordlist path")
@click.option("--no-passive", is_flag=True, default=False,
              help="Disable passive subdomain sources (crt.sh, HackerTarget)")
@click.option("--http/--no-http", default=None,
              help="Run HTTP probing & tech fingerprinting [default: on]")
@click.option("--http-ports", default=None,
              help="Ports to probe for HTTP [default: 80,443,8080,8443]")
@click.option("--no-path-probe", is_flag=True, default=False,
              help="Skip interesting path discovery")
@click.option("--ssl/--no-ssl", "run_ssl", default=None,
              help="Run SSL/TLS analysis [default: on]")
@click.option("--ssl-port", default=443, show_default=True,
              help="Port to use for SSL analysis")
@click.option("--whois/--no-whois", "run_whois", default=None,
              help="Run WHOIS lookup [default: on]")
@click.option("--ip-intel/--no-ip-intel", "run_ip_intel", default=None,
              help="Run ASN/IP intelligence lookup [default: off]")
@click.option("--crawl/--no-crawl", "run_crawl", default=None,
              help="Run web crawl and endpoint discovery [default: off]")
@click.option("--crawl-depth", default=None, type=int,
              help="Max crawl depth [default: 2]")
@click.option("--crawl-pages", default=None, type=int,
              help="Max pages to crawl [default: 50]")
@click.option("--passive/--no-passive-sources", "run_passive", default=None,
              help="Run passive source integrations (Shodan, Censys, etc.) [default: off]")
@click.option("--all", "-a", "run_all", is_flag=True, default=False,
              help="Enable all modules (overrides individual flags)")
# Reporting
@click.option("--report", "-r", "report_name", default=None,
              help="Output report base name (no extension). Saves JSON + HTML.")
@click.option("--output-dir", "-o", default=None,
              help="Directory to save reports [default: reports]")
@click.option("--insecure", is_flag=True, default=False,
              help="Disable TLS certificate verification for target scanning (self-signed certs)")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and progress output")
# Batch
@click.option("--targets-file", "-T", default=None,
              help="File with newline-separated targets for batch scanning")
@click.option("--resume", is_flag=True, default=False,
              help="Resume a previous batch scan (requires --report for state file)")
def scan(
    target: str,
    profile: Optional[str],
    config: Optional[str],
    ports: Optional[str],
    concurrency: Optional[int],
    timeout: Optional[float],
    no_banners: bool,
    delay: Optional[float],
    jitter: Optional[float],
    rate_limit: Optional[int],
    udp: Optional[bool],
    udp_ports: Optional[str],
    dns: Optional[bool],
    subdomains: Optional[bool],
    wordlist: Optional[str],
    no_passive: bool,
    http: Optional[bool],
    http_ports: Optional[str],
    no_path_probe: bool,
    run_ssl: Optional[bool],
    ssl_port: int,
    run_whois: Optional[bool],
    run_ip_intel: Optional[bool],
    run_crawl: Optional[bool],
    crawl_depth: Optional[int],
    crawl_pages: Optional[int],
    run_passive: Optional[bool],
    run_all: bool,
    insecure: bool,
    report_name: Optional[str],
    output_dir: Optional[str],
    quiet: bool,
    targets_file: Optional[str],
    resume: bool,
) -> None:
    """
    Run a full or selective reconnaissance scan against TARGET.

    TARGET is a domain name or IP address.
    When --targets-file is set, TARGET is ignored and each line of the file is scanned.

    Examples:\n
      reconx scan example.com\n
      reconx scan example.com --profile full --report out\n
      reconx scan example.com --all --udp --ip-intel --crawl\n
      reconx scan placeholder --targets-file hosts.txt --resume --report batch\n
      reconx scan example.com --delay 0.5 --jitter 0.2  # low-noise mode
    """
    # ── Load config/profile ─────────────────────────────────
    prof = config_module.load(config_path=config, preset=profile)

    # CLI flags override profile values
    if run_all:
        prof.dns = prof.http = prof.ssl = prof.whois = prof.subdomains = True
        prof.udp = prof.ip_intel = prof.crawl = prof.passive_sources = True

    if insecure:
        prof.verify_ssl = False

    if ports is not None:         prof.ports = ports
    if concurrency is not None:   prof.concurrency = concurrency
    if timeout is not None:       prof.timeout = timeout
    if delay is not None:         prof.delay = delay
    if jitter is not None:        prof.jitter = jitter
    if rate_limit is not None:    prof.rate_limit = rate_limit
    if udp is not None:           prof.udp = udp
    if udp_ports is not None:     prof.udp_ports = udp_ports
    if dns is not None:           prof.dns = dns
    if subdomains is not None:    prof.subdomains = subdomains
    if wordlist is not None:      prof.wordlist = wordlist
    if no_passive:                prof.passive_subdomain = False
    if http is not None:          prof.http = http
    if http_ports is not None:    prof.http_ports = http_ports
    if no_path_probe:             prof.path_probe = False
    if run_ssl is not None:       prof.ssl = run_ssl
    if run_whois is not None:     prof.whois = run_whois
    if run_ip_intel is not None:  prof.ip_intel = run_ip_intel
    if run_crawl is not None:     prof.crawl = run_crawl
    if crawl_depth is not None:   prof.crawl_depth = crawl_depth
    if crawl_pages is not None:   prof.crawl_max_pages = crawl_pages
    if run_passive is not None:   prof.passive_sources = run_passive
    if output_dir is not None:    prof.output_dir = output_dir

    # ── Build target list ───────────────────────────────────
    targets: list[str] = []
    if targets_file:
        tf = Path(targets_file)
        if not tf.exists():
            print_error(f"Targets file not found: {targets_file}")
            sys.exit(1)
        targets = [
            line.strip()
            for line in tf.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not targets:
            print_error("Targets file is empty.")
            sys.exit(1)
    else:
        targets = [target]

    # ── Resume state ────────────────────────────────────────
    state: Optional[ScanState] = None
    if resume and report_name:
        sf = state_file_for(report_name, prof.output_dir)
        state = ScanState.load(sf)
        state.targets = targets
        remaining = state.remaining_targets(targets)
        if len(remaining) < len(targets):
            skipped = len(targets) - len(remaining)
            print_info(f"Resuming: skipping {skipped} already-completed targets")
        targets = remaining
        if not targets:
            print_success("All targets already completed.")
            return

    if not quiet:
        print_banner(__version__)

    if len(targets) > 1:
        print_info(f"Batch mode: [bold cyan]{len(targets)} targets[/bold cyan]")
    if prof.delay or prof.jitter:
        print_info(f"[dim]Safe mode: delay={prof.delay}s jitter=0-{prof.jitter}s[/dim]")

    for i, tgt in enumerate(targets, 1):
        if len(targets) > 1:
            console.rule(f"[bold magenta]Target {i}/{len(targets)}: {tgt}[/bold magenta]")
        print_info(f"Target: [bold cyan]{tgt}[/bold cyan]")
        print_info(f"Started: {datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

        collected: dict = {"target": tgt}
        tgt_report = f"{report_name}_{tgt.replace('.', '_').replace(':', '_')}" \
            if (report_name and len(targets) > 1) else report_name

        asyncio.run(_run_scan(
            target=tgt,
            prof=prof,
            grab_banners=not no_banners,
            ssl_port=ssl_port,
            report_name=tgt_report,
            collected=collected,
            verify_ssl=prof.verify_ssl,
        ))

        if state and report_name:
            state.save_result(tgt, collected)
            state.flush()


# ─────────────────────────────────────────────────────────────
# Core scan runner
# ─────────────────────────────────────────────────────────────

async def _run_scan(
    target: str,
    prof: "config_module.ScanProfile",
    grab_banners: bool,
    ssl_port: int,
    report_name: Optional[str],
    collected: dict,
    verify_ssl: bool = True,
) -> None:
    # ── Port Scan ────────────────────────────────────────────
    print_section("Port Scan", "🔍")
    port_list = scanner.parse_port_range(prof.ports)
    print_info(f"Scanning {len(port_list)} TCP ports (concurrency={prof.concurrency})")
    scan_result = await scanner.scan(
        target, ports=port_list, concurrency=prof.concurrency,
        timeout=prof.timeout, grab_banners=grab_banners,
        delay=prof.delay, jitter=prof.jitter,
    )
    display_scan_result(scan_result)
    collected["port_scan"] = scan_result

    # ── UDP Scan ─────────────────────────────────────────────
    if prof.udp:
        print_section("UDP Scan", "📡")
        udp_port_list = [int(p.strip()) for p in prof.udp_ports.split(",") if p.strip()]
        print_info(f"Probing {len(udp_port_list)} UDP ports")
        udp_result = await udp_scanner.scan(target, ports=udp_port_list, timeout=max(prof.timeout, 2.0))
        display_udp_result(udp_result)
        collected["udp"] = udp_result

    # ── DNS ─────────────────────────────────────────────────
    if prof.dns:
        print_section("DNS Enumeration", "📡")
        dns_result = await dns_enum.enumerate(target)
        display_dns_result(dns_result)
        collected["dns"] = dns_result

    # ── WHOIS ────────────────────────────────────────────────
    if prof.whois:
        print_section("WHOIS", "📋")
        whois_result = await whois_lookup.lookup(target)
        display_whois_result(whois_result)
        collected["whois"] = whois_result

    # ── SSL ──────────────────────────────────────────────────
    if prof.ssl:
        print_section(f"SSL/TLS Analysis (:{ssl_port})", "🔒")
        ssl_result = await ssl_analyzer.analyze(target, port=ssl_port)
        display_ssl_result(ssl_result)
        collected["ssl"] = ssl_result

    # ── HTTP ─────────────────────────────────────────────────
    if prof.http:
        print_section("HTTP Probing & Technology Fingerprinting", "🕵️")
        http_port_list = [int(p.strip()) for p in prof.http_ports.split(",") if p.strip()]
        http_results = await http_probe.probe(
            target, ports=http_port_list, probe_paths=prof.path_probe,
            verify_ssl=verify_ssl,
        )
        display_http_results(http_results)
        collected["http"] = http_results

    # ── Subdomains ───────────────────────────────────────────
    if prof.subdomains:
        print_section("Subdomain Enumeration", "🌐")
        sub_result = await subdomain.enumerate(
            target, wordlist_path=prof.wordlist, use_passive=prof.passive_subdomain
        )
        display_subdomain_result(sub_result)
        collected["subdomains"] = sub_result

    # ── Web Crawl ────────────────────────────────────────────
    if prof.crawl:
        print_section("Web Crawl & Endpoint Discovery", "🕸️")
        crawl_result = await web_crawler.crawl(
            target,
            max_depth=prof.crawl_depth,
            max_pages=prof.crawl_max_pages,
            verify_ssl=verify_ssl,
        )
        display_crawl_result(crawl_result)
        collected["crawl"] = crawl_result

    # ── IP Intelligence ──────────────────────────────────────
    if prof.ip_intel:
        print_section("IP & ASN Intelligence", "🌍")
        ip_result = await ip_intel.lookup(target)
        display_ip_intel_result(ip_result)
        collected["ip_intel"] = ip_result

    # ── Passive Sources ──────────────────────────────────────
    if prof.passive_sources:
        print_section("Passive Intelligence", "🔭")
        ip_addr = ""
        if "ip_intel" in collected:
            ir = collected["ip_intel"]
            ip_addr = getattr(ir, "ip", ir.get("ip", "") if isinstance(ir, dict) else "")
        passive_result = await passive_sources.gather(
            target, ip=ip_addr,
            shodan_key=prof.shodan_key,
            censys_id=prof.censys_id,
            censys_secret=prof.censys_secret,
            securitytrails_key=prof.securitytrails_key,
            virustotal_key=prof.virustotal_key,
            abuseipdb_key=prof.abuseipdb_key,
        )
        display_passive_result(passive_result)
        collected["passive"] = passive_result

    # ── Severity Summary ─────────────────────────────────────
    print_section("Findings Summary", "⚠️")
    findings = aggregate_findings(collected)
    display_severity_summary(findings)
    collected["_findings"] = findings

    # ── Asset Correlation ─────────────────────────────────────
    try:
        corr_result = correlate(collected)
        collected["correlation"] = corr_result
        if corr_result.correlated_findings:
            print_info(
                f"[dim]Correlation: {len(corr_result.correlated_findings)} correlated finding(s), "
                f"{len(corr_result.host_roles)} host(s) classified[/dim]"
            )
    except Exception as _corr_exc:  # noqa: BLE001
        import logging as _logging
        _logging.getLogger(__name__).warning("Correlation failed: %s", _corr_exc)

    # ── Plugin Runner ─────────────────────────────────────────
    if plugin_registry.all:
        print_section(f"Plugins ({len(plugin_registry.all)})", "🧩")
        plugin_results = await plugin_registry.run_all(target, prof, collected, timeout=60.0)
        for pr in plugin_results:
            if pr.findings:
                print_info(f"  [{pr.plugin_name}] {len(pr.findings)} finding(s)")
                collected["_findings"] = list(collected.get("_findings", [])) + pr.findings
        collected["plugin_results"] = plugin_results

    # ── Reports ──────────────────────────────────────────────
    if report_name:
        print_section("Generating Reports", "📄")
        ts = datetime.datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = f"{prof.output_dir}/{report_name}_{ts}"

        if "json" in prof.report_formats:
            json_path = report.save_json(collected, f"{base}.json")
            print_success(f"JSON report: {json_path}")

        if "html" in prof.report_formats:
            html_path = report.generate_html(collected, f"{base}.html")
            print_success(f"HTML report: {html_path}")

    console.print(
        f"\n  [bold green]Scan complete.[/bold green]  "
        f"[dim]{datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]\n"
    )


# ─────────────────────────────────────────────────────────────
# Standalone commands
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="top100", show_default=True)
@click.option("--concurrency", "-c", default=300, show_default=True)
@click.option("--timeout", "-t", default=1.5, show_default=True)
@click.option("--delay", default=0.0)
@click.option("--jitter", default=0.0)
def portscan(target: str, ports: str, concurrency: int, timeout: float,
             delay: float, jitter: float) -> None:
    """Quick TCP port scan only."""
    print_banner(__version__)
    port_list = scanner.parse_port_range(ports)
    print_info(f"Scanning {len(port_list)} ports on {target}…")
    result = asyncio.run(
        scanner.scan(target, ports=port_list, concurrency=concurrency,
                     timeout=timeout, delay=delay, jitter=jitter)
    )
    display_scan_result(result)


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="53,67,69,123,161,500", show_default=True)
@click.option("--timeout", "-t", default=2.0, show_default=True)
def udpscan(target: str, ports: str, timeout: float) -> None:
    """UDP port scan with protocol-specific probes."""
    print_banner(__version__)
    print_section("UDP Scan", "📡")
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    result = asyncio.run(udp_scanner.scan(target, ports=port_list, timeout=timeout))
    display_udp_result(result)


@cli.command("subdomains")
@click.argument("target")
@click.option("--passive/--no-passive", default=True, show_default=True)
@click.option("--wordlist", "-w", default=None)
def subdomains_cmd(target: str, passive: bool, wordlist: Optional[str]) -> None:
    """Subdomain enumeration only."""
    print_banner(__version__)
    print_section("Subdomain Enumeration", "🌐")
    result = asyncio.run(subdomain.enumerate(target, wordlist_path=wordlist, use_passive=passive))
    display_subdomain_result(result)


# Backward-compat alias — deprecated name kept for existing scripts
@cli.command("subdomenum", hidden=True, deprecated=True)
@click.argument("target")
@click.option("--passive/--no-passive", default=True, show_default=True)
@click.option("--wordlist", "-w", default=None)
def subdomenum(target: str, passive: bool, wordlist: Optional[str]) -> None:
    """Subdomain enumeration (deprecated alias — use 'subdomains' instead)."""
    result = asyncio.run(subdomain.enumerate(target, wordlist_path=wordlist, use_passive=passive))
    display_subdomain_result(result)


@cli.command()
@click.argument("domain")
def dnsenum(domain: str) -> None:
    """DNS enumeration only."""
    print_banner(__version__)
    print_section("DNS Enumeration", "📡")
    result = asyncio.run(dns_enum.enumerate(domain))
    display_dns_result(result)


@cli.command()
@click.argument("target")
@click.option("--port", "-p", default=443, show_default=True)
def sslcheck(target: str, port: int) -> None:
    """SSL/TLS certificate analysis only."""
    print_banner(__version__)
    print_section(f"SSL/TLS Analysis (:{port})", "🔒")
    result = asyncio.run(ssl_analyzer.analyze(target, port=port))
    display_ssl_result(result)


@cli.command()
@click.argument("domain")
def whoislookup(domain: str) -> None:
    """WHOIS lookup only."""
    print_banner(__version__)
    print_section("WHOIS", "📋")
    result = asyncio.run(whois_lookup.lookup(domain))
    display_whois_result(result)


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="80,443,8080,8443", show_default=True)
@click.option("--no-path-probe", is_flag=True, default=False)
def httpprobe(target: str, ports: str, no_path_probe: bool) -> None:
    """HTTP probing & technology fingerprinting only."""
    print_banner(__version__)
    print_section("HTTP Probing", "🕵️")
    port_list = [int(p.strip()) for p in ports.split(",") if p.strip()]
    results = asyncio.run(http_probe.probe(target, ports=port_list, probe_paths=not no_path_probe))
    display_http_results(results)


@cli.command()
@click.argument("target")
@click.option("--depth", default=2, show_default=True, help="Max crawl depth")
@click.option("--max-pages", default=50, show_default=True, help="Max pages to visit")
@click.option("--port", default=443, show_default=True, help="Starting port (443=https)")
def crawl(target: str, depth: int, max_pages: int, port: int) -> None:
    """Web crawl and endpoint/JS route discovery."""
    print_banner(__version__)
    print_section("Web Crawl & Endpoint Discovery", "🕸️")
    result = asyncio.run(web_crawler.crawl(target, max_depth=depth, max_pages=max_pages, port=port))
    display_crawl_result(result)


@cli.command()
@click.argument("target")
def ipintel(target: str) -> None:
    """ASN, CIDR, cloud provider, and geolocation lookup."""
    print_banner(__version__)
    print_section("IP & ASN Intelligence", "🌍")
    result = asyncio.run(ip_intel.lookup(target))
    display_ip_intel_result(result)


@cli.command("init-config")
@click.option("--output", "-o", default="reconx.yml", show_default=True,
              help="Output path for the example config file")
def init_config(output: str) -> None:
    """Write an example reconx.yml config file to disk."""
    config_module.write_example(output)
    print_success(f"Example config written to: {output}")
    print_info("Edit it and pass via:  reconx scan example.com --config reconx.yml")


@cli.command("install-completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]), default="bash")
def install_completion(shell: str) -> None:
    """Install shell tab-completion for reconx.

    \b
    Usage:
      reconx install-completion bash   # writes to ~/.bash_completion.d/
      reconx install-completion zsh    # writes to ~/.zsh/completions/
      reconx install-completion fish   # writes to ~/.config/fish/completions/
    """
    import subprocess, os

    try:
        result = subprocess.run(
            ["reconx"],
            env={**os.environ, "_RECONX_COMPLETE": f"{shell}_source"},
            capture_output=True, text=True,
        )
        script = result.stdout
    except FileNotFoundError:
        print_error("reconx not found on PATH. Run: pip install -e .")
        return

    if shell == "bash":
        dest = Path.home() / ".bash_completion.d" / "reconx"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(script)
        print_success(f"Bash completion installed: {dest}")
        print_info("Add to ~/.bashrc:  source ~/.bash_completion.d/reconx")
    elif shell == "zsh":
        dest = Path.home() / ".zsh" / "completions" / "_reconx"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(script)
        print_success(f"Zsh completion installed: {dest}")
    elif shell == "fish":
        dest = Path.home() / ".config" / "fish" / "completions" / "reconx.fish"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(script)
        print_success(f"Fish completion installed: {dest}")
