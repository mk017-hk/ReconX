"""
ReconX CLI — main entry point.

Usage:
    python -m reconx [OPTIONS] TARGET

    reconx scan example.com --ports top100 --all
    reconx scan example.com --dns --http --ssl --whois
    reconx scan example.com --subdomains --report my_report
"""

import asyncio
import datetime
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
    display_dns_result,
    display_http_results,
    display_scan_result,
    display_ssl_result,
    display_subdomain_result,
    display_whois_result,
)

# Lazy imports of heavy modules
from reconx.core import scanner, dns_enum, subdomain, http_probe, ssl_analyzer, whois_lookup
from reconx.utils import report


# ─────────────────────────────────────────────────────────────
# CLI definition
# ─────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="ReconX")
def cli() -> None:
    """ReconX — All-in-one Reconnaissance & Pentesting Toolkit."""


@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="top100", show_default=True,
              help="Port spec: top100, top1000, all, 1-1024, 22,80,443")
@click.option("--concurrency", "-c", default=300, show_default=True,
              help="Max concurrent connections for port scan")
@click.option("--timeout", "-t", default=1.5, show_default=True,
              help="Per-port timeout (seconds)")
@click.option("--no-banners", is_flag=True, default=False,
              help="Skip banner grabbing (faster)")
@click.option("--dns/--no-dns", default=True, show_default=True,
              help="Run DNS enumeration")
@click.option("--subdomains/--no-subdomains", default=False, show_default=True,
              help="Run subdomain enumeration")
@click.option("--wordlist", "-w", default=None,
              help="Custom subdomain wordlist path")
@click.option("--no-passive", is_flag=True, default=False,
              help="Disable passive subdomain sources (crt.sh, HackerTarget)")
@click.option("--http/--no-http", default=True, show_default=True,
              help="Run HTTP probing & tech fingerprinting")
@click.option("--http-ports", default="80,443,8080,8443", show_default=True,
              help="Ports to probe for HTTP")
@click.option("--no-path-probe", is_flag=True, default=False,
              help="Skip interesting path discovery")
@click.option("--ssl/--no-ssl", "run_ssl", default=True, show_default=True,
              help="Run SSL/TLS analysis (port 443)")
@click.option("--ssl-port", default=443, show_default=True,
              help="Port to use for SSL analysis")
@click.option("--whois/--no-whois", "run_whois", default=True, show_default=True,
              help="Run WHOIS lookup")
@click.option("--all", "-a", "run_all", is_flag=True, default=False,
              help="Enable all modules (overrides individual flags)")
@click.option("--report", "-r", "report_name", default=None,
              help="Output report base name (no extension). Saves JSON + HTML.")
@click.option("--output-dir", "-o", default="reports", show_default=True,
              help="Directory to save reports")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and progress output")
def scan(
    target: str,
    ports: str,
    concurrency: int,
    timeout: float,
    no_banners: bool,
    dns: bool,
    subdomains: bool,
    wordlist: Optional[str],
    no_passive: bool,
    http: bool,
    http_ports: str,
    no_path_probe: bool,
    run_ssl: bool,
    ssl_port: int,
    run_whois: bool,
    run_all: bool,
    report_name: Optional[str],
    output_dir: str,
    quiet: bool,
) -> None:
    """
    Run a full or selective reconnaissance scan against TARGET.

    TARGET can be a domain name or IP address.

    Examples:\n
      reconx scan example.com\n
      reconx scan example.com --all --report example_recon\n
      reconx scan 192.168.1.1 --ports 1-1024 --no-ssl --no-whois\n
      reconx scan example.com --subdomains --wordlist /usr/share/wordlists/subdomains.txt
    """
    if run_all:
        dns = http = run_ssl = run_whois = subdomains = True

    if not quiet:
        print_banner(__version__)

    print_info(f"Target: [bold cyan]{target}[/bold cyan]")
    print_info(f"Started: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")

    collected: dict = {"target": target}

    asyncio.run(_run_scan(
        target=target,
        ports_spec=ports,
        concurrency=concurrency,
        timeout=timeout,
        grab_banners=not no_banners,
        run_dns=dns,
        run_subdomains=subdomains,
        wordlist=wordlist,
        use_passive=not no_passive,
        run_http=http,
        http_ports_spec=http_ports,
        probe_paths=not no_path_probe,
        run_ssl=run_ssl,
        ssl_port=ssl_port,
        run_whois=run_whois,
        report_name=report_name,
        output_dir=output_dir,
        collected=collected,
    ))


async def _run_scan(
    target: str,
    ports_spec: str,
    concurrency: int,
    timeout: float,
    grab_banners: bool,
    run_dns: bool,
    run_subdomains: bool,
    wordlist: Optional[str],
    use_passive: bool,
    run_http: bool,
    http_ports_spec: str,
    probe_paths: bool,
    run_ssl: bool,
    ssl_port: int,
    run_whois: bool,
    report_name: Optional[str],
    output_dir: str,
    collected: dict,
) -> None:
    # ── Port Scan ────────────────────────────────────────────
    print_section("Port Scan", "🔍")
    port_list = scanner.parse_port_range(ports_spec)
    print_info(f"Scanning {len(port_list)} ports with concurrency={concurrency}…")
    scan_result = await scanner.scan(
        target, ports=port_list, concurrency=concurrency,
        timeout=timeout, grab_banners=grab_banners,
    )
    display_scan_result(scan_result)
    collected["port_scan"] = scan_result

    # ── DNS ─────────────────────────────────────────────────
    if run_dns:
        print_section("DNS Enumeration", "📡")
        dns_result = await dns_enum.enumerate(target)
        display_dns_result(dns_result)
        collected["dns"] = dns_result

    # ── WHOIS ────────────────────────────────────────────────
    if run_whois:
        print_section("WHOIS", "📋")
        whois_result = await whois_lookup.lookup(target)
        display_whois_result(whois_result)
        collected["whois"] = whois_result

    # ── SSL ──────────────────────────────────────────────────
    if run_ssl:
        print_section(f"SSL/TLS Analysis (:{ssl_port})", "🔒")
        ssl_result = await ssl_analyzer.analyze(target, port=ssl_port)
        display_ssl_result(ssl_result)
        collected["ssl"] = ssl_result

    # ── HTTP ─────────────────────────────────────────────────
    if run_http:
        print_section("HTTP Probing & Technology Fingerprinting", "🕵️")
        http_port_list = [int(p.strip()) for p in http_ports_spec.split(",") if p.strip()]
        http_results = await http_probe.probe(
            target, ports=http_port_list, probe_paths=probe_paths
        )
        display_http_results(http_results)
        collected["http"] = http_results

    # ── Subdomains ───────────────────────────────────────────
    if run_subdomains:
        print_section("Subdomain Enumeration", "🌐")
        sub_result = await subdomain.enumerate(
            target, wordlist_path=wordlist, use_passive=use_passive
        )
        display_subdomain_result(sub_result)
        collected["subdomains"] = sub_result

    # ── Reports ──────────────────────────────────────────────
    if report_name:
        print_section("Generating Reports", "📄")
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"{output_dir}/{report_name}_{ts}"

        json_path = report.save_json(collected, f"{base}.json")
        print_success(f"JSON report: {json_path}")

        html_path = report.generate_html(collected, f"{base}.html")
        print_success(f"HTML report: {html_path}")

    console.print(
        f"\n  [bold green]Scan complete.[/bold green]  "
        f"[dim]{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/dim]\n"
    )


# ─────────────────────────────────────────────────────────────
# Additional utility commands
# ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--ports", "-p", default="top100", show_default=True)
@click.option("--concurrency", "-c", default=300, show_default=True)
@click.option("--timeout", "-t", default=1.5, show_default=True)
def portscan(target: str, ports: str, concurrency: int, timeout: float) -> None:
    """Quick port scan only."""
    print_banner(__version__)
    port_list = scanner.parse_port_range(ports)
    print_info(f"Scanning {len(port_list)} ports on {target}…")
    result = asyncio.run(
        scanner.scan(target, ports=port_list, concurrency=concurrency, timeout=timeout)
    )
    display_scan_result(result)


@cli.command()
@click.argument("domain")
@click.option("--passive/--no-passive", default=True, show_default=True)
@click.option("--wordlist", "-w", default=None)
def subdomenum(domain: str, passive: bool, wordlist: Optional[str]) -> None:
    """Subdomain enumeration only."""
    print_banner(__version__)
    print_section("Subdomain Enumeration", "🌐")
    result = asyncio.run(subdomain.enumerate(domain, wordlist_path=wordlist, use_passive=passive))
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
