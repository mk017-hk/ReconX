"""
Rich terminal display helpers for ReconX.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝"""


def print_banner(version: str) -> None:
    console.print(BANNER, style="bold cyan")
    console.print(
        f"  [bold]All-in-one Reconnaissance & Pentesting Toolkit[/bold]  "
        f"[dim]v{version}[/dim]\n"
        f"  [dim]For authorised security testing only.[/dim]\n",
        highlight=False,
    )


def print_section(title: str, icon: str = "") -> None:
    label = f"{icon}  {title}" if icon else title
    console.rule(f"[bold cyan]{label}[/bold cyan]")


def print_success(msg: str) -> None:
    console.print(f"  [bold green]✔[/bold green]  {msg}")


def print_warning(msg: str) -> None:
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def print_error(msg: str) -> None:
    console.print(f"  [bold red]✖[/bold red]  {msg}")


def print_info(msg: str) -> None:
    console.print(f"  [dim]→[/dim]  {msg}")


def print_finding(msg: str, level: str = "warn") -> None:
    colours = {"critical": "bold red", "warn": "yellow", "info": "cyan"}
    colour = colours.get(level, "yellow")
    console.print(f"  [{colour}]![/]  {msg}")


# ─────────────────────────────────────────────────────────────
# Module-specific display functions
# ─────────────────────────────────────────────────────────────

def display_scan_result(result) -> None:
    from reconx.core.scanner import ScanResult

    if result.error:
        print_error(f"Port scan failed: {result.error}")
        return

    table = Table(
        title=f"Open Ports — {result.host} ({result.ip})",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Port", style="bold green", width=8)
    table.add_column("Service", width=14)
    table.add_column("Version", width=28, style="cyan")
    table.add_column("Banner", style="dim")

    for p in result.open_ports:
        table.add_row(
            str(p.port),
            p.service,
            p.version[:28] if p.version else "",
            p.banner[:60] if p.banner else "",
        )

    if not result.open_ports:
        console.print("  [dim]No open ports found.[/dim]")
    else:
        console.print(table)
        console.print(
            f"  [dim]Scanned {result.total_scanned} ports · "
            f"Found [bold green]{len(result.open_ports)}[/bold green] open[/dim]"
        )


def display_dns_result(result) -> None:
    if result.error:
        print_error(f"DNS enumeration failed: {result.error}")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
    table.add_column("Type", style="bold blue", width=10)
    table.add_column("Value")

    for rtype, records in result.records.items():
        for r in records:
            table.add_row(rtype, r.value)

    if result.records:
        console.print(table)
    else:
        console.print("  [dim]No DNS records found.[/dim]")

    for zt in result.zone_transfers:
        if zt.success:
            console.print(
                f"\n  [bold red]⚠ ZONE TRANSFER SUCCESSFUL from {zt.nameserver}![/bold red]"
            )
            for rec in zt.records[:20]:
                console.print(f"    [dim]{rec}[/dim]")

    if result.security_findings:
        console.print("\n  [bold yellow]Security Findings:[/bold yellow]")
        for f in result.security_findings:
            print_finding(f)


def display_subdomain_result(result) -> None:
    if result.error:
        print_error(f"Subdomain enumeration failed: {result.error}")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
    table.add_column("Subdomain", style="bold")
    table.add_column("IP(s)", style="green")
    table.add_column("Source", style="dim")

    for s in result.subdomains:
        ips = ", ".join(s.ips) if s.ips else "[dim]—[/dim]"
        table.add_row(s.name, ips, s.source)

    if result.subdomains:
        console.print(table)
        console.print(
            f"  [dim]Checked {result.total_checked} words · "
            f"Found [bold green]{len(result.subdomains)}[/bold green] subdomains[/dim]"
        )
    else:
        console.print("  [dim]No subdomains found.[/dim]")


def display_http_results(results: list) -> None:
    if not results:
        console.print("  [dim]No HTTP responses.[/dim]")
        return

    for r in results:
        status_style = "green" if 200 <= r.status_code < 300 else "red" if r.status_code >= 400 else "yellow"
        console.print(
            f"\n  [bold cyan]{r.url}[/bold cyan]  "
            f"[{status_style}]{r.status_code}[/{status_style}]"
            + (f"  [dim]{r.title}[/dim]" if r.title else "")
        )

        if r.server:
            console.print(f"  [dim]Server:[/dim] {r.server}")

        if r.technologies:
            cats: dict[str, list[str]] = {}
            for t in r.technologies:
                cats.setdefault(t.category, []).append(t.name)
            for cat, names in cats.items():
                console.print(f"  [dim]{cat}:[/dim] [cyan]{', '.join(names)}[/cyan]")

        if r.missing_security_headers:
            console.print(f"  [yellow]Missing security headers ({len(r.missing_security_headers)}):[/yellow]")
            for m in r.missing_security_headers:
                print_finding(m, "warn")

        if r.interesting_paths:
            console.print(f"  [bold]Interesting paths:[/bold]")
            for ip in r.interesting_paths:
                status_c = "green" if ip.status_code == 200 else "yellow"
                note = f"  [bold red]{ip.note}[/bold red]" if ip.note else ""
                console.print(
                    f"    [{status_c}]{ip.status_code}[/{status_c}]  {ip.path}{note}"
                )


def display_ssl_result(result) -> None:
    if result.error:
        print_error(f"SSL analysis failed: {result.error}")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
    table.add_column("Field", style="bold", width=22)
    table.add_column("Value")

    if result.cert:
        c = result.cert
        expiry_style = "red" if c.is_expired else "yellow" if c.days_until_expiry < 30 else "green"
        table.add_row("Subject CN", c.subject.get("commonName", "—"))
        table.add_row("Issuer", c.issuer.get("organizationName", "—"))
        table.add_row("Valid Until", f"[{expiry_style}]{c.not_after} ({c.days_until_expiry}d)[/{expiry_style}]")
        table.add_row("Self-Signed", "[bold red]YES[/bold red]" if c.is_self_signed else "No")
        table.add_row("SANs", "\n".join(c.san[:10]) or "—")
        table.add_row("Cipher", f"{result.cipher} ({result.cipher_bits} bits)")

    console.print(table)

    if result.protocols:
        console.print("\n  [bold]Protocol Support:[/bold]")
        for p in result.protocols:
            if p.supported:
                style = "bold red" if p.deprecated else "green"
                console.print(f"    [{style}]✔[/{style}]  {p.name}" + (" [dim](DEPRECATED)[/dim]" if p.deprecated else ""))
            else:
                console.print(f"    [dim]✖  {p.name}[/dim]")

    if result.findings:
        console.print("\n  [bold yellow]Findings:[/bold yellow]")
        for f in result.findings:
            level = "critical" if "EXPIRED" in f or "CRITICAL" in f else "warn"
            print_finding(f, level)


def display_whois_result(result) -> None:
    if result.error:
        print_error(f"WHOIS failed: {result.error}")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
    table.add_column("Field", style="bold", width=22)
    table.add_column("Value")

    table.add_row("Registrar", result.registrar or "—")
    table.add_row("Created", result.creation_date or "—")
    table.add_row("Expires", result.expiration_date or "—")
    table.add_row("Updated", result.updated_date or "—")
    table.add_row("Country", result.registrant_country or "—")
    table.add_row("DNSSEC", result.dnssec or "—")
    table.add_row("Name Servers", "\n".join(result.name_servers) or "—")
    table.add_row("Emails", "\n".join(result.emails) or "—")

    console.print(table)


def display_udp_result(result) -> None:
    if result.error:
        print_error(f"UDP scan failed: {result.error}")
        return

    table = Table(
        title=f"UDP Ports — {result.host} ({result.ip})",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Port", style="bold yellow", width=8)
    table.add_column("State", width=14)
    table.add_column("Service", width=14)
    table.add_column("Banner", style="dim")

    for p in result.open_ports:
        state_style = "green" if p.state == "open" else "yellow"
        table.add_row(
            str(p.port),
            f"[{state_style}]{p.state}[/{state_style}]",
            p.service,
            p.banner[:60] if p.banner else "",
        )

    if not result.open_ports:
        console.print("  [dim]No UDP responses received.[/dim]")
    else:
        console.print(table)
        console.print(
            f"  [dim]Probed {result.total_scanned} UDP ports · "
            f"Found [bold yellow]{len(result.open_ports)}[/bold yellow] open/filtered[/dim]"
        )


def display_crawl_result(result) -> None:
    if result.error:
        print_error(f"Crawl failed: {result.error}")
        return

    endpoints = [e for e in result.endpoints if e.status_code in range(200, 500)]
    if endpoints:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
        table.add_column("URL", max_width=60)
        table.add_column("Status", width=8)
        table.add_column("Source", width=12, style="dim")
        table.add_column("Note", style="bold red")

        for ep in sorted(endpoints, key=lambda e: (e.status_code, e.url)):
            sc = ep.status_code
            sc_style = "green" if 200 <= sc < 300 else "yellow" if sc < 400 else "red"
            table.add_row(
                ep.url[:60],
                f"[{sc_style}]{sc}[/{sc_style}]",
                ep.source,
                ep.note or "",
            )
        console.print(table)

    if result.js_files:
        console.print(f"\n  [bold]JS files analysed:[/bold] {len(result.js_files)}")
        all_ep: set[str] = set()
        for js in result.js_files:
            all_ep.update(js.endpoints_found)
        if all_ep:
            console.print(f"  [dim]API routes found in JS:[/dim] [cyan]{len(all_ep)}[/cyan]")
            for ep in sorted(all_ep)[:20]:
                console.print(f"    [dim]{ep}[/dim]")

    if result.discovered_subdomains:
        console.print(f"\n  [bold]Subdomains in JS:[/bold]")
        for s in result.discovered_subdomains[:15]:
            console.print(f"    [cyan]{s}[/cyan]")

    console.print(
        f"\n  [dim]Pages crawled: {result.total_pages_crawled} · "
        f"Endpoints: {len(result.endpoints)} · "
        f"JS files: {len(result.js_files)}[/dim]"
    )


def display_ip_intel_result(result) -> None:
    if result.error:
        print_error(f"IP intel failed: {result.error}")
        return

    table = Table(box=box.SIMPLE_HEAD, header_style="bold cyan", border_style="dim")
    table.add_column("Field", style="bold", width=22)
    table.add_column("Value")

    table.add_row("IP", result.ip)
    if result.ptr_records:
        table.add_row("PTR", "\n".join(result.ptr_records))
    if result.asn:
        table.add_row("ASN", f"{result.asn.asn} {result.asn.asn_name}")
        table.add_row("Network", result.asn.cidr or "—")
        table.add_row("Org", result.asn.org or result.asn.asn_description or "—")
        if result.asn.cloud_provider:
            table.add_row("Cloud", f"[bold cyan]{result.asn.cloud_provider}[/bold cyan]")
    if result.geo:
        table.add_row("Location", f"{result.geo.city}, {result.geo.country} ({result.geo.country_code})")
        table.add_row("ISP", result.geo.isp or "—")

    console.print(table)

    if result.is_private:
        print_warning("Target resolves to a private/RFC1918 address")


def display_passive_result(result) -> None:
    if not result.hosts and not result.subdomains and not result.findings:
        console.print("  [dim]No passive source data found.[/dim]")
        return

    if result.findings:
        console.print("\n  [bold]Passive Intelligence:[/bold]")
        for f in result.findings:
            level = "critical" if "malicious" in f.lower() or "abuse" in f.lower() else "info"
            print_finding(f, level)

    if result.subdomains:
        console.print(f"\n  [dim]Subdomains from passive sources:[/dim] [cyan]{len(result.subdomains)}[/cyan]")
        for s in result.subdomains[:20]:
            console.print(f"    [dim]{s}[/dim]")

    if result.emails:
        console.print(f"\n  [dim]Emails discovered:[/dim] {', '.join(result.emails[:10])}")


def display_severity_summary(findings) -> None:
    from reconx.core.severity import Severity, SEVERITY_ORDER
    if not findings:
        return

    counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        counts[sev] = counts.get(sev, 0) + 1

    styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "MEDIUM": "bold yellow",
        "LOW": "dim green",
        "INFO": "dim",
    }

    console.print("\n  [bold]Findings by severity:[/bold]")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts.get(sev, 0)
        if count:
            style = styles.get(sev, "")
            console.print(f"    [{style}]{sev:10}[/{style}]  {count}")

    console.print()
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        style = styles.get(sev, "dim")
        mod = f"[dim][{f.module}][/dim] " if f.module else ""
        console.print(f"  [{style}]{sev:10}[/{style}]  {mod}{f.title}")
