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
    table.add_column("Banner", style="dim")

    for p in result.open_ports:
        table.add_row(
            str(p.port),
            p.service,
            p.banner[:80] if p.banner else "",
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
