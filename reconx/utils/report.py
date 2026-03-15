"""
Report generation — JSON and self-contained HTML reports.
"""

import json
import datetime
from dataclasses import asdict
from pathlib import Path
from typing import Any

from reconx import __version__


def _serialise(obj: Any) -> Any:
    """Recursively make objects JSON-serialisable."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialise(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    return obj


def save_json(data: dict, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "reconx_version": __version__,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        **{k: _serialise(v) for k, v in data.items()},
    }
    path.write_text(json.dumps(payload, indent=2, default=str))
    return str(path)


# ─────────────────────────────────────────────────────────────
# HTML report template
# ─────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReconX Report — {target}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --accent: #58a6ff;
      --green: #3fb950;
      --red: #f85149;
      --yellow: #d29922;
      --orange: #db6d28;
      --text: #c9d1d9;
      --muted: #8b949e;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
    a {{ color: var(--accent); text-decoration: none; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    /* Header */
    .header {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between; }}
    .logo {{ font-size: 28px; font-weight: 700; color: var(--accent); letter-spacing: 2px; }}
    .logo span {{ color: var(--red); }}
    .meta {{ text-align: right; color: var(--muted); font-size: 12px; }}
    .target-badge {{ background: #21262d; border: 1px solid var(--border); border-radius: 20px; padding: 6px 16px; font-family: monospace; color: var(--accent); margin-top: 8px; display: inline-block; }}
    /* Summary cards */
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
    .card-number {{ font-size: 36px; font-weight: 700; color: var(--accent); }}
    .card-label {{ color: var(--muted); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}
    /* Section */
    .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
    .section-header {{ padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; background: #1c2128; }}
    .section-title {{ font-size: 15px; font-weight: 600; }}
    .section-body {{ padding: 16px 20px; }}
    /* Table */
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; border-bottom: 1px solid var(--border); }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; font-family: monospace; font-size: 13px; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1c2128; }}
    /* Badges */
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
    .badge-green {{ background: #1b4332; color: var(--green); }}
    .badge-red {{ background: #3d1c1c; color: var(--red); }}
    .badge-yellow {{ background: #332d00; color: var(--yellow); }}
    .badge-blue {{ background: #1c2d3d; color: var(--accent); }}
    .badge-orange {{ background: #3d2000; color: var(--orange); }}
    /* Finding */
    .finding {{ background: #3d1c1c; border-left: 3px solid var(--red); padding: 8px 12px; margin-bottom: 6px; border-radius: 0 4px 4px 0; font-size: 13px; }}
    .finding-warn {{ background: #332d00; border-left-color: var(--yellow); }}
    .finding-info {{ background: #1c2d3d; border-left-color: var(--accent); }}
    /* Port state */
    .port-open {{ color: var(--green); font-weight: 600; }}
    /* Tech tag */
    .tech-tag {{ display: inline-block; background: #21262d; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; margin: 2px; font-size: 12px; color: var(--accent); }}
    /* Footer */
    .footer {{ text-align: center; color: var(--muted); font-size: 12px; margin-top: 32px; padding: 16px; }}
    /* Responsive nav */
    .nav {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 24px; }}
    .nav a {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 14px; font-size: 13px; color: var(--text); transition: border-color .2s; }}
    .nav a:hover {{ border-color: var(--accent); color: var(--accent); }}
    pre {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; color: var(--muted); }}
    .empty {{ color: var(--muted); font-style: italic; padding: 8px 0; }}
  </style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div>
      <div class="logo">Recon<span>X</span></div>
      <div style="color:var(--muted);font-size:12px;margin-top:4px;">All-in-one Reconnaissance &amp; Pentesting Toolkit</div>
      <div class="target-badge">{target}</div>
    </div>
    <div class="meta">
      <div>Generated: {generated_at}</div>
      <div>Version: {version}</div>
    </div>
  </div>

  <!-- Nav -->
  <div class="nav">
    {nav_links}
  </div>

  <!-- Summary cards -->
  <div class="cards">
    {summary_cards}
  </div>

  <!-- Content sections -->
  {sections}

  <div class="footer">ReconX v{version} — For authorised security testing only</div>
</div>
</body>
</html>"""


def _badge(text: str, colour: str = "blue") -> str:
    return f'<span class="badge badge-{colour}">{text}</span>'


def _section(title: str, icon: str, content: str, anchor: str = "") -> str:
    anchor_attr = f'id="{anchor}"' if anchor else ""
    return f"""
<div class="section" {anchor_attr}>
  <div class="section-header">
    <span>{icon}</span>
    <span class="section-title">{title}</span>
  </div>
  <div class="section-body">{content}</div>
</div>"""


def _findings_html(findings: list[str]) -> str:
    if not findings:
        return '<div class="empty">No findings.</div>'
    html = ""
    for f in findings:
        cls = "finding"
        if "CRITICAL" in f or "EXPIRED" in f or "EXPOSED" in f or "SUCCESSFUL" in f:
            cls = "finding"
        elif "missing" in f.lower() or "weak" in f.lower() or "deprecated" in f.lower():
            cls = "finding finding-warn"
        else:
            cls = "finding finding-info"
        html += f'<div class="{cls}">{f}</div>'
    return html


def generate_html(data: dict, output_path: str) -> str:
    """Generate a self-contained HTML report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    target = data.get("target", "Unknown")
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    sections_html = ""
    nav_links = ""
    cards = []

    all_findings: list[str] = []

    # ── Port Scan ──────────────────────────────────
    scan = data.get("port_scan")
    if scan:
        open_ports = scan.get("open_ports", [])
        cards.append(("open_ports", str(len(open_ports)), "Open Ports"))

        rows = ""
        for p in open_ports:
            banner = p.get("banner", "")[:80]
            rows += f"""<tr>
              <td class="port-open">{p['port']}</td>
              <td>TCP</td>
              <td>{_badge(p.get('service','?'), 'blue')}</td>
              <td>{banner or '<span class="empty">—</span>'}</td>
            </tr>"""

        table = f"""<table>
          <tr><th>Port</th><th>Proto</th><th>Service</th><th>Banner</th></tr>
          {rows if rows else '<tr><td colspan="4" class="empty">No open ports found</td></tr>'}
        </table>"""

        sections_html += _section("Port Scan", "🔍", table, "ports")
        nav_links += '<a href="#ports">Ports</a>'

    # ── DNS ────────────────────────────────────────
    dns = data.get("dns")
    if dns:
        records = dns.get("records", {})
        total_records = sum(len(v) for v in records.values())
        cards.append(("dns_records", str(total_records), "DNS Records"))

        rows = ""
        for rtype, recs in records.items():
            for r in recs:
                rows += f"<tr><td>{_badge(rtype, 'blue')}</td><td>{r['value']}</td></tr>"

        dns_findings = dns.get("security_findings", [])
        all_findings.extend(dns_findings)

        zone_transfers = dns.get("zone_transfers", [])
        zt_html = ""
        for zt in zone_transfers:
            if zt.get("success"):
                zt_html += f'<div class="finding">Zone transfer SUCCESSFUL from {zt["nameserver"]}!</div>'

        table = f"""<table>
          <tr><th>Type</th><th>Value</th></tr>
          {rows if rows else '<tr><td colspan="2" class="empty">No records found</td></tr>'}
        </table>"""

        content = table
        if dns_findings:
            content += "<br><b>Security Findings:</b><br>" + _findings_html(dns_findings)
        if zt_html:
            content += zt_html

        sections_html += _section("DNS Enumeration", "📡", content, "dns")
        nav_links += '<a href="#dns">DNS</a>'

    # ── Subdomains ─────────────────────────────────
    subs = data.get("subdomains")
    if subs:
        subdomain_list = subs.get("subdomains", [])
        cards.append(("subdomains", str(len(subdomain_list)), "Subdomains"))

        rows = ""
        for s in subdomain_list:
            ips = ", ".join(s.get("ips", [])) or "Unresolved"
            source_colour = {"crtsh": "green", "hackertarget": "orange", "bruteforce": "blue"}.get(
                s.get("source", "bruteforce"), "blue"
            )
            rows += f"""<tr>
              <td style="font-family:monospace">{s['name']}</td>
              <td>{ips}</td>
              <td>{_badge(s.get('source','?'), source_colour)}</td>
            </tr>"""

        table = f"""<table>
          <tr><th>Subdomain</th><th>IP(s)</th><th>Source</th></tr>
          {rows if rows else '<tr><td colspan="3" class="empty">No subdomains found</td></tr>'}
        </table>"""

        sections_html += _section("Subdomain Enumeration", "🌐", table, "subs")
        nav_links += '<a href="#subs">Subdomains</a>'

    # ── HTTP ───────────────────────────────────────
    http_results = data.get("http", [])
    if http_results:
        tech_set: set[str] = set()
        for r in http_results:
            for t in r.get("technologies", []):
                tech_set.add(t.get("name", ""))

        cards.append(("techs", str(len(tech_set)), "Technologies"))

        content = ""
        for r in http_results:
            url = r.get("url", "")
            status = r.get("status_code", 0)
            status_colour = "green" if 200 <= status < 300 else "red" if status >= 400 else "yellow"
            title = r.get("title", "")
            server = r.get("server", "")
            techs = r.get("technologies", [])
            missing = r.get("missing_security_headers", [])
            paths = r.get("interesting_paths", [])

            tech_tags = "".join(f'<span class="tech-tag">{t["name"]}</span>' for t in techs)
            missing_html = _findings_html(missing)

            path_rows = ""
            for ip in paths:
                note_html = f' <span style="color:var(--red)">{ip["note"]}</span>' if ip.get("note") else ""
                status_c = "green" if ip["status_code"] == 200 else "yellow"
                path_rows += f"<tr><td>{ip['path']}</td><td>{_badge(str(ip['status_code']), status_c)}</td><td>{note_html}</td></tr>"

            endpoint_html = f"""
<div style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid var(--border)">
  <div style="margin-bottom:8px">
    <b><a href="{url}" target="_blank">{url}</a></b>
    {_badge(str(status), status_colour)}
    {f'<span style="color:var(--muted);margin-left:8px">{title}</span>' if title else ''}
  </div>
  {f'<div style="margin-bottom:6px"><span class="badge badge-blue">Server</span> {server}</div>' if server else ''}
  <div style="margin-bottom:8px">{tech_tags if tech_tags else '<span class="empty">No technologies detected</span>'}</div>
  {'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px">Missing Security Headers (' + str(len(missing)) + ')</summary>' + missing_html + '</details>' if missing else ''}
  {'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px">Interesting Paths (' + str(len(paths)) + ')</summary><table><tr><th>Path</th><th>Status</th><th>Note</th></tr>' + path_rows + '</table></details>' if paths else ''}
</div>"""
            content += endpoint_html

        all_missing = [m for r in http_results for m in r.get("missing_security_headers", [])]
        all_findings.extend(all_missing)

        sections_html += _section("HTTP Probing & Technology Fingerprinting", "🕵️", content, "http")
        nav_links += '<a href="#http">HTTP</a>'

    # ── SSL ───────────────────────────────────────
    ssl_result = data.get("ssl")
    if ssl_result and not ssl_result.get("error"):
        cert = ssl_result.get("cert", {})
        ssl_findings = ssl_result.get("findings", [])
        all_findings.extend(ssl_findings)

        days = cert.get("days_until_expiry", 0) if cert else 0
        expiry_colour = "red" if days < 0 else "yellow" if days < 30 else "green"

        subject = cert.get("subject", {}) if cert else {}
        issuer = cert.get("issuer", {}) if cert else {}
        san = cert.get("san", []) if cert else []

        cert_html = ""
        if cert:
            cert_html = f"""<table>
              <tr><th>Field</th><th>Value</th></tr>
              <tr><td>Subject CN</td><td>{subject.get('commonName', '—')}</td></tr>
              <tr><td>Issuer</td><td>{issuer.get('organizationName', '—')}</td></tr>
              <tr><td>Valid From</td><td>{cert.get('not_before','—')}</td></tr>
              <tr><td>Valid Until</td><td>{cert.get('not_after','—')} {_badge(str(days) + ' days', expiry_colour)}</td></tr>
              <tr><td>Self-Signed</td><td>{_badge('YES', 'red') if cert.get('is_self_signed') else _badge('No', 'green')}</td></tr>
              <tr><td>SANs</td><td>{'<br>'.join(san) if san else '—'}</td></tr>
              <tr><td>Cipher Suite</td><td>{ssl_result.get('cipher','—')} ({ssl_result.get('cipher_bits',0)} bits)</td></tr>
            </table>"""

        protos = ssl_result.get("protocols", [])
        proto_html = ""
        if protos:
            proto_rows = "".join(
                f"<tr><td>{p['name']}</td><td>"
                f"{_badge('Supported', 'red' if p.get('deprecated') else 'green') if p['supported'] else _badge('Not Supported', 'muted')}"
                f"</td></tr>"
                for p in protos
            )
            proto_html = f"<br><b>Protocol Support:</b><table><tr><th>Protocol</th><th>Status</th></tr>{proto_rows}</table>"

        content = cert_html + proto_html
        if ssl_findings:
            content += "<br><b>Findings:</b><br>" + _findings_html(ssl_findings)

        sections_html += _section("SSL/TLS Analysis", "🔒", content, "ssl")
        nav_links += '<a href="#ssl">SSL/TLS</a>'

    # ── WHOIS ─────────────────────────────────────
    whois = data.get("whois")
    if whois and not whois.get("error"):
        rows = f"""
          <tr><td>Registrar</td><td>{whois.get('registrar','—')}</td></tr>
          <tr><td>Created</td><td>{whois.get('creation_date','—')}</td></tr>
          <tr><td>Expires</td><td>{whois.get('expiration_date','—')}</td></tr>
          <tr><td>Updated</td><td>{whois.get('updated_date','—')}</td></tr>
          <tr><td>Country</td><td>{whois.get('registrant_country','—')}</td></tr>
          <tr><td>DNSSEC</td><td>{whois.get('dnssec','—')}</td></tr>
          <tr><td>Name Servers</td><td>{'<br>'.join(whois.get('name_servers',[]))}</td></tr>
          <tr><td>Status</td><td>{'<br>'.join(whois.get('status',[]))}</td></tr>
        """
        table = f"<table><tr><th>Field</th><th>Value</th></tr>{rows}</table>"
        sections_html += _section("WHOIS", "📋", table, "whois")
        nav_links += '<a href="#whois">WHOIS</a>'

    # ── Findings Summary ──────────────────────────
    if all_findings:
        cards.append(("findings", str(len(all_findings)), "Total Findings"))
        findings_content = _findings_html(all_findings)
        sections_html = _section("Security Findings Summary", "⚠️", findings_content, "findings") + sections_html
        nav_links = '<a href="#findings">⚠️ Findings</a>' + nav_links

    # ── Render ─────────────────────────────────────
    cards_html = "".join(
        f"""<div class="card">
          <div class="card-number">{num}</div>
          <div class="card-label">{label}</div>
        </div>"""
        for _, num, label in cards
    )

    html = _HTML_TEMPLATE.format(
        target=target,
        generated_at=generated_at,
        version=__version__,
        nav_links=nav_links,
        summary_cards=cards_html,
        sections=sections_html,
    )

    path.write_text(html)
    return str(path)
