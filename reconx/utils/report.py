"""
Report generation — JSON and self-contained HTML reports.

v1.4 upgrades:
  - Schema versioning in JSON output
  - Executive summary section (risk rating, key stats, top findings)
  - Confidence score badges per finding
  - Remediation guidance per finding (collapsible)
  - Asset inventory section from correlation data
  - Correlation findings section (admin hosts, shadow subdomains, etc.)
  - Per-finding evidence list
  - References (OWASP / RFC links)
"""

import json
import datetime
from datetime import timezone
from pathlib import Path
from typing import Any

from reconx import __version__

SCHEMA_VERSION = "1.4"


# ─────────────────────────────────────────────────────────────
# Serialisation
# ─────────────────────────────────────────────────────────────

def _serialise(obj: Any) -> Any:
    from enum import Enum
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialise(getattr(obj, k)) for k in obj.__dataclass_fields__}
    if isinstance(obj, list):
        return [_serialise(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    return obj


def save_json(data: dict, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "reconx_version": __version__,
        "generated_at": datetime.datetime.now(timezone.utc).isoformat() + "Z",
        **{k: _serialise(v) for k, v in data.items()},
    }
    path.write_text(json.dumps(payload, indent=2, default=str))
    return str(path)


# ─────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────

_SEV_COLOURS = {
    "CRITICAL": ("#f85149", "#3d1c1c"),
    "HIGH":     ("#db6d28", "#3d2000"),
    "MEDIUM":   ("#d29922", "#332d00"),
    "LOW":      ("#3fb950", "#1b4332"),
    "INFO":     ("#58a6ff", "#1c2d3d"),
}


def _badge(text: str, colour: str = "blue") -> str:
    return f'<span class="badge badge-{colour}">{text}</span>'


def _sev_badge(severity: str) -> str:
    colour_map = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue",
    }
    return _badge(severity, colour_map.get(severity.upper(), "blue"))


def _section(title: str, icon: str, content: str, anchor: str = "",
             collapsible: bool = False, open_by_default: bool = True) -> str:
    anchor_attr = f'id="{anchor}"' if anchor else ""
    inner = f"""
<div class="section" {anchor_attr}>
  <div class="section-header" onclick="toggleSection(this)">
    <span>{icon}</span>
    <span class="section-title">{title}</span>
    <span class="toggle-icon" style="margin-left:auto">▼</span>
  </div>
  <div class="section-body" {'style="display:none"' if collapsible and not open_by_default else ''}>
    {content}
  </div>
</div>"""
    return inner


def _conf_badge(confidence: int) -> str:
    """Render a small confidence percentage badge."""
    col = "red" if confidence >= 90 else "orange" if confidence >= 70 else "yellow" if confidence >= 50 else "muted"
    return f'<span class="badge badge-{col}" style="font-size:10px" title="Confidence">{confidence}%</span>'


def _findings_html(findings: list, module: str = "", show_remediation: bool = True) -> str:
    """
    Render a list of findings as HTML rows.

    Accepts:
      - Finding dataclass objects (severity, title, detail, module, confidence,
        evidence, remediation, references, affected)
      - Plain strings (severity auto-classified)
      - Dicts with "sev", "title", "module" keys (internal use)
    """
    if not findings:
        return '<div class="empty">No findings.</div>'
    html = ""
    for f in findings:
        if hasattr(f, "severity") and hasattr(f, "title"):
            # Finding dataclass
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            title = f.title
            detail = getattr(f, "detail", "")
            mod = getattr(f, "module", module)
            confidence = getattr(f, "confidence", 0)
            evidence = getattr(f, "evidence", [])
            remediation = getattr(f, "remediation", "")
            references = getattr(f, "references", [])
            affected = getattr(f, "affected", "")
        elif isinstance(f, dict) and "sev" in f:
            sev = f["sev"]
            title = f.get("title", "")
            detail = f.get("detail", "")
            mod = f.get("module", module)
            confidence = f.get("confidence", 0)
            evidence = f.get("evidence", [])
            remediation = f.get("remediation", "")
            references = f.get("references", [])
            affected = f.get("affected", "")
        else:
            title = str(f)
            detail = ""
            sev = _classify_severity(title)
            mod = module
            confidence = 0
            evidence = []
            remediation = ""
            references = []
            affected = ""

        fg, bg = _SEV_COLOURS.get(sev, ("#c9d1d9", "#161b22"))
        mod_tag = f'<span style="font-size:10px;opacity:0.6;margin-left:6px">[{mod}]</span>' if mod else ""
        conf_tag = _conf_badge(confidence) if confidence else ""
        affected_tag = (
            f'<span style="font-size:10px;color:#58a6ff;margin-left:6px" title="Affected">{affected}</span>'
            if affected else ""
        )
        detail_html = f'<div style="font-size:12px;opacity:0.7;margin-top:2px">{detail}</div>' if detail else ""

        # Evidence list
        evidence_html = ""
        if evidence:
            ev_items = "".join(
                f'<li style="font-size:11px;color:#8b949e;font-family:monospace">{e}</li>'
                for e in evidence[:5]
            )
            evidence_html = f'<details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px;color:#8b949e">Evidence ({len(evidence)})</summary><ul style="margin:4px 0 0 16px">{ev_items}</ul></details>'

        # Remediation + references
        remediation_html = ""
        if show_remediation and remediation:
            ref_links = ""
            if references:
                ref_links = " ".join(
                    f'<a href="{r}" target="_blank" style="font-size:10px;color:#58a6ff;margin-right:6px">{r.split("/")[2] if "/" in r else r}</a>'
                    for r in references[:3]
                )
            remediation_html = f"""<details style="margin-top:4px">
  <summary style="cursor:pointer;font-size:11px;color:#3fb950">Remediation</summary>
  <div style="font-size:12px;padding:4px 0;color:#c9d1d9">{remediation}</div>
  {f'<div style="margin-top:2px">{ref_links}</div>' if ref_links else ""}
</details>"""

        html += f"""<div class="finding-row" style="border-left-color:{fg};background:{bg}">
  <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
    {_sev_badge(sev)}{conf_tag}{mod_tag}{affected_tag}
    <span>{title}</span>
  </div>
  {detail_html}{evidence_html}{remediation_html}
</div>\n"""
    return html


def _classify_severity(text: str) -> str:
    """Quick-classify a string finding for HTML rendering."""
    t = text.upper()
    if any(k in t for k in ("ZONE TRANSFER", "GIT REPO", "ENV FILE", "EXPIRED", "ACTUATOR")):
        return "CRITICAL"
    if any(k in t for k in ("DEPRECATED", "WEAK CIPHER", "SELF-SIGNED", "SSLv", "TLS 1.0", "TLS 1.1", "SNMP", "TELNET", "EXPOSED")):
        return "HIGH"
    if any(k in t for k in ("MISSING", "CSP", "HSTS", "SPF", "DMARC", "CLICKJACKING")):
        return "MEDIUM"
    if any(k in t for k in ("REFERRER", "PERMISSION", "COOKIE", "EXPIR", "PTR", "ASN")):
        return "LOW"
    return "INFO"


# ─────────────────────────────────────────────────────────────
# Mini SVG charts
# ─────────────────────────────────────────────────────────────

def _severity_chart(counts: dict[str, int]) -> str:
    """Render a tiny horizontal bar chart for severity counts."""
    total = sum(counts.values()) or 1
    colours = {"CRITICAL": "#f85149", "HIGH": "#db6d28", "MEDIUM": "#d29922", "LOW": "#3fb950", "INFO": "#58a6ff"}
    bars = ""
    for sev, count in counts.items():
        if not count:
            continue
        pct = count / total * 100
        col = colours.get(sev, "#8b949e")
        bars += f'<div style="display:flex;align-items:center;gap:8px;margin:3px 0">'
        bars += f'<span style="width:60px;font-size:11px;color:{col}">{sev}</span>'
        bars += f'<div style="background:{col};height:10px;width:{pct:.1f}%;border-radius:3px;min-width:4px"></div>'
        bars += f'<span style="font-size:11px;color:#8b949e">{count}</span></div>'
    return bars


def _service_chart(open_ports: list) -> str:
    """Bar chart of open ports by service."""
    counts: dict[str, int] = {}
    for p in open_ports:
        svc = p.get("service", "Unknown") if isinstance(p, dict) else getattr(p, "service", "Unknown")
        counts[svc] = counts.get(svc, 0) + 1

    if not counts:
        return ""

    max_count = max(counts.values()) or 1
    bars = ""
    for svc, count in sorted(counts.items(), key=lambda x: -x[1])[:10]:
        pct = count / max_count * 100
        bars += f'<div style="display:flex;align-items:center;gap:8px;margin:3px 0">'
        bars += f'<span style="width:100px;font-size:11px;color:#8b949e;overflow:hidden;text-overflow:ellipsis">{svc}</span>'
        bars += f'<div style="background:#58a6ff;height:10px;width:{pct:.1f}%;border-radius:3px;min-width:4px"></div>'
        bars += f'<span style="font-size:11px;color:#8b949e">{count}</span></div>'
    return bars


# ─────────────────────────────────────────────────────────────
# CSS + JS
# ─────────────────────────────────────────────────────────────

_STYLE = """
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --green: #3fb950; --red: #f85149;
    --yellow: #d29922; --orange: #db6d28; --text: #c9d1d9; --muted: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
  a { color: var(--accent); text-decoration: none; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  /* Header */
  .header { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 24px; margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between; }
  .logo { font-size: 28px; font-weight: 700; color: var(--accent); letter-spacing: 2px; }
  .logo span { color: var(--red); }
  .meta { text-align: right; color: var(--muted); font-size: 12px; }
  .target-badge { background: #21262d; border: 1px solid var(--border); border-radius: 20px; padding: 6px 16px; font-family: monospace; color: var(--accent); margin-top: 8px; display: inline-block; }
  /* Summary cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .card-number { font-size: 32px; font-weight: 700; color: var(--accent); }
  .card-number.critical { color: var(--red); }
  .card-number.high { color: var(--orange); }
  .card-number.medium { color: var(--yellow); }
  .card-label { color: var(--muted); font-size: 11px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
  /* Section */
  .section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 16px; overflow: hidden; }
  .section-header { padding: 14px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; background: #1c2128; cursor: pointer; user-select: none; }
  .section-header:hover { background: #21262d; }
  .section-title { font-size: 15px; font-weight: 600; }
  .section-body { padding: 16px 20px; }
  .toggle-icon { color: var(--muted); font-size: 12px; transition: transform .2s; }
  .section-header.collapsed .toggle-icon { transform: rotate(-90deg); }
  /* Table */
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; font-family: monospace; font-size: 13px; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1c2128; }
  /* Badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-green   { background: #1b4332; color: var(--green); }
  .badge-red     { background: #3d1c1c; color: var(--red); }
  .badge-yellow  { background: #332d00; color: var(--yellow); }
  .badge-blue    { background: #1c2d3d; color: var(--accent); }
  .badge-orange  { background: #3d2000; color: var(--orange); }
  .badge-muted   { background: #21262d; color: var(--muted); }
  /* Findings */
  .finding-row { border-left: 3px solid var(--red); padding: 8px 12px; margin-bottom: 6px; border-radius: 0 4px 4px 0; font-size: 13px; }
  /* Port state */
  .port-open { color: var(--green); font-weight: 600; }
  /* Tech tag */
  .tech-tag { display: inline-block; background: #21262d; border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; margin: 2px; font-size: 12px; color: var(--accent); }
  /* Footer */
  .footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 32px; padding: 16px; }
  /* Nav */
  .nav { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }
  .nav a { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 6px 14px; font-size: 13px; color: var(--text); transition: border-color .2s; }
  .nav a:hover { border-color: var(--accent); color: var(--accent); }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; color: var(--muted); }
  .empty { color: var(--muted); font-style: italic; padding: 8px 0; }
  .chart-box { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin-top: 12px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  /* Executive summary */
  .exec-summary { background: #1c2128; border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; }
  .risk-badge { display: inline-block; padding: 4px 16px; border-radius: 20px; font-size: 13px; font-weight: 700; letter-spacing: 1px; }
  .risk-critical { background: #3d1c1c; color: #f85149; border: 1px solid #f85149; }
  .risk-high     { background: #3d2000; color: #db6d28; border: 1px solid #db6d28; }
  .risk-medium   { background: #332d00; color: #d29922; border: 1px solid #d29922; }
  .risk-low      { background: #1b4332; color: #3fb950; border: 1px solid #3fb950; }
  .risk-info     { background: #1c2d3d; color: #58a6ff; border: 1px solid #58a6ff; }
  /* Asset inventory */
  .asset-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 8px; }
  .asset-box { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; }
  .asset-box-title { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 6px; }
  @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } .header { flex-direction: column; gap: 12px; } }
"""

_JS = """
function toggleSection(header) {
  const body = header.nextElementSibling;
  const isHidden = body.style.display === 'none';
  body.style.display = isHidden ? '' : 'none';
  header.classList.toggle('collapsed', !isHidden);
}
// Collapse all except findings by default on large reports
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.section-body[data-collapse]').forEach(b => {
    b.style.display = 'none';
    b.previousElementSibling.classList.add('collapsed');
  });
});
"""

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReconX Report — {target}</title>
  <style>{style}</style>
</head>
<body>
<div class="container">
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
  <div class="nav">{nav_links}</div>
  <div class="cards">{summary_cards}</div>
  {sections}
  <div class="footer">ReconX v{version} — For authorised security testing only</div>
</div>
<script>{js}</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────

def _port_section(scan: dict) -> tuple[str, str]:
    open_ports = scan.get("open_ports", [])
    rows = ""
    for p in open_ports:
        banner = (p.get("banner", "") or "")[:60]
        version = (p.get("version", "") or "")[:30]
        rows += f"""<tr>
          <td class="port-open">{p['port']}</td>
          <td>TCP</td>
          <td>{_badge(p.get('service','?'), 'blue')}</td>
          <td style="color:#58a6ff">{version}</td>
          <td>{banner or '<span class="empty">—</span>'}</td>
        </tr>"""

    chart = ""
    if open_ports:
        chart = f'<div class="chart-box"><b style="font-size:12px;color:var(--muted)">Services</b>{_service_chart(open_ports)}</div>'

    table = f"""<table>
      <tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>Banner</th></tr>
      {rows or '<tr><td colspan="5" class="empty">No open ports found</td></tr>'}
    </table>{chart}"""

    return table, f'<a href="#ports">Ports ({len(open_ports)})</a>'


def _udp_section(udp: dict) -> tuple[str, str]:
    open_ports = udp.get("open_ports", [])
    rows = ""
    for p in open_ports:
        state = p.get("state", "open|filtered")
        state_col = "green" if state == "open" else "yellow"
        rows += f"""<tr>
          <td style="color:var(--yellow)">{p['port']}</td>
          <td>UDP</td>
          <td>{_badge(p.get('service','?'), 'blue')}</td>
          <td>{_badge(state, state_col)}</td>
          <td>{(p.get('banner','') or '')[:60]}</td>
        </tr>"""

    table = f"""<table>
      <tr><th>Port</th><th>Proto</th><th>Service</th><th>State</th><th>Banner</th></tr>
      {rows or '<tr><td colspan="5" class="empty">No UDP responses</td></tr>'}
    </table>"""

    return table, f'<a href="#udp">UDP ({len(open_ports)})</a>'


def _dns_section(dns: dict) -> tuple[str, str]:
    records = dns.get("records", {})
    total = sum(len(v) for v in records.values())
    rows = ""
    for rtype, recs in records.items():
        for r in recs:
            rows += f"<tr><td>{_badge(rtype, 'blue')}</td><td>{r['value']}</td></tr>"

    zt_html = ""
    for zt in dns.get("zone_transfers", []):
        if zt.get("success"):
            zt_html += f'<div class="finding-row" style="border-left-color:#f85149;background:#3d1c1c">{_sev_badge("CRITICAL")} Zone transfer SUCCESSFUL from {zt["nameserver"]}!</div>'

    findings_html = _findings_html(dns.get("security_findings", []), "dns")

    content = f"""<table>
      <tr><th>Type</th><th>Value</th></tr>
      {rows or '<tr><td colspan="2" class="empty">No records found</td></tr>'}
    </table>"""
    if zt_html:
        content += "<br>" + zt_html
    if dns.get("security_findings"):
        content += "<br><b>Security Findings:</b><br>" + findings_html

    return content, f'<a href="#dns">DNS ({total})</a>'


def _crawl_section(crawl: dict) -> tuple[str, str]:
    endpoints = crawl.get("endpoints", [])
    js_files = crawl.get("js_files", [])
    subdomains = crawl.get("discovered_subdomains", [])

    ep_rows = ""
    for ep in sorted(endpoints, key=lambda e: (e.get("status_code", 0), e.get("url", "")))[:100]:
        sc = ep.get("status_code", 0)
        sc_col = "green" if 200 <= sc < 300 else "yellow" if sc < 400 else "red"
        note = ep.get("note", "")
        ep_rows += f"""<tr>
          <td><a href="{ep['url']}" target="_blank">{ep['url'][:70]}</a></td>
          <td>{_badge(str(sc), sc_col) if sc else '<span class="empty">—</span>'}</td>
          <td style="color:var(--muted);font-size:11px">{ep.get('source','')}</td>
          <td style="color:var(--red)">{note}</td>
        </tr>"""

    all_ep: set[str] = set()
    for js in js_files:
        all_ep.update(js.get("endpoints_found", []))

    js_html = ""
    if all_ep:
        ep_list = "".join(f"<tr><td>{e}</td></tr>" for e in sorted(all_ep)[:50])
        js_html = f"""<br><details><summary style="cursor:pointer;color:var(--muted);font-size:12px">
          API routes from JS ({len(all_ep)})
        </summary><table><tr><th>Endpoint</th></tr>{ep_list}</table></details>"""

    sub_html = ""
    if subdomains:
        sub_list = "".join(f"<span class='tech-tag'>{s}</span>" for s in subdomains[:20])
        sub_html = f"<br><b>Subdomains in JS:</b><br>{sub_list}"

    content = f"""<table>
      <tr><th>URL</th><th>Status</th><th>Source</th><th>Note</th></tr>
      {ep_rows or '<tr><td colspan="4" class="empty">No endpoints found</td></tr>'}
    </table>{js_html}{sub_html}"""

    return content, f'<a href="#crawl">Crawl ({len(endpoints)})</a>'


def _ip_intel_section(intel: dict) -> tuple[str, str]:
    asn = intel.get("asn") or {}
    geo = intel.get("geo") or {}
    ptr = intel.get("ptr_records", [])

    rows = f"""
      <tr><td>IP</td><td>{intel.get('ip','—')}</td></tr>
      <tr><td>PTR</td><td>{', '.join(ptr) or '—'}</td></tr>
      <tr><td>ASN</td><td>{asn.get('asn','—')} {asn.get('asn_name','')}</td></tr>
      <tr><td>Network</td><td>{asn.get('cidr','—')}</td></tr>
      <tr><td>Org</td><td>{asn.get('org','') or asn.get('asn_description','—')}</td></tr>
      <tr><td>Cloud</td><td>{_badge(asn['cloud_provider'], 'blue') if asn.get('cloud_provider') else '—'}</td></tr>
      <tr><td>Country</td><td>{asn.get('country','—')}</td></tr>
      <tr><td>Location</td><td>{geo.get('city','—')}, {geo.get('country','—')}</td></tr>
      <tr><td>ISP</td><td>{geo.get('isp','—')}</td></tr>
    """
    content = f"<table><tr><th>Field</th><th>Value</th></tr>{rows}</table>"
    if intel.get("findings"):
        content += "<br>" + _findings_html(intel["findings"], "ip_intel")

    return content, '<a href="#ip_intel">IP Intel</a>'


def _passive_section(passive: dict) -> tuple[str, str]:
    content = ""
    hosts = passive.get("hosts", [])
    subs = passive.get("subdomains", [])
    emails = passive.get("emails", [])
    findings = passive.get("findings", [])

    if findings:
        content += _findings_html(findings, "passive")

    if hosts:
        rows = ""
        for h in hosts:
            ports = ", ".join(str(p) for p in h.get("ports", [])[:20])
            rows += f"<tr><td>{h.get('ip','')}</td><td>{', '.join(h.get('hostnames',[]))}</td><td>{ports}</td><td>{_badge(h.get('source','?'), 'blue')}</td></tr>"
        content += f"""<br><table>
          <tr><th>IP</th><th>Hostnames</th><th>Open Ports</th><th>Source</th></tr>{rows}
        </table>"""

    if subs:
        sub_tags = "".join(f"<span class='tech-tag'>{s}</span>" for s in subs[:30])
        content += f"<br><b>Subdomains ({len(subs)}):</b><br>{sub_tags}"

    if emails:
        content += f"<br><b>Emails:</b> {', '.join(emails[:10])}"

    if passive.get("abuse_score") is not None:
        score = passive["abuse_score"]
        col = "red" if score > 50 else "yellow" if score > 10 else "green"
        content += f"<br><b>AbuseIPDB score:</b> {_badge(str(score) + '%', col)}"

    if passive.get("vt_detections"):
        content += f"<br><b>VirusTotal:</b> {_badge(str(passive['vt_detections']) + ' detections', 'red')}"

    return content or '<div class="empty">No passive data found.</div>', '<a href="#passive">Passive</a>'


# ─────────────────────────────────────────────────────────────
# Executive summary
# ─────────────────────────────────────────────────────────────

def _risk_level(counts: dict[str, int]) -> str:
    """Derive overall risk level from finding severity counts."""
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) > 0:
        return "HIGH"
    if counts.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if counts.get("LOW", 0) > 0:
        return "LOW"
    return "INFO"


def _executive_summary(
    target: str,
    all_findings: list,
    collected: dict,
) -> str:
    """Render an executive summary block."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("sev", "INFO") if isinstance(f, dict) else (
            (f.severity.value if hasattr(f.severity, "value") else str(f.severity))
            if hasattr(f, "severity") else "INFO"
        )
        counts[sev] = counts.get(sev, 0) + 1

    risk = _risk_level(counts)
    risk_css = f"risk-{risk.lower()}"

    # Quick stats
    open_ports = 0
    scan = collected.get("port_scan")
    if scan:
        op = getattr(scan, "open_ports", scan.get("open_ports", []) if isinstance(scan, dict) else [])
        open_ports = len(op)

    sub_count = 0
    subs = collected.get("subdomains")
    if subs:
        sl = getattr(subs, "subdomains", subs.get("subdomains", []) if isinstance(subs, dict) else [])
        sub_count = len(sl)

    tech_count = 0
    http_results = collected.get("http", [])
    if http_results:
        tech_set: set = set()
        for r in http_results:
            r_d = r if isinstance(r, dict) else _serialise(r)
            for t in r_d.get("technologies", []):
                tech_set.add(t.get("name", ""))
        tech_count = len(tech_set)

    total_findings = sum(counts.values())

    # Top critical/high findings
    top_findings: list = []
    for f in all_findings:
        if isinstance(f, dict):
            if f.get("sev") in ("CRITICAL", "HIGH"):
                top_findings.append(f)
        elif hasattr(f, "severity"):
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_val in ("CRITICAL", "HIGH"):
                top_findings.append(f)
        if len(top_findings) >= 5:
            break

    top_html = ""
    if top_findings:
        items = ""
        for f in top_findings[:5]:
            t = f.get("title", "") if isinstance(f, dict) else getattr(f, "title", "")
            s = f.get("sev", "HIGH") if isinstance(f, dict) else (
                f.severity.value if hasattr(f.severity, "value") else "HIGH"
            )
            items += f'<li>{_sev_badge(s)} {t}</li>'
        top_html = f'<div style="margin-top:12px"><b style="font-size:12px;color:var(--muted)">Key Findings:</b><ul style="margin:6px 0 0 20px;list-style:disc">{items}</ul></div>'

    stats = f"""
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-top:12px">
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:var(--accent)">{total_findings}</div><div style="font-size:11px;color:var(--muted)">TOTAL FINDINGS</div></div>
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:#f85149">{counts['CRITICAL']}</div><div style="font-size:11px;color:var(--muted)">CRITICAL</div></div>
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:#db6d28">{counts['HIGH']}</div><div style="font-size:11px;color:var(--muted)">HIGH</div></div>
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:var(--accent)">{open_ports}</div><div style="font-size:11px;color:var(--muted)">OPEN PORTS</div></div>
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:var(--accent)">{sub_count}</div><div style="font-size:11px;color:var(--muted)">SUBDOMAINS</div></div>
  <div style="text-align:center"><div style="font-size:22px;font-weight:700;color:var(--accent)">{tech_count}</div><div style="font-size:11px;color:var(--muted)">TECHNOLOGIES</div></div>
</div>"""

    return f"""<div class="exec-summary">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
    <div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:4px">OVERALL RISK</div>
      <span class="risk-badge {risk_css}">{risk}</span>
    </div>
    <div style="flex:1;min-width:200px">
      <div style="font-size:12px;color:var(--muted)">Target: <span style="color:var(--accent);font-family:monospace">{target}</span></div>
      <div style="font-size:12px;color:var(--muted);margin-top:2px">Scanned with ReconX v{__version__} on {datetime.datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>
    </div>
  </div>
  {stats}{top_html}
</div>"""


# ─────────────────────────────────────────────────────────────
# Correlation / asset inventory section
# ─────────────────────────────────────────────────────────────

def _correlation_section(corr: Any) -> tuple[str, str]:
    """Build the Asset Correlation section from a CorrelationResult."""
    c = corr if isinstance(corr, dict) else _serialise(corr)

    # Host role table
    host_roles = c.get("host_roles", {})
    role_rows = ""
    for host, role in list(host_roles.items())[:30]:
        role_col = {
            "admin": "red", "staging": "yellow", "dev": "yellow",
            "api": "blue", "prod": "green", "cdn": "muted",
        }.get(role, "muted")
        role_rows += f"<tr><td style='font-family:monospace'>{host}</td><td>{_badge(role, role_col)}</td></tr>"

    # Asset inventory boxes
    all_ips = c.get("all_ips", [])
    ssl_confirmed = c.get("ssl_confirmed_subdomains", [])
    not_in_san = c.get("subdomains_not_in_san", [])
    cloud = c.get("cloud_providers", [])

    assets_html = f"""<div class="asset-grid">
  <div class="asset-box">
    <div class="asset-box-title">Unique IPs</div>
    {''.join(f'<div style="font-family:monospace;font-size:12px">{ip}</div>' for ip in all_ips[:20]) or '<span class="empty">—</span>'}
  </div>
  <div class="asset-box">
    <div class="asset-box-title">SSL-Confirmed Subdomains ({len(ssl_confirmed)})</div>
    {''.join(f'<div style="font-size:12px;color:#3fb950">{s}</div>' for s in ssl_confirmed[:15]) or '<span class="empty">None</span>'}
  </div>
  <div class="asset-box">
    <div class="asset-box-title">Not in SSL SAN ({len(not_in_san)})</div>
    {''.join(f'<div style="font-size:12px;color:#d29922">{s}</div>' for s in not_in_san[:15]) or '<span class="empty">None</span>'}
  </div>
  <div class="asset-box">
    <div class="asset-box-title">Cloud Providers</div>
    {''.join(f'<div>{_badge(p, "blue")}</div>' for p in cloud) or '<span class="empty">Unknown</span>'}
  </div>
</div>"""

    role_table = f"""<div style="margin-top:16px">
  <b style="font-size:12px;color:var(--muted)">Host Role Classification</b>
  <table style="margin-top:8px"><tr><th>Host</th><th>Inferred Role</th></tr>
    {role_rows or '<tr><td colspan="2" class="empty">No hosts classified</td></tr>'}
  </table>
</div>"""

    # Correlated findings
    corr_findings = c.get("correlated_findings", [])
    corr_findings_html = ""
    if corr_findings:
        corr_findings_html = "<div style='margin-top:16px'><b style='font-size:12px;color:var(--muted)'>Correlated Findings</b><br><br>" + _findings_html(corr_findings, "correlation") + "</div>"

    content = assets_html + role_table + corr_findings_html
    return content, '<a href="#correlation">Correlation</a>'


# ─────────────────────────────────────────────────────────────
# Main HTML generator
# ─────────────────────────────────────────────────────────────

def generate_html(data: dict, output_path: str) -> str:
    """Generate a self-contained HTML report with severity scoring and charts."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    target = data.get("target", "Unknown")
    generated_at = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections_html = ""
    nav_links = ""
    cards: list[tuple[str, str, str, str]] = []   # (anchor, number, label, colour_class)

    # Promote structured Finding objects into all_findings early so executive
    # summary can access them.  We also collect string findings below.
    pre_findings = data.get("_findings", [])


    # ── Collect all findings for severity summary ──────────────
    all_findings = []

    def _collect_str_findings(texts, module):
        for t in (texts or []):
            if isinstance(t, str) and t.strip():
                all_findings.append({"sev": _classify_severity(t), "title": t, "module": module})

    # ── Port Scan ────────────────────────────────────────────
    scan = data.get("port_scan")
    if scan:
        port_content, port_nav = _port_section(scan if isinstance(scan, dict) else _serialise(scan))
        open_count = len(scan.get("open_ports", []) if isinstance(scan, dict) else _serialise(scan).get("open_ports", []))
        cards.append(("ports", str(open_count), "Open Ports (TCP)", ""))
        sections_html += _section("Port Scan", "🔍", port_content, "ports")
        nav_links += port_nav

    # ── UDP ──────────────────────────────────────────────────
    udp = data.get("udp")
    if udp:
        ud = udp if isinstance(udp, dict) else _serialise(udp)
        udp_content, udp_nav = _udp_section(ud)
        cards.append(("udp", str(len(ud.get("open_ports", []))), "UDP Ports", ""))
        sections_html += _section("UDP Scan", "📡", udp_content, "udp")
        nav_links += udp_nav
        for p in ud.get("open_ports", []):
            if p.get("service") in ("SNMP", "IKE/IPSec"):
                all_findings.append({"sev": "HIGH", "title": f"{p['service']} open on UDP/{p['port']}", "module": "udp"})

    # ── DNS ──────────────────────────────────────────────────
    dns = data.get("dns")
    if dns:
        dd = dns if isinstance(dns, dict) else _serialise(dns)
        dns_content, dns_nav = _dns_section(dd)
        total_dns = sum(len(v) for v in dd.get("records", {}).values())
        cards.append(("dns", str(total_dns), "DNS Records", ""))
        sections_html += _section("DNS Enumeration", "📡", dns_content, "dns")
        nav_links += dns_nav
        _collect_str_findings(dd.get("security_findings", []), "dns")
        for zt in dd.get("zone_transfers", []):
            if zt.get("success"):
                all_findings.append({"sev": "CRITICAL", "title": f"Zone transfer SUCCESSFUL from {zt['nameserver']}", "module": "dns"})

    # ── Subdomains ───────────────────────────────────────────
    subs = data.get("subdomains")
    if subs:
        sd = subs if isinstance(subs, dict) else _serialise(subs)
        subdomain_list = sd.get("subdomains", [])
        cards.append(("subs", str(len(subdomain_list)), "Subdomains", ""))
        rows = ""
        for s in subdomain_list:
            ips = ", ".join(s.get("ips", [])) or "Unresolved"
            sc_col = {"crtsh": "green", "hackertarget": "orange", "bruteforce": "blue", "passive": "yellow"}.get(s.get("source", ""), "blue")
            rows += f"<tr><td>{s['name']}</td><td>{ips}</td><td>{_badge(s.get('source','?'), sc_col)}</td></tr>"
        table = f"""<table><tr><th>Subdomain</th><th>IP(s)</th><th>Source</th></tr>
          {rows or '<tr><td colspan="3" class="empty">No subdomains found</td></tr>'}
        </table>"""
        sections_html += _section("Subdomain Enumeration", "🌐", table, "subs")
        nav_links += f'<a href="#subs">Subdomains ({len(subdomain_list)})</a>'

    # ── HTTP ─────────────────────────────────────────────────
    http_results = data.get("http", [])
    if http_results:
        http_list = [r if isinstance(r, dict) else _serialise(r) for r in http_results]
        tech_set: set[str] = set()
        for r in http_list:
            for t in r.get("technologies", []):
                tech_set.add(t.get("name", ""))

        cards.append(("http", str(len(tech_set)), "Technologies", ""))
        content = ""
        for r in http_list:
            url = r.get("url", "")
            status = r.get("status_code", 0)
            sc_col = "green" if 200 <= status < 300 else "red" if status >= 400 else "yellow"
            techs = "".join(f'<span class="tech-tag">{t["name"]}</span>' for t in r.get("technologies", []))
            missing = r.get("missing_security_headers", [])
            paths = r.get("interesting_paths", [])
            _collect_str_findings(missing, "http")
            for ip_path in paths:
                note = ip_path.get("note", "") if isinstance(ip_path, dict) else ""
                if note:
                    all_findings.append({"sev": _classify_severity(note), "title": note, "module": "http"})

            path_rows = ""
            for ip_p in paths:
                ip_d = ip_p if isinstance(ip_p, dict) else {}
                sc2_col = "green" if ip_d.get("status_code") == 200 else "yellow"
                path_rows += f"<tr><td>{ip_d.get('path','')}</td><td>{_badge(str(ip_d.get('status_code',0)), sc2_col)}</td><td style='color:var(--red)'>{ip_d.get('note','')}</td></tr>"

            content += f"""
<div style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid var(--border)">
  <div style="margin-bottom:8px">
    <b><a href="{url}" target="_blank">{url}</a></b> {_badge(str(status), sc_col)}
    {f'<span style="color:var(--muted);margin-left:8px">{r.get("title","")}</span>' if r.get("title") else ''}
  </div>
  {f'<div style="margin-bottom:6px">{_badge("Server","blue")} {r.get("server","")}</div>' if r.get("server") else ''}
  <div style="margin-bottom:8px">{techs or '<span class="empty">No technologies detected</span>'}</div>
  {'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px">Missing Headers (' + str(len(missing)) + ')</summary>' + _findings_html(missing, "http") + '</details>' if missing else ''}
  {'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px">Interesting Paths (' + str(len(paths)) + ')</summary><table><tr><th>Path</th><th>Status</th><th>Note</th></tr>' + path_rows + '</table></details>' if paths else ''}
</div>"""

        sections_html += _section("HTTP Probing & Technology Fingerprinting", "🕵️", content, "http")
        nav_links += f'<a href="#http">HTTP ({len(http_list)})</a>'

    # ── Web Crawl ────────────────────────────────────────────
    crawl = data.get("crawl")
    if crawl:
        cd = crawl if isinstance(crawl, dict) else _serialise(crawl)
        crawl_content, crawl_nav = _crawl_section(cd)
        cards.append(("crawl", str(len(cd.get("endpoints", []))), "Crawled Endpoints", ""))
        sections_html += _section("Web Crawl & Endpoint Discovery", "🕸️", crawl_content, "crawl")
        nav_links += crawl_nav

    # ── SSL ──────────────────────────────────────────────────
    ssl_result = data.get("ssl")
    if ssl_result and not (ssl_result.get("error") if isinstance(ssl_result, dict) else getattr(ssl_result, "error", None)):
        sd2 = ssl_result if isinstance(ssl_result, dict) else _serialise(ssl_result)
        cert = sd2.get("cert") or {}
        days = cert.get("days_until_expiry", 0)
        expiry_col = "red" if days < 0 else "yellow" if days < 30 else "green"
        subject = cert.get("subject") or {}
        issuer = cert.get("issuer") or {}
        san = cert.get("san") or []
        ssl_findings = sd2.get("findings", [])
        _collect_str_findings(ssl_findings, "ssl")

        cert_html = f"""<table>
          <tr><th>Field</th><th>Value</th></tr>
          <tr><td>Subject CN</td><td>{subject.get('commonName','—')}</td></tr>
          <tr><td>Issuer</td><td>{issuer.get('organizationName','—')}</td></tr>
          <tr><td>Valid From</td><td>{cert.get('not_before','—')}</td></tr>
          <tr><td>Valid Until</td><td>{cert.get('not_after','—')} {_badge(str(days)+' days', expiry_col)}</td></tr>
          <tr><td>Self-Signed</td><td>{_badge('YES','red') if cert.get('is_self_signed') else _badge('No','green')}</td></tr>
          <tr><td>SANs</td><td>{'<br>'.join(san[:10]) if san else '—'}</td></tr>
          <tr><td>Cipher</td><td>{sd2.get('cipher','—')} ({sd2.get('cipher_bits',0)} bits)</td></tr>
        </table>"""

        protos = sd2.get("protocols", [])
        proto_rows = "".join(
            f"<tr><td>{p['name']}</td><td>"
            f"{_badge('Supported', 'red' if p.get('deprecated') else 'green') if p['supported'] else _badge('Not Supported','muted')}"
            f"</td></tr>"
            for p in protos
        )
        proto_html = f"<br><b>Protocol Support:</b><table><tr><th>Protocol</th><th>Status</th></tr>{proto_rows}</table>" if protos else ""
        findings_html = ("<br><b>Findings:</b><br>" + _findings_html(ssl_findings, "ssl")) if ssl_findings else ""

        sections_html += _section("SSL/TLS Analysis", "🔒", cert_html + proto_html + findings_html, "ssl")
        nav_links += '<a href="#ssl">SSL/TLS</a>'

    # ── WHOIS ────────────────────────────────────────────────
    whois = data.get("whois")
    if whois and not (whois.get("error") if isinstance(whois, dict) else getattr(whois, "error", None)):
        wd = whois if isinstance(whois, dict) else _serialise(whois)
        rows = f"""
          <tr><td>Registrar</td><td>{wd.get('registrar','—')}</td></tr>
          <tr><td>Created</td><td>{wd.get('creation_date','—')}</td></tr>
          <tr><td>Expires</td><td>{wd.get('expiration_date','—')}</td></tr>
          <tr><td>Country</td><td>{wd.get('registrant_country','—')}</td></tr>
          <tr><td>DNSSEC</td><td>{wd.get('dnssec','—')}</td></tr>
          <tr><td>Name Servers</td><td>{'<br>'.join(wd.get('name_servers',[]))}</td></tr>
        """
        sections_html += _section("WHOIS", "📋", f"<table><tr><th>Field</th><th>Value</th></tr>{rows}</table>", "whois")
        nav_links += '<a href="#whois">WHOIS</a>'

    # ── IP Intel ─────────────────────────────────────────────
    ip_intel = data.get("ip_intel")
    if ip_intel:
        id2 = ip_intel if isinstance(ip_intel, dict) else _serialise(ip_intel)
        intel_content, intel_nav = _ip_intel_section(id2)
        sections_html += _section("IP & ASN Intelligence", "🌍", intel_content, "ip_intel")
        nav_links += intel_nav
        _collect_str_findings(id2.get("findings", []), "ip_intel")

    # ── Passive Sources ──────────────────────────────────────
    passive = data.get("passive")
    if passive:
        pd2 = passive if isinstance(passive, dict) else _serialise(passive)
        passive_content, passive_nav = _passive_section(pd2)
        sections_html += _section("Passive Intelligence", "🔭", passive_content, "passive")
        nav_links += passive_nav
        _collect_str_findings(pd2.get("findings", []), "passive")

    # ── Correlation / Asset Inventory ────────────────────────
    correlation = data.get("correlation")
    if correlation:
        corr_content, corr_nav = _correlation_section(correlation)
        sections_html += _section("Asset Correlation & Inventory", "🔗", corr_content, "correlation",
                                  collapsible=False)
        nav_links += corr_nav
        # Include correlated findings in all_findings
        c_d = correlation if isinstance(correlation, dict) else _serialise(correlation)
        for cf in c_d.get("correlated_findings", []):
            all_findings.append(cf)

    # ── Severity Summary (prepended, always shown) ───────────
    # Merge pre-scan structured findings (Finding dataclass objects)
    merged_findings: list = list(pre_findings) + [
        f for f in all_findings if not isinstance(f, dict) or "sev" not in f
    ]
    # Also keep dict-format findings from module parsing
    dict_findings = [f for f in all_findings if isinstance(f, dict) and "sev" in f]
    merged_findings = list(pre_findings) + dict_findings + [
        f for f in all_findings
        if not (isinstance(f, dict) and "sev" in f) and f not in pre_findings
    ]

    if merged_findings:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in merged_findings:
            if isinstance(f, dict) and "sev" in f:
                sev = f["sev"]
            elif hasattr(f, "severity"):
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            else:
                sev = "INFO"
            counts[sev] = counts.get(sev, 0) + 1

        # Severity cards
        for sev, col_class in [("CRITICAL", "critical"), ("HIGH", "high"), ("MEDIUM", "medium")]:
            if counts.get(sev, 0):
                cards.insert(0, ("findings", str(counts[sev]), f"{sev} Findings", col_class))

        chart_html = f'<div class="chart-box">{_severity_chart(counts)}</div>'
        findings_content = chart_html + "<br>" + _findings_html(merged_findings)
        sections_html = _section("Security Findings", "⚠️", findings_content, "findings") + sections_html
        nav_links = '<a href="#findings">⚠️ Findings</a>' + nav_links
    else:
        merged_findings = all_findings

    # ── Executive Summary (always first) ──────────────────────
    exec_html = _executive_summary(target, merged_findings, data)

    # ── Render ────────────────────────────────────────────────
    cards_html = "".join(
        f'<div class="card"><div class="card-number {col_class}">{num}</div>'
        f'<div class="card-label">{label}</div></div>'
        for _, num, label, col_class in cards
    )

    html = _HTML_TEMPLATE.format(
        target=target,
        generated_at=generated_at,
        version=__version__,
        nav_links=nav_links,
        summary_cards=cards_html,
        sections=exec_html + sections_html,
        style=_STYLE,
        js=_JS,
    )

    path.write_text(html)
    return str(path)
