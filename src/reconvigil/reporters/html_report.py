"""Self-contained offline dark-mode HTML report.

Security model: every target-controlled value goes through `esc()` (control-char stripping +
`html.escape(quote=True)`); the page loads nothing external; a CSP meta tag allows only the
single inline script by SHA-256 hash and no inline event handlers exist.
"""

from __future__ import annotations

import base64
import hashlib
import html

from reconvigil.models import DriftReport, Severity
from reconvigil.reporters import ReportContext, clean


def esc(value: object) -> str:
    return html.escape(clean(value), quote=True)


_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e;
--critical:#ff4d6d;--high:#ff8a3d;--medium:#f2c94c;--low:#4cc3ff;--info:#8b949e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
h1{margin:0 0 4px;font-size:1.6rem}h2{margin:32px 0 12px;font-size:1.2rem;
border-bottom:1px solid var(--line);padding-bottom:6px}
.mut{color:var(--mut)}code{font-family:ui-monospace,Consolas,monospace;font-size:.9em;
background:#0b0f14;padding:1px 5px;border-radius:4px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-top:4px solid var(--c);
border-radius:8px;padding:12px;text-align:left;color:var(--fg);cursor:pointer;font:inherit}
.card .n{font-size:1.8rem;font-weight:700;color:var(--c)}
.card[aria-pressed=true]{outline:2px solid var(--c)}
.critical{--c:var(--critical)}.high{--c:var(--high)}.medium{--c:var(--medium)}
.low{--c:var(--low)}.info{--c:var(--info)}.all{--c:#a371f7}
.table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:8px;
overflow:hidden}
.table th,.table td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;
vertical-align:top;word-break:break-word}
.table th{color:var(--mut);font-weight:600;font-size:.85rem}
.scroll{overflow-x:auto}
.finding{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--c);
border-radius:8px;padding:12px 14px;margin:10px 0}
.finding[hidden]{display:none}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.75rem;
font-weight:700;color:#0d1117;background:var(--c)}
.drift li{margin:2px 0}
"""

_JS = """
(function(){
  var cards=document.querySelectorAll('[data-filter]');
  var items=document.querySelectorAll('.finding');
  function apply(sev){
    items.forEach(function(el){el.hidden=!(sev==='all'||el.getAttribute('data-sev')===sev);});
    cards.forEach(function(c){c.setAttribute('aria-pressed',
      String(c.getAttribute('data-filter')===sev));});
  }
  cards.forEach(function(c){c.addEventListener('click',function(){
    apply(c.getAttribute('data-filter'));});});
  apply('all');
})();
"""


def _drift_html(d: DriftReport) -> str:
    if d.is_baseline:
        return '<p class="mut">Baseline scan: no previous snapshot to compare.</p>'
    if not d.has_changes:
        return f'<p class="mut">No changes since scan #{d.baseline_scan_id}.</p>'
    groups = (
        ("New assets", [f"<code>{esc(h)}</code>" for h in d.new_assets]),
        ("Removed assets", [f"<code>{esc(h)}</code>" for h in d.removed_assets]),
        (
            "Changed IPs",
            [
                f"<code>{esc(c.host)}</code>: {esc(', '.join(c.old))} &rarr; "
                f"{esc(', '.join(c.new))}"
                for c in d.changed_ips
            ],
        ),
        ("New endpoints", [f"<code>{esc(e.url)}</code>" for e in d.new_endpoints]),
        (
            "New findings",
            [
                f"<b>{esc(f.severity.value)}</b> <code>{esc(f.asset)}</code> {esc(f.title)}"
                for f in d.new_findings
            ],
        ),
        (
            "Resolved findings",
            [f"<code>{esc(f.asset)}</code> {esc(f.title)}" for f in d.resolved_findings],
        ),
    )
    parts = [f'<p class="mut">Compared with scan #{d.baseline_scan_id}.</p>']
    for label, items in groups:
        if items:
            lis = "".join(f"<li>{i}</li>" for i in items)
            parts.append(f'<h3>{label} ({len(items)})</h3><ul class="drift">{lis}</ul>')
    return "\n".join(parts)


def render(ctx: ReportContext) -> str:
    r = ctx.result
    counts = ctx.severity_counts()
    cards = [
        '<button type="button" class="card all" data-filter="all" aria-pressed="true">'
        f'<div class="n">{len(r.findings)}</div>All findings</button>'
    ]
    for sev in Severity:
        cards.append(
            f'<button type="button" class="card {sev.value.lower()}" '
            f'data-filter="{sev.value.lower()}" aria-pressed="false">'
            f'<div class="n">{counts[sev]}</div>{sev.value.title()}</button>'
        )

    rows = []
    for a in r.assets:
        p = a.primary_http()
        tls = a.tls
        tls_txt = ""
        if tls:
            tls_txt = f"{esc(tls.subject or '')} / {esc(tls.issuer or '')}"
            if tls.days_remaining is not None:
                tls_txt += f" ({tls.days_remaining}d)"
            if tls.error:
                tls_txt += f" {esc(tls.error)}"
        rows.append(
            "<tr>"
            f"<td><code>{esc(a.host)}</code></td>"
            f"<td>{esc(', '.join(a.ips))}</td>"
            f"<td>{esc(', '.join(a.cnames))}</td>"
            f"<td>{esc(p.status) if p and p.status else '-'}</td>"
            f"<td>{esc(p.title or '') if p else ''}</td>"
            f"<td>{esc(p.server or '') if p else ''}</td>"
            f"<td>{tls_txt}</td></tr>"
        )

    findings = []
    for f in ctx.sorted_findings():
        sev = f.severity.value.lower()
        loc = f' <span class="mut">at</span> <code>{esc(f.location)}</code>' if f.location else ""
        ev = f"<p><b>Evidence:</b> <code>{esc(f.evidence)}</code></p>" if f.evidence else ""
        findings.append(
            f'<article class="finding {sev}" data-sev="{sev}">'
            f'<span class="badge">{esc(f.severity.value)}</span> <b>{esc(f.title)}</b>'
            f' <span class="mut">{esc(f.cwe)} &middot; {esc(f.rule_id)}</span>'
            f"<div><code>{esc(f.asset)}</code>{loc}</div>"
            f"<p>{esc(f.description)}</p>{ev}"
            f"<p><b>Remediation:</b> {esc(f.remediation)}</p></article>"
        )
    if not findings:
        findings.append('<p class="mut">No findings.</p>')

    warn = ""
    if r.warnings:
        items = "".join(f"<li>{esc(w)}</li>" for w in r.warnings)
        warn = f"<h2>Scan warnings</h2><ul>{items}</ul>"
    drift = _drift_html(ctx.drift) if ctx.drift else '<p class="mut">Drift not computed.</p>'
    scan_no = f" &middot; scan #{ctx.scan_id}" if ctx.scan_id is not None else ""

    digest = base64.b64encode(hashlib.sha256(_JS.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        f"script-src 'sha256-{digest}'; base-uri 'none'; form-action 'none'"
    )
    when = esc(f"{ctx.when:%Y-%m-%d %H:%M UTC}")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark">
<title>ReconVigil audit: {esc(r.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>Attack Surface &amp; Security Audit</h1>
<p class="mut"><code>{esc(r.target)}</code> &middot; {when}{scan_no}
 &middot; ReconVigil {esc(ctx.tool_version)} &middot; {len(r.assets)} assets</p>
<div class="cards">{"".join(cards)}</div>
<h2>Attack surface drift</h2>
{drift}
<h2>Asset inventory</h2>
<div class="scroll"><table class="table"><thead><tr><th>Host</th><th>IPs</th><th>CNAME</th>
<th>HTTP</th><th>Title</th><th>Server</th><th>TLS</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<h2>Findings</h2>
{"".join(findings)}
{warn}
</main>
<script>{_JS}</script>
</body>
</html>
"""
