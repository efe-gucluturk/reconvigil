"""Rich terminal summary. Target data is rendered via Text (never parsed as markup)."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reconvigil.models import SEVERITY_RANK, DriftReport, Finding, ScanSummary, Severity
from reconvigil.reporters import ReportContext, clean

SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _t(value: object, style: str = "") -> Text:
    return Text(clean(value), style=style)


def banner(console: Console, ctx: ReportContext) -> None:
    counts = ctx.severity_counts()
    line = Text()
    for sev in Severity:
        line.append(f" {sev.value}: {counts[sev]} ", style=SEV_STYLE[sev])
        line.append("  ")
    body = Text()
    body.append("Target: ", style="bold")
    body.append(clean(ctx.result.target))
    body.append(f"   Assets: {len(ctx.result.assets)}   Findings: {len(ctx.result.findings)}\n")
    body.append_text(line)
    worst = next((s for s in Severity if counts[s]), None)
    if worst is None or worst == Severity.INFO:
        colour = "green"
    elif SEVERITY_RANK[worst] <= SEVERITY_RANK[Severity.HIGH]:
        colour = "red"
    else:
        colour = "yellow"
    console.print(Panel(body, title="ReconVigil Attack Surface Audit", border_style=colour))


def drift_panel(console: Console, d: DriftReport) -> None:
    if d.is_baseline:
        console.print(
            Panel(
                "Baseline snapshot stored; no previous scan to compare.",
                title="Attack Surface Drift",
                border_style="blue",
            )
        )
        return
    body = Text()
    if not d.has_changes:
        body.append(f"No changes since scan #{d.baseline_scan_id}.")
    sections = (
        ("New assets", [(h, "green") for h in d.new_assets]),
        ("Removed assets", [(h, "red") for h in d.removed_assets]),
        (
            "Changed IPs",
            [
                (f"{c.host}: {', '.join(c.old)} -> {', '.join(c.new)}", "yellow")
                for c in d.changed_ips
            ],
        ),
        ("New endpoints", [(e.url, "green") for e in d.new_endpoints]),
        (
            "New findings",
            [
                (f"[{f.severity.value}] {f.asset}: {f.title}", SEV_STYLE[f.severity])
                for f in d.new_findings
            ],
        ),
        ("Resolved findings", [(f"{f.asset}: {f.title}", "green") for f in d.resolved_findings]),
    )
    for label, items in sections:
        if items:
            body.append(f"{label} ({len(items)})\n", style="bold")
            for text, style in items:
                body.append("  - ")
                body.append(clean(text) + "\n", style=style)
    console.print(
        Panel(
            body, title=f"Attack Surface Drift vs scan #{d.baseline_scan_id}", border_style="blue"
        )
    )


def render(console: Console, ctx: ReportContext) -> None:
    banner(console, ctx)
    for warning in ctx.result.warnings:
        console.print(Text("warn: " + clean(warning), style="yellow"))
    if ctx.drift is not None:
        drift_panel(console, ctx.drift)

    assets = Table(title="Asset inventory", expand=False)
    for col in ("Host", "IPs", "HTTP", "Title", "Server", "TLS days"):
        assets.add_column(col, overflow="fold")
    for a in ctx.result.assets:
        p = a.primary_http()
        days = a.tls.days_remaining if a.tls and a.tls.days_remaining is not None else "-"
        assets.add_row(
            _t(a.host),
            _t(", ".join(a.ips)),
            _t(p.status if p and p.status else "-"),
            _t((p.title or "") if p else ""),
            _t((p.server or "") if p else ""),
            _t(days),
        )
    console.print(assets)

    findings = ctx.sorted_findings()
    if not findings:
        console.print(Text("No findings.", style="green"))
        return
    table = Table(title="Findings (by severity)")
    for col in ("Severity", "CWE", "Asset", "Finding"):
        table.add_column(col, overflow="fold")
    for f in findings:
        title = _t(f.title)
        if f.location:
            title.append(f"  [{clean(f.location)}]", style="dim")
        table.add_row(_t(f.severity.value, SEV_STYLE[f.severity]), _t(f.cwe), _t(f.asset), title)
    console.print(table)

    console.print(Text("Remediation", style="bold underline"))
    hits: dict[str, set[str]] = {}
    first: dict[str, Finding] = {}
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        hits.setdefault(f.rule_id, set()).add(f.asset)
        first.setdefault(f.rule_id, f)
    for rule_id, hosts in hits.items():
        f = first[rule_id]
        line = Text()
        line.append(f"[{f.severity.value}] ", style=SEV_STYLE[f.severity])
        line.append(clean(f.title), style="bold")
        line.append(f" ({len(hosts)} asset(s))\n    -> {clean(f.remediation)}")
        console.print(line)


def history_table(console: Console, target: str, scans: list[ScanSummary]) -> None:
    table = Table(title=f"Scan history for {clean(target)}")
    for col in ("ID", "Started (UTC)", "Duration", "Assets", "Findings", "C", "H", "M", "L", "I"):
        table.add_column(col, justify="left" if col == "Started (UTC)" else "right")
    for s in scans:
        secs = int((s.finished_at - s.started_at).total_seconds())
        table.add_row(
            str(s.scan_id),
            f"{s.started_at:%Y-%m-%d %H:%M:%S}",
            f"{secs}s",
            str(s.assets),
            str(s.findings),
            *[str(s.severities.get(sev.value, 0)) for sev in Severity],
        )
    console.print(table)
