"""Markdown executive + technical audit report. Untrusted data is escaped."""

from __future__ import annotations

import re

from reconvigil.models import DriftReport, Severity
from reconvigil.reporters import ReportContext, clean

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&])")


def md_text(value: object) -> str:
    """Escape untrusted text for inline Markdown (also neutralizes raw HTML and table pipes)."""
    return _MD_SPECIAL.sub(r"\\\1", " ".join(clean(value).split()))


def md_code(value: object) -> str:
    """Untrusted text inside a code span (pipes escaped for tables, backticks neutralized)."""
    text = " ".join(clean(value).split()).replace("`", "'").replace("|", r"\|")
    return f"`{text}`" if text else ""


def render(ctx: ReportContext) -> str:
    r = ctx.result
    counts = ctx.severity_counts()
    out: list[str] = [
        f"# Attack Surface & Security Audit: {md_text(r.target)}",
        "",
        f"*Generated {ctx.when:%Y-%m-%d %H:%M UTC} by ReconVigil {md_text(ctx.tool_version)}"
        + (f", scan #{ctx.scan_id}" if ctx.scan_id is not None else "")
        + "*",
        "",
        "## Executive Summary",
        "",
        f"- **Assets discovered:** {len(r.assets)}",
        f"- **Findings:** {len(r.findings)}",
        "",
        "| Severity | Count |",
        "|---|---:|",
        *[f"| {sev.value} | {counts[sev]} |" for sev in Severity],
        "",
    ]
    top = [f for f in ctx.sorted_findings() if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if top:
        out += ["**Priority issues:**", ""]
        out += [
            f"- **{f.severity.value}** {md_code(f.asset)}: {md_text(f.title)}" for f in top[:10]
        ]
        out.append("")

    if ctx.drift is not None:
        out += _drift(ctx.drift)

    out += ["## Asset Inventory", "", "| Host | IPs | HTTP | Title | Server | TLS days left |"]
    out.append("|---|---|---|---|---|---:|")
    for a in r.assets:
        p = a.primary_http()
        days = a.tls.days_remaining if a.tls and a.tls.days_remaining is not None else "-"
        out.append(
            f"| {md_code(a.host)} | {md_code(', '.join(a.ips))} | {p.status if p else '-'} "
            f"| {md_text(p.title or '') if p else ''} | {md_text(p.server or '') if p else ''} "
            f"| {days} |"
        )
    out.append("")

    out += ["## Technical Findings", ""]
    if not r.findings:
        out += ["No findings.", ""]
    for i, f in enumerate(ctx.sorted_findings(), 1):
        out += [
            f"### {i}. [{f.severity.value}] {md_text(f.title)}",
            "",
            f"- **Asset:** {md_code(f.asset)}"
            + (f" &nbsp; **Location:** {md_code(f.location)}" if f.location else ""),
            f"- **Rule:** {md_code(f.rule_id)} &nbsp; **CWE:** {md_text(f.cwe)}",
            f"- **Description:** {md_text(f.description)}",
            f"- **Remediation:** {md_text(f.remediation)}",
            *([f"- **Evidence:** {md_code(f.evidence)}"] if f.evidence else []),
            "",
        ]
    if r.warnings:
        out += ["## Scan Warnings", "", *[f"- {md_text(w)}" for w in r.warnings], ""]
    return "\n".join(out)


def _drift(d: DriftReport) -> list[str]:
    out = ["## Attack Surface Drift", ""]
    if d.is_baseline:
        return [*out, "Baseline scan: no previous snapshot to compare.", ""]
    out.append(f"Compared with scan #{d.baseline_scan_id}.")
    out.append("")
    if not d.has_changes:
        return [*out, "No changes detected.", ""]
    sections = (
        ("New assets", [md_code(h) for h in d.new_assets]),
        ("Removed assets", [md_code(h) for h in d.removed_assets]),
        (
            "Changed IPs",
            [f"{md_code(c.host)}: {md_code(', '.join(c.old))} → {md_code(', '.join(c.new))}"
             for c in d.changed_ips],
        ),
        ("New endpoints", [md_code(e.url) for e in d.new_endpoints]),
        ("New findings", [f"**{f.severity.value}** {md_code(f.asset)}: {md_text(f.title)}"
                          for f in d.new_findings]),
        ("Resolved findings", [f"{md_code(f.asset)}: {md_text(f.title)}"
                               for f in d.resolved_findings]),
    )  # fmt: skip
    for label, items in sections:
        if items:
            out += [f"**{label}**", "", *[f"- {i}" for i in items], ""]
    return out
