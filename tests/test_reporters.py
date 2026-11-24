from __future__ import annotations

import base64
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from conftest import PUBLIC_IP, FakeResolver, LabServer, make_fetcher, make_scope
from reconvigil.cli import app
from reconvigil.models import (
    Asset,
    DriftReport,
    EndpointRef,
    Finding,
    HttpProbe,
    IPChange,
    ScanResult,
    Severity,
    TlsInfo,
)
from reconvigil.recon import web_prober
from reconvigil.reporters import (
    ReportContext,
    clean,
    html_report,
    json_report,
    markdown_report,
    meets_threshold,
    terminal,
)

XSS = "<script>alert(document.domain)</script>"
XSS_ESCAPED = "&lt;script&gt;alert(document.domain)&lt;/script&gt;"
NOW = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


def _finding(sev: Severity = Severity.HIGH, **kw: str) -> Finding:
    base = {
        "rule_id": "rule-x", "title": "Finding", "cwe": "CWE-200", "asset": "a.target.com",
        "description": "desc", "remediation": "fix it", "location": "", "evidence": "",
    }  # fmt: skip
    base.update(kw)
    return Finding(severity=sev, **base)


def _hostile_ctx() -> ReportContext:
    evil = '"><img src=x onerror=alert(1)>'
    asset = Asset(
        host="a.target.com",
        ips=["1.2.3.4"],
        cnames=[evil, XSS],
        http=[
            HttpProbe(
                url=f"https://a.target.com/{evil}", status=200, title=XSS, server=f"{XSS} 1.0"
            )
        ],
        tls=TlsInfo(subject=XSS, issuer=evil, days_remaining=10, error=XSS),
        endpoints=[f"https://a.target.com/{XSS}"],
    )
    findings = [
        _finding(Severity.CRITICAL, title=XSS, location=evil, evidence=f"Server: {XSS}"),
        _finding(
            Severity.LOW, rule_id="r2", title="ok | pipe `tick` [link](http://x)", evidence="a|b"
        ),
    ]
    result = ScanResult(
        target="target.com", started_at=NOW, finished_at=NOW, assets=[asset],
        findings=findings, warnings=[XSS],
    )  # fmt: skip
    drift = DriftReport(
        target="target.com", current_scan_id=2, baseline_scan_id=1,
        new_assets=[XSS], removed_assets=[evil],
        changed_ips=[IPChange(host=XSS, old=[evil], new=[XSS])],
        new_endpoints=[EndpointRef(host="a", url=XSS)],
        new_findings=[findings[0]], resolved_findings=[findings[1]],
    )  # fmt: skip
    return ReportContext(result=result, drift=drift, scan_id=2, generated_at=NOW)


# ------------------------------------------------------------------ HTML safety
def test_html_report_escapes_all_untrusted_fields() -> None:
    doc = html_report.render(_hostile_ctx())
    assert XSS not in doc
    assert "<img" not in doc
    assert XSS_ESCAPED in doc
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in doc
    # exactly one <script> element: our own, and no inline event handlers anywhere
    assert doc.count("<script") == 1
    assert not re.search(r"<[a-z][^>]*\son\w+\s*=", doc, re.IGNORECASE)


def test_html_report_is_self_contained_with_pinned_csp() -> None:
    doc = html_report.render(_hostile_ctx())
    assert not re.search(r"<link\b|@import|<iframe|<img|<object|<embed", doc)
    assert not re.search(r'\b(src|href)\s*=\s*["\']?(https?:)?//', doc)
    assert "cdn" not in doc.lower() and "googleapis" not in doc.lower()
    script = re.search(r"<script>(.*?)</script>", doc, re.DOTALL)
    assert script
    digest = base64.b64encode(hashlib.sha256(script.group(1).encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in doc
    assert "default-src 'none'" in doc
    for needle in ('data-filter="critical"', 'data-filter="info"', "Attack surface drift"):
        assert needle in doc


def test_html_filter_markup_has_card_per_severity_and_matching_findings() -> None:
    ctx = _hostile_ctx()
    doc = html_report.render(ctx)
    assert 'data-sev="critical"' in doc and 'data-sev="low"' in doc
    assert 'data-sev="high"' not in doc


def test_clean_strips_controls_ansi_and_bidi() -> None:
    assert clean("a\x1b[31mred\x00‮b​c\x7f") == "a[31mredbc"
    assert clean("tab\tnewline\n") == "tab\tnewline\n"


# ------------------------------------------------------------------ other reporters
def test_markdown_report_neutralizes_html_and_table_breakers() -> None:
    doc = markdown_report.render(_hostile_ctx())
    # raw HTML may only appear inside code spans, which Markdown renders literally
    outside_code = re.sub(r"`[^`\n]*`", "", doc)
    assert not re.search(r"(?<!\\)<(script|img)", outside_code)  # no unescaped tags
    assert "\\<script\\>" in doc  # titles (non-code text) are backslash-escaped
    assert "[link](http://x)" not in doc  # link syntax is escaped
    asset_rows = [ln for ln in doc.splitlines() if ln.startswith("| `a.target.com`")]
    assert len(asset_rows) == 1 and asset_rows[0].count("|") - asset_rows[0].count("\\|") == 7
    headings = (
        "# Attack Surface & Security Audit",
        "## Executive Summary",
        "## Attack Surface Drift",
        "## Asset Inventory",
        "## Technical Findings",
    )
    for heading in headings:
        assert heading in doc
    assert "**Remediation:** fix it" in doc


def test_json_report_roundtrip() -> None:
    doc = json.loads(json_report.render(_hostile_ctx()))
    assert doc["summary"]["severities"]["CRITICAL"] == 1
    assert doc["scan"]["assets"][0]["http"][0]["title"] == XSS  # data preserved, not mangled
    assert doc["drift"]["baseline_scan_id"] == 1 and doc["scan_id"] == 2
    assert doc["tool"]["name"] == "reconvigil"


def test_terminal_report_does_not_interpret_markup_or_ansi() -> None:
    ctx = _hostile_ctx()
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False)
    ev = _finding(
        Severity.MEDIUM, title="[red]boom[/red] \x1b[31mansi\x1b[0m", asset="b.target.com"
    )
    result = ctx.result.model_copy(update={"findings": [*ctx.result.findings, ev]})
    terminal.render(console, ReportContext(result=result, drift=ctx.drift, generated_at=NOW))
    out = buf.getvalue()
    assert "[red]boom[/red]" in out
    assert "\x1b" not in out
    assert "Attack Surface Drift" in out and "Remediation" in out and "fix it" in out


def test_meets_threshold() -> None:
    fs = [_finding(Severity.MEDIUM), _finding(Severity.INFO)]
    assert meets_threshold(fs, Severity.MEDIUM) and meets_threshold(fs, Severity.LOW)
    assert not meets_threshold(fs, Severity.HIGH)
    assert not meets_threshold(fs, None)
    assert not meets_threshold([], Severity.LOW)


# ------------------------------------------------------------------ adversarial E2E: Stored XSS
def test_e2e_malicious_target_cannot_inject_script_into_html_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resolver = FakeResolver().add("target.test", "127.0.0.1")
    monkeypatch.setattr("reconvigil.scanner.DnsPythonResolver", lambda: resolver)
    routes = {
        "/": (
            200,
            {"Content-Type": "text/html", "Server": f"{XSS} 1.0"},
            f"<html><head><title>{XSS}</title></head><body>{XSS}</body></html>",
        )
    }
    out = tmp_path / "report.html"
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("zzz\n", encoding="utf-8")
    with LabServer(routes) as lab:
        result = CliRunner().invoke(
            app,
            [
                "scan", "target.test", "--no-ct", "--allow-private", "--timeout", "2",
                "--http-port", str(lab.port), "--https-port", str(lab.dead_port),
                "--wordlist", str(wordlist), "--db", str(tmp_path / "s.db"),
                "--format", "html", "--output", str(out), "--fail-on", "none",
            ],
        )  # fmt: skip
    assert result.exit_code == 0, result.output
    doc = out.read_text(encoding="utf-8")
    assert XSS_ESCAPED in doc  # title + Server banner rendered as inert text
    assert "<script>alert(document.domain)</script>" not in doc
    assert doc.count("<script") == 1
    assert "server: " + XSS_ESCAPED in doc  # evidence snippet escaped as well


# ------------------------------------------------------------------ rule catalog consistency
def _ids(findings: list[Finding]) -> dict[str, Finding]:
    return {f.rule_id: f for f in findings}


async def test_posture_catalog_matches_emitted_findings() -> None:
    catalog = {r.id: r for r in web_prober.POSTURE_RULES}
    host = "www.target.com"

    def res(headers: dict[str, str]) -> web_prober.FetchResult:
        return web_prober.FetchResult(
            url=f"https://{host}/", status=200, headers=httpx.Headers(headers)
        )

    emitted: list[Finding] = []
    emitted += web_prober.grade_headers(
        host,
        res({
            "server": "nginx/1.2", "x-powered-by": "PHP/7.4", "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "content-security-policy": "script-src 'unsafe-inline'",
        }),
        https=True,
    )  # fmt: skip
    emitted += web_prober.grade_headers(
        host,
        res({"strict-transport-security": "max-age=10", "access-control-allow-origin": "*"}),
        https=True,
    )
    emitted += web_prober.grade_headers(
        host,
        res({
            "access-control-allow-origin": web_prober.CORS_PROBE_ORIGIN,
            "access-control-allow-credentials": "true",
        }),
        https=True,
    )  # fmt: skip
    for tls in (
        TlsInfo(expired=True),
        TlsInfo(self_signed=True),
        TlsInfo(hostname_mismatch=True, error="x"),
        TlsInfo(error="certificate verification failed: issuer"),
        TlsInfo(days_remaining=20, not_after=NOW),
    ):
        emitted += web_prober.tls_findings(host, tls)

    # transport-level findings come from probe_host
    def http_only(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("no", request=request)
        return httpx.Response(200, text="<html></html>")

    def both(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    async def tls(h: str, ip: str) -> TlsInfo:
        return TlsInfo(subject=h)

    for handler in (http_only, both):
        scope = make_scope(FakeResolver().add(host, PUBLIC_IP))
        async with make_fetcher(scope, handler) as fetcher:
            r = await web_prober.probe_host(host, scope, fetcher, [], tls_fetcher=tls)
        emitted += [f for f in r.findings if f.rule_id in ("no-https", "http-no-redirect")]

    found = _ids(emitted)
    assert set(found) == set(catalog), set(catalog) ^ set(found)
    for rule_id, finding in found.items():
        assert (finding.severity, finding.cwe) == (
            catalog[rule_id].severity,
            catalog[rule_id].cwe,
        ), rule_id
