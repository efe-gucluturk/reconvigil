"""ReconVigil command line interface.

Exit codes: 0 = clean, 1 = findings at/above --fail-on threshold, 2 = scope/input error.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from reconvigil import __version__
from reconvigil.models import SEVERITY_RANK, Severity
from reconvigil.recon.dns_recon import TAKEOVER_CWE, TAKEOVER_REMEDIATION, TAKEOVER_SEVERITY
from reconvigil.recon.web_prober import POSTURE_RULES
from reconvigil.reporters import (
    ReportContext,
    clean,
    html_report,
    json_report,
    markdown_report,
    meets_threshold,
    terminal,
)
from reconvigil.rules import load_exposure_rules, load_takeover_rules
from reconvigil.scanner import ScanConfig, load_wordlist, run_scan
from reconvigil.security.safe_http import HttpLimits
from reconvigil.security.scope import ScopeError, normalize_hostname, normalize_root_domain
from reconvigil.storage.state_db import StateDB

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="ReconVigil: security-hardened attack surface management & recon engine. "
    "Only scan assets you are authorized to test.",
)
console = Console()
err = Console(stderr=True)

DEFAULT_DB = Path(".reconvigil.db")
SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_WORDLIST_BYTES = 10 * 1024 * 1024


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    markdown = "markdown"
    html = "html"


class FailOn(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


def _fail(message: str) -> NoReturn:
    err.print(Text("error: " + clean(message), style="red"))
    raise typer.Exit(2)


# ---------------------------------------------------------------- safe path handling
def _check_text(raw: Path, what: str) -> Path:
    text = str(raw)
    if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        _fail(f"{what}: path is empty or contains control characters")
    return raw.expanduser().resolve()


def _safe_db_path(raw: Path, *, must_exist: bool = False) -> Path:
    path = _check_text(raw, "--db")
    if path.is_dir():
        _fail(f"--db: {path} is a directory")
    if not path.parent.is_dir():
        _fail(f"--db: parent directory {path.parent} does not exist")
    if path.exists():
        try:
            with path.open("rb") as fh:
                head = fh.read(16)
        except OSError as exc:
            _fail(f"--db: cannot read {path}: {exc.strerror}")
        if head and head != SQLITE_MAGIC:
            _fail(f"--db: {path} exists but is not a SQLite database (refusing to touch it)")
    elif must_exist:
        _fail(f"--db: database {path} not found")
    return path


def _safe_output_path(raw: Path, db: Path) -> Path:
    path = _check_text(raw, "--output")
    if path.is_dir():
        _fail(f"--output: {path} is a directory")
    if not path.parent.is_dir():
        _fail(f"--output: parent directory {path.parent} does not exist")
    if path == db or path.suffix in (".db", ".sqlite", ".sqlite3"):
        _fail("--output must not overwrite a database file")
    return path


def _safe_wordlist(raw: Path) -> Path:
    path = _check_text(raw, "--wordlist")
    if not path.is_file():
        _fail(f"--wordlist: {path} is not a file")
    if path.stat().st_size > MAX_WORDLIST_BYTES:
        _fail("--wordlist: file larger than 10 MB")
    return path


def _emit(text: str) -> None:
    """Write a report to stdout as UTF-8 regardless of the console code page."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        sys.stdout.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()
    else:
        sys.stdout.write(text)


def _render_report(fmt: OutputFormat, ctx: ReportContext) -> str:
    if fmt == OutputFormat.json:
        return json_report.render(ctx)
    if fmt == OutputFormat.markdown:
        return markdown_report.render(ctx)
    return html_report.render(ctx)


# ---------------------------------------------------------------- commands
@app.command("version")
def version() -> None:
    """Print the ReconVigil version."""
    console.print(f"reconvigil {__version__}")


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Root domain, e.g. example.com")],
    db: Annotated[Path, typer.Option(help="SQLite state database")] = DEFAULT_DB,
    format: Annotated[OutputFormat, typer.Option(help="Report format")] = OutputFormat.table,
    output: Annotated[
        Path | None, typer.Option(help="Write the json/markdown/html report to this file")
    ] = None,
    fail_on: Annotated[
        FailOn, typer.Option(help="Exit 1 if any finding meets/exceeds this severity")
    ] = FailOn.high,
    concurrency: Annotated[int, typer.Option(min=1, max=50, help="Max concurrent requests")] = 10,
    timeout: Annotated[
        float, typer.Option(min=0.5, max=120.0, help="Connect/read timeout in seconds")
    ] = 8.0,
    wordlist: Annotated[Path | None, typer.Option(help="Custom subdomain wordlist")] = None,
    no_ct: Annotated[bool, typer.Option("--no-ct", help="Skip passive crt.sh lookup")] = False,
    allow_private: Annotated[
        bool, typer.Option("--allow-private", help="Lab only: allow localhost/RFC1918 targets")
    ] = False,
    seed: Annotated[list[str] | None, typer.Option(help="Extra in-scope seed host")] = None,
    http_port: Annotated[int, typer.Option(min=1, max=65535, help="HTTP port to probe")] = 80,
    https_port: Annotated[int, typer.Option(min=1, max=65535, help="HTTPS port to probe")] = 443,
    max_candidates: Annotated[
        int, typer.Option(min=0, max=10000, help="Cap on brute-force candidates")
    ] = 5000,
) -> None:
    """Discover the attack surface of DOMAIN, store a snapshot, and report drift."""
    try:
        root = normalize_root_domain(target)
        seeds = [normalize_hostname(s) for s in (seed or [])]
    except ScopeError as exc:
        _fail(str(exc))
    db_path = _safe_db_path(db)
    out_path = None
    if output is not None:
        if format == OutputFormat.table:
            _fail("--output requires --format json, markdown or html")
        out_path = _safe_output_path(output, db_path)
    words = None
    if wordlist is not None:
        try:
            words = load_wordlist(_safe_wordlist(wordlist))
        except OSError as exc:
            _fail(f"--wordlist: {exc.strerror}")

    if allow_private:
        err.print(Text("warning: private-IP blocking disabled (--allow-private)", style="yellow"))
    config = ScanConfig(
        target=root,
        seeds=seeds,
        words=words,
        use_ct=not no_ct,
        block_private_ips=not allow_private,
        concurrency=concurrency,
        max_candidates=max_candidates,
        http_port=http_port,
        https_port=https_port,
    )
    limits = HttpLimits(
        connect_timeout=timeout,
        read_timeout=timeout,
        total_timeout=timeout * 2.5,
        max_concurrent_requests=concurrency,
    )
    try:
        store = StateDB(db_path)
    except sqlite3.DatabaseError as exc:
        _fail(f"--db: cannot open database: {exc}")
    try:
        try:
            result = asyncio.run(run_scan(config, limits=limits))
        except ScopeError as exc:  # e.g. a seed outside the target scope
            _fail(str(exc))
        scan_id = store.save_scan(result)
        drift = store.compute_drift(scan_id)
    finally:
        store.close()

    ctx = ReportContext(result=result, drift=drift, scan_id=scan_id)
    if format == OutputFormat.table:
        terminal.render(console, ctx)
    elif out_path is not None:
        out_path.write_text(_render_report(format, ctx), encoding="utf-8")
        terminal.render(console, ctx)
        err.print(f"report written to {out_path}")
    else:
        _emit(_render_report(format, ctx))
        err.print(f"scan #{scan_id} stored in {db_path}")

    threshold = None if fail_on == FailOn.none else Severity(fail_on.value.upper())
    if meets_threshold(result.findings, threshold):
        raise typer.Exit(1)


@app.command()
def diff(
    domain: Annotated[str, typer.Argument(help="Root domain")],
    db: Annotated[Path, typer.Option(help="SQLite state database")] = DEFAULT_DB,
) -> None:
    """Show attack-surface drift between the two most recent snapshots."""
    try:
        root = normalize_root_domain(domain)
    except ScopeError as exc:
        _fail(str(exc))
    db_path = _safe_db_path(db, must_exist=True)
    with StateDB(db_path) as store:
        latest = store.latest_scan_id(root)
        if latest is None:
            _fail(f"no scans stored for {root}")
        drift = store.compute_drift(latest)
    terminal.drift_panel(console, drift)


@app.command()
def history(
    domain: Annotated[str, typer.Argument(help="Root domain")],
    db: Annotated[Path, typer.Option(help="SQLite state database")] = DEFAULT_DB,
) -> None:
    """List stored scan snapshots with asset counts and severity totals."""
    try:
        root = normalize_root_domain(domain)
    except ScopeError as exc:
        _fail(str(exc))
    db_path = _safe_db_path(db, must_exist=True)
    with StateDB(db_path) as store:
        scans = store.list_scans(root)
    if not scans:
        _fail(f"no scans stored for {root}")
    terminal.history_table(console, root, scans)


@app.command()
def rules() -> None:
    """Show built-in takeover fingerprints, exposed-path rules and header/TLS audit rules."""
    takeover = Table(title="Subdomain takeover fingerprints")
    for col in ("Service", "CNAME patterns", "Fingerprints", "Severity", "CWE", "Remediation"):
        takeover.add_column(col, overflow="fold")
    for r in load_takeover_rules():
        takeover.add_row(
            r.service,
            "\n".join(r.cname_patterns),
            "\n".join(r.fingerprints)
            + ("\n(NXDOMAIN also flagged)" if r.nxdomain_takeover else ""),
            TAKEOVER_SEVERITY.value,
            TAKEOVER_CWE,
            TAKEOVER_REMEDIATION,
        )
    console.print(takeover)

    exposed = Table(title="Exposed path rules")
    for col in ("ID", "Path", "Severity", "CWE", "Remediation"):
        exposed.add_column(col, overflow="fold")
    for e in load_exposure_rules():
        sev = e.severity.value
        top = min((x.severity for x in e.escalate), default=None, key=SEVERITY_RANK.__getitem__)
        if top is not None:
            sev += f" (up to {top.value})"
        exposed.add_row(e.id, e.path, sev, e.cwe, " ".join(e.remediation.split()))
    console.print(exposed)

    posture = Table(title="HTTP header / CORS / TLS audit rules")
    for col in ("ID", "Check", "Severity", "CWE", "Remediation"):
        posture.add_column(col, overflow="fold")
    for p in POSTURE_RULES:
        posture.add_row(p.id, p.title, p.severity.value, p.cwe, p.remediation)
    console.print(posture)


if __name__ == "__main__":
    app()
