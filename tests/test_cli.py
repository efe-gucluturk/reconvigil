from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import FakeResolver, LabServer
from reconvigil.cli import app

runner = CliRunner()
HTML = {"Content-Type": "text/html"}
TXT = {"Content-Type": "text/plain"}
GIT = (200, TXT, "ref: refs/heads/main\n")


@pytest.fixture
def lab(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[LabServer]:
    """Local HTTP server + fake DNS mapping target.test -> 127.0.0.1 (no network needed)."""
    resolver = FakeResolver().add("target.test", "127.0.0.1")
    monkeypatch.setattr("reconvigil.scanner.DnsPythonResolver", lambda: resolver)
    routes: dict[str, tuple[int, dict[str, str], str]] = {
        "/": (200, HTML, "<html><title>Lab Home</title></html>")
    }
    with LabServer(routes) as server:
        yield server


def scan_args(lab: LabServer, tmp_path: Path, *extra: str) -> list[str]:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("zzz-none\n", encoding="utf-8")
    return [
        "scan", "target.test", "--no-ct", "--allow-private",
        "--http-port", str(lab.port), "--https-port", str(lab.dead_port),
        "--timeout", "2", "--wordlist", str(wordlist),
        "--db", str(tmp_path / "state.db"), *extra,
    ]  # fmt: skip


# ----------------------------------------------------------------- scan
def test_scan_table_clean_exit_0_with_relaxed_threshold(lab: LabServer, tmp_path: Path) -> None:
    result = runner.invoke(app, scan_args(lab, tmp_path, "--fail-on", "critical"))
    assert result.exit_code == 0, result.output
    assert "Attack Surface Audit" in result.output and "target.test" in result.output
    assert "Lab Home" in result.output
    assert "Remediation" in result.output


def test_scan_exit_1_when_findings_meet_threshold(lab: LabServer, tmp_path: Path) -> None:
    lab.routes["/.git/HEAD"] = GIT
    result = runner.invoke(app, scan_args(lab, tmp_path))  # default --fail-on high
    assert result.exit_code == 1, result.output
    assert "exposed" in result.output.lower() or "Git repository" in result.output


def test_scan_fail_on_none_never_fails(lab: LabServer, tmp_path: Path) -> None:
    lab.routes["/.git/HEAD"] = GIT
    assert runner.invoke(app, scan_args(lab, tmp_path, "--fail-on", "none")).exit_code == 0


def test_scan_fail_on_medium_catches_missing_hsts_etc(lab: LabServer, tmp_path: Path) -> None:
    assert runner.invoke(app, scan_args(lab, tmp_path, "--fail-on", "medium")).exit_code == 1


def test_scan_json_stdout_is_pure_json(lab: LabServer, tmp_path: Path) -> None:
    result = runner.invoke(app, scan_args(lab, tmp_path, "--format", "json", "--fail-on", "none"))
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert doc["scan"]["target"] == "target.test" and doc["drift"]["baseline_scan_id"] is None
    assert doc["summary"]["assets"] == 1


@pytest.mark.parametrize(
    ("fmt", "marker"),
    [("json", '"summary"'), ("markdown", "## Executive Summary"), ("html", "<!DOCTYPE html>")],
)
def test_scan_output_file(lab: LabServer, tmp_path: Path, fmt: str, marker: str) -> None:
    out = tmp_path / f"report.{fmt}"
    result = runner.invoke(
        app, scan_args(lab, tmp_path, "--format", fmt, "--output", str(out), "--fail-on", "none")
    )
    assert result.exit_code == 0, result.output
    assert marker in out.read_text(encoding="utf-8")


def test_scan_input_errors_exit_2(lab: LabServer, tmp_path: Path) -> None:
    base = scan_args(lab, tmp_path)
    bad_db = tmp_path / "notadb.db"
    bad_db.write_text("precious data", encoding="utf-8")
    cases = {
        "table+output": [*base, "--output", str(tmp_path / "r.txt")],
        "non-sqlite db": [*base[:-2], "--db", str(bad_db)],
        "output==db": [*base, "--format", "json", "--output", str(tmp_path / "state.db")],
        "output is dir": [*base, "--format", "json", "--output", str(tmp_path)],
        "missing parent": [*base, "--format", "json", "--output", str(tmp_path / "x" / "r.json")],
        "missing wordlist": [*base, "--wordlist", str(tmp_path / "nope.txt")],
        "out-of-scope seed": [*base, "--seed", "evil.com"],
        "concurrency too high": [*base, "--concurrency", "51"],
        "concurrency zero": [*base, "--concurrency", "0"],
        "bad fail-on": [*base, "--fail-on", "urgent"],
        "bad format": [*base, "--format", "pdf"],
        "timeout zero": [*base, "--timeout", "0"],
    }
    for name, args in cases.items():
        assert runner.invoke(app, args).exit_code == 2, name
    assert bad_db.read_text(encoding="utf-8") == "precious data"


@pytest.mark.parametrize(
    "bad", ["http://user:pw@target.test", "target.test/../x", "127.0.0.1", "x"]
)
def test_scan_malformed_target_exit_2(bad: str, tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", bad, "--db", str(tmp_path / "s.db")])
    assert result.exit_code == 2


def test_scan_private_target_blocked_without_allow_private(lab: LabServer, tmp_path: Path) -> None:
    args = [a for a in scan_args(lab, tmp_path, "--fail-on", "none") if a != "--allow-private"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "private-ip" in result.output.lower() or "private/reserved" in result.output
    assert "Lab Home" not in result.output  # never fetched


# ----------------------------------------------------------------- diff / history
def test_diff_and_history_across_two_scans(lab: LabServer, tmp_path: Path) -> None:
    db = ["--db", str(tmp_path / "state.db")]
    assert runner.invoke(app, scan_args(lab, tmp_path, "--fail-on", "none")).exit_code == 0
    lab.routes["/.git/HEAD"] = GIT
    assert runner.invoke(app, scan_args(lab, tmp_path, "--fail-on", "none")).exit_code == 0

    diff = runner.invoke(app, ["diff", "target.test", *db])
    assert diff.exit_code == 0, diff.output
    assert "New endpoints" in diff.output and ".git/HEAD" in diff.output
    assert "New findings" in diff.output

    hist = runner.invoke(app, ["history", "target.test", *db])
    assert hist.exit_code == 0, hist.output
    assert "Scan history" in hist.output
    assert hist.output.count("2026-") == 2  # one row per snapshot


def test_diff_history_errors_exit_2(tmp_path: Path) -> None:
    missing = ["--db", str(tmp_path / "none.db")]
    for cmd in ("diff", "history"):
        assert runner.invoke(app, [cmd, "target.test", *missing]).exit_code == 2
        assert runner.invoke(app, [cmd, "not a domain", *missing]).exit_code == 2
    # existing database but unknown domain
    from reconvigil.storage.state_db import StateDB

    StateDB(tmp_path / "empty.db").close()
    for cmd in ("diff", "history"):
        result = runner.invoke(app, [cmd, "target.test", "--db", str(tmp_path / "empty.db")])
        assert result.exit_code == 2 and "no scans" in result.output


# ----------------------------------------------------------------- rules / misc
def test_rules_command() -> None:
    result = runner.invoke(app, ["rules"], env={"COLUMNS": "300"})
    assert result.exit_code == 0
    for needle in ("AWS S3", "GitHub Pages", "Fastly", "/.env", "/.git/HEAD", "CWE-538",
                   "hdr-hsts-missing", "cors-wildcard-credentials", "tls-expired"):  # fmt: skip
        assert needle in result.output, needle


def test_help_and_version() -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0
    for cmd in ("scan", "diff", "history", "rules"):
        assert cmd in runner.invoke(app, ["--help"]).output
    assert "reconvigil" in runner.invoke(app, ["version"]).output
