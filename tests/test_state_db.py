from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from reconvigil.models import Asset, Finding, HttpProbe, ScanResult, Severity, TlsInfo
from reconvigil.storage.state_db import StateDB

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def finding(rule: str, asset: str, loc: str = "", sev: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule, title=f"title {rule}", severity=sev, cwe="CWE-200", asset=asset,
        location=loc, description="d", remediation="r", evidence="e",
    )  # fmt: skip


def asset(
    host: str, ips: list[str], endpoints: list[str] | None = None, status: int = 200
) -> Asset:
    return Asset(
        host=host, ips=ips, sources=["ct"], endpoints=endpoints or [],
        http=[HttpProbe(url=f"https://{host}/", status=status, title=f"{host} home")],
        tls=TlsInfo(not_after=T0 + timedelta(days=90), days_remaining=90),
    )  # fmt: skip


def scan(target: str, assets: list[Asset], findings: list[Finding], day: int = 0) -> ScanResult:
    return ScanResult(
        target=target,
        started_at=T0 + timedelta(days=day),
        finished_at=T0 + timedelta(days=day, minutes=1),
        assets=assets,
        findings=findings,
    )


def test_drift_between_two_consecutive_scans(tmp_path: Path) -> None:
    f_old = finding("hdr-hsts-missing", "a.target.com")
    f_kept = finding("spf-missing", "target.com")
    first = scan(
        "target.com",
        [
            asset("a.target.com", ["1.1.1.1"], ["https://a.target.com/"]),
            asset("b.target.com", ["2.2.2.2"], ["https://b.target.com/"]),
            asset("c.target.com", ["3.3.3.3"], ["https://c.target.com/"]),
        ],
        [f_old, f_kept],
    )
    f_new = finding("exposed-git-head", "d.target.com", "/.git/HEAD", Severity.HIGH)
    second = scan(
        "target.com",
        [
            asset("a.target.com", ["1.1.1.1"], ["https://a.target.com/"]),
            asset("c.target.com", ["3.3.3.9", "3.3.3.8"], ["https://c.target.com/", "https://c.target.com/.env"]),
            asset("d.target.com", ["4.4.4.4"], ["https://d.target.com/", "https://d.target.com/.git/HEAD"]),
        ],
        [f_kept, f_new],
        day=1,
    )  # fmt: skip
    with StateDB(tmp_path / "state.db") as db:
        assert db.journal_mode() == "wal"
        id1 = db.save_scan(first)
        baseline = db.compute_drift(id1)
        assert baseline.is_baseline and not baseline.has_changes
        id2 = db.save_scan(second)
        drift = db.compute_drift(id2)

    assert drift.baseline_scan_id == id1 and drift.current_scan_id == id2
    assert drift.new_assets == ["d.target.com"]
    assert drift.removed_assets == ["b.target.com"]
    assert [(c.host, c.old, c.new) for c in drift.changed_ips] == [
        ("c.target.com", ["3.3.3.3"], ["3.3.3.8", "3.3.3.9"])
    ]
    assert {e.url for e in drift.new_endpoints} == {
        "https://c.target.com/.env",
        "https://d.target.com/",
        "https://d.target.com/.git/HEAD",
    }
    assert [f.rule_id for f in drift.new_findings] == ["exposed-git-head"]
    assert drift.new_findings[0].severity == Severity.HIGH
    assert [f.rule_id for f in drift.resolved_findings] == ["hdr-hsts-missing"]
    assert drift.has_changes


def test_identical_scans_have_no_drift() -> None:
    result = scan("target.com", [asset("a.target.com", ["1.1.1.1"], ["https://a.target.com/"])], [])
    with StateDB(":memory:") as db:
        db.save_scan(result)
        second = db.save_scan(result)
        assert not db.compute_drift(second).has_changes


def test_baseline_is_per_target() -> None:
    with StateDB(":memory:") as db:
        db.save_scan(scan("target.com", [asset("a.target.com", ["1.1.1.1"])], []))
        db.save_scan(scan("other.org", [asset("x.other.org", ["9.9.9.9"])], []))
        third = db.save_scan(scan("target.com", [asset("a.target.com", ["1.1.1.2"])], []))
        drift = db.compute_drift(third)
        assert drift.target == "target.com" and drift.baseline_scan_id == 1
        assert drift.new_assets == [] and drift.removed_assets == []
        assert [c.host for c in drift.changed_ips] == ["a.target.com"]
        assert db.latest_scan_id("other.org") == 2 and db.latest_scan_id("nope.com") is None


def test_roundtrip_and_sql_injection_safe() -> None:
    nasty = "x'); DROP TABLE scans;--.target.com"
    f = finding("rule", nasty, "/'; DROP TABLE findings;--")
    a = asset(nasty, ["1.1.1.1"], [f"https://{nasty}/"])
    with StateDB(":memory:") as db:
        sid = db.save_scan(scan("target.com", [a], [f]))
        assets = db.load_assets(sid)
        assert assets[0].host == nasty and assets[0].http[0].status == 200
        assert assets[0].tls is not None and assets[0].tls.days_remaining == 90
        loaded = db.load_findings(sid)
        assert loaded == [f]
        assert db.latest_scan_id("target.com") == sid  # tables intact
