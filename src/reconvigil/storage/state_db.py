"""SQLite (WAL) snapshot store and attack-surface drift computation. Parameterized SQL only."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from types import TracebackType

from reconvigil.models import (
    Asset,
    DriftReport,
    EndpointRef,
    Finding,
    IPChange,
    ScanResult,
    ScanSummary,
    Severity,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id);
CREATE TABLE IF NOT EXISTS assets (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    ips TEXT NOT NULL,
    http_status INTEGER,
    http_title TEXT,
    tls_not_after TEXT,
    detail_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, host)
);
CREATE TABLE IF NOT EXISTS endpoints (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    url TEXT NOT NULL,
    PRIMARY KEY (scan_id, url)
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    asset TEXT NOT NULL,
    location TEXT NOT NULL,
    severity TEXT NOT NULL,
    cwe TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    evidence TEXT NOT NULL,
    category TEXT NOT NULL,
    PRIMARY KEY (scan_id, fingerprint)
);
"""


class StateDB:
    def __init__(self, path: str | Path = "reconvigil.db") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)

    def __enter__(self) -> StateDB:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def journal_mode(self) -> str:
        return str(self._conn.execute("PRAGMA journal_mode").fetchone()[0])

    # -- writes -----------------------------------------------------------
    def save_scan(self, result: ScanResult) -> int:
        with self._conn:  # single transaction; rolls back on error
            cur = self._conn.execute(
                "INSERT INTO scans (target, started_at, finished_at) VALUES (?, ?, ?)",
                (result.target, result.started_at.isoformat(), result.finished_at.isoformat()),
            )
            scan_id = int(cur.lastrowid or 0)
            for asset in result.assets:
                probe = asset.primary_http()
                self._conn.execute(
                    "INSERT INTO assets (scan_id, host, ips, http_status, http_title,"
                    " tls_not_after, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        asset.host,
                        ",".join(sorted(asset.ips)),
                        probe.status if probe else None,
                        probe.title if probe else None,
                        asset.tls.not_after.isoformat()
                        if asset.tls and asset.tls.not_after
                        else None,
                        asset.model_dump_json(),
                    ),
                )
                self._conn.executemany(
                    "INSERT OR IGNORE INTO endpoints (scan_id, host, url) VALUES (?, ?, ?)",
                    [(scan_id, asset.host, url) for url in asset.endpoints],
                )
            self._conn.executemany(
                "INSERT OR REPLACE INTO findings (scan_id, fingerprint, rule_id, asset, location,"
                " severity, cwe, title, description, remediation, evidence, category)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        f.fingerprint,
                        f.rule_id,
                        f.asset,
                        f.location,
                        f.severity.value,
                        f.cwe,
                        f.title,
                        f.description,
                        f.remediation,
                        f.evidence,
                        f.category,
                    )
                    for f in result.findings
                ],
            )
        return scan_id

    # -- reads ------------------------------------------------------------
    def latest_scan_id(self, target: str, *, before: int | None = None) -> int | None:
        if before is None:
            row = self._conn.execute(
                "SELECT MAX(id) AS id FROM scans WHERE target = ?", (target,)
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT MAX(id) AS id FROM scans WHERE target = ? AND id < ?", (target, before)
            ).fetchone()
        return int(row["id"]) if row and row["id"] is not None else None

    def list_scans(self, target: str) -> list[ScanSummary]:
        """Snapshots of `target`, oldest first, with asset counts and severity totals."""
        rows = self._conn.execute(
            "SELECT s.id, s.target, s.started_at, s.finished_at,"
            " (SELECT COUNT(*) FROM assets a WHERE a.scan_id = s.id) AS n_assets"
            " FROM scans s WHERE s.target = ? ORDER BY s.id",
            (target,),
        ).fetchall()
        out: list[ScanSummary] = []
        for r in rows:
            sev = {
                str(x["severity"]): int(x["n"])
                for x in self._conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ?"
                    " GROUP BY severity",
                    (r["id"],),
                )
            }
            out.append(
                ScanSummary(
                    scan_id=r["id"],
                    target=r["target"],
                    started_at=datetime.fromisoformat(r["started_at"]),
                    finished_at=datetime.fromisoformat(r["finished_at"]),
                    assets=r["n_assets"],
                    findings=sum(sev.values()),
                    severities=sev,
                )
            )
        return out

    def scan_target(self, scan_id: int) -> str:
        row = self._conn.execute("SELECT target FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown scan id {scan_id}")
        return str(row["target"])

    def load_assets(self, scan_id: int) -> list[Asset]:
        rows = self._conn.execute(
            "SELECT detail_json FROM assets WHERE scan_id = ? ORDER BY host", (scan_id,)
        ).fetchall()
        return [Asset.model_validate_json(r["detail_json"]) for r in rows]

    def load_findings(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY fingerprint", (scan_id,)
        ).fetchall()
        return [
            Finding(
                rule_id=r["rule_id"],
                title=r["title"],
                severity=Severity(r["severity"]),
                cwe=r["cwe"],
                asset=r["asset"],
                location=r["location"],
                description=r["description"],
                remediation=r["remediation"],
                evidence=r["evidence"],
                category=r["category"],
            )
            for r in rows
        ]

    # -- drift ------------------------------------------------------------
    def compute_drift(self, scan_id: int, *, baseline_id: int | None = None) -> DriftReport:
        """Diff `scan_id` against the previous scan of the same target (or `baseline_id`)."""
        target = self.scan_target(scan_id)
        if baseline_id is None:
            baseline_id = self.latest_scan_id(target, before=scan_id)
        report = DriftReport(target=target, current_scan_id=scan_id, baseline_scan_id=baseline_id)
        if baseline_id is None:
            return report

        cur = {a.host: a for a in self.load_assets(scan_id)}
        old = {a.host: a for a in self.load_assets(baseline_id)}
        report.new_assets = sorted(cur.keys() - old.keys())
        report.removed_assets = sorted(old.keys() - cur.keys())
        for host in sorted(cur.keys() & old.keys()):
            if sorted(cur[host].ips) != sorted(old[host].ips):
                report.changed_ips.append(
                    IPChange(host=host, old=sorted(old[host].ips), new=sorted(cur[host].ips))
                )
        old_endpoints = {url for a in old.values() for url in a.endpoints}
        report.new_endpoints = [
            EndpointRef(host=host, url=url)
            for host, asset in sorted(cur.items())
            for url in sorted(asset.endpoints)
            if url not in old_endpoints
        ]
        cur_f = {f.fingerprint: f for f in self.load_findings(scan_id)}
        old_f = {f.fingerprint: f for f in self.load_findings(baseline_id)}
        report.new_findings = [cur_f[k] for k in sorted(cur_f.keys() - old_f.keys())]
        report.resolved_findings = [old_f[k] for k in sorted(old_f.keys() - cur_f.keys())]
        return report
