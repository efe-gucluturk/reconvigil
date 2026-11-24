"""Report renderers (terminal, JSON, Markdown, HTML) over a shared context.

All target-controlled strings (titles, banners, CNAMEs, TLS subjects, URLs, evidence) are
untrusted and must pass through `clean()` plus the renderer's own escaping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from reconvigil import __version__
from reconvigil.models import SEVERITY_RANK, DriftReport, Finding, ScanResult, Severity

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def clean(value: object) -> str:
    """Strip control chars (incl. ANSI ESC), zero-width and bidi-override characters."""
    return _CTRL_RE.sub("", str(value))


@dataclass(frozen=True)
class ReportContext:
    result: ScanResult
    drift: DriftReport | None = None
    scan_id: int | None = None
    generated_at: datetime | None = None
    tool_version: str = __version__

    @property
    def when(self) -> datetime:
        return self.generated_at or datetime.now(UTC)

    def severity_counts(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for f in self.result.findings:
            counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.result.findings,
            key=lambda f: (SEVERITY_RANK[f.severity], f.asset, f.rule_id, f.location),
        )


def meets_threshold(findings: list[Finding], threshold: Severity | None) -> bool:
    """True if any finding is at or above `threshold` (None disables the gate)."""
    if threshold is None:
        return False
    return any(SEVERITY_RANK[f.severity] <= SEVERITY_RANK[threshold] for f in findings)
