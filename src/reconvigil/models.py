"""Strict pydantic models shared across ReconVigil."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _coerce_severity(value: object) -> object:
    if isinstance(value, str) and not isinstance(value, Severity):
        return Severity(value.upper())
    return value


SeverityField = Annotated[Severity, BeforeValidator(_coerce_severity)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class Finding(StrictModel):
    rule_id: str
    title: str
    severity: SeverityField
    cwe: str = Field(pattern=r"^CWE-\d{1,5}$")
    asset: str
    location: str = ""
    description: str
    remediation: str
    evidence: str = ""
    category: str = "general"

    @field_validator("evidence")
    @classmethod
    def _cap_evidence(cls, value: str) -> str:
        return value if len(value) <= 1000 else value[:1000] + "…"

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}|{self.asset}|{self.location}"


class DnsRecords(StrictModel):
    host: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)  # full chain, first hop first
    mx: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        return sorted({*self.a, *self.aaaa})


class HttpProbe(StrictModel):
    url: str
    status: int | None = None
    title: str | None = None
    server: str | None = None
    final_url: str | None = None
    redirect_to: str | None = None
    truncated: bool = False
    error: str | None = None


class TlsInfo(StrictModel):
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = Field(default_factory=list)
    not_after: datetime | None = None
    days_remaining: int | None = None
    expired: bool = False
    self_signed: bool = False
    hostname_mismatch: bool = False
    error: str | None = None


class Asset(StrictModel):
    host: str
    ips: list[str] = Field(default_factory=list)
    cnames: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    http: list[HttpProbe] = Field(default_factory=list)
    tls: TlsInfo | None = None
    endpoints: list[str] = Field(default_factory=list)  # live service roots + exposed URLs

    def primary_http(self) -> HttpProbe | None:
        live = [p for p in self.http if p.status is not None]
        for probe in live:
            if probe.url.startswith("https://"):
                return probe
        return live[0] if live else None


class ScanResult(StrictModel):
    target: str
    started_at: datetime
    finished_at: datetime
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScanSummary(StrictModel):
    scan_id: int
    target: str
    started_at: datetime
    finished_at: datetime
    assets: int
    findings: int
    severities: dict[str, int] = Field(default_factory=dict)


class IPChange(StrictModel):
    host: str
    old: list[str]
    new: list[str]


class EndpointRef(StrictModel):
    host: str
    url: str


class DriftReport(StrictModel):
    target: str
    current_scan_id: int
    baseline_scan_id: int | None
    new_assets: list[str] = Field(default_factory=list)
    removed_assets: list[str] = Field(default_factory=list)
    changed_ips: list[IPChange] = Field(default_factory=list)
    new_endpoints: list[EndpointRef] = Field(default_factory=list)
    new_findings: list[Finding] = Field(default_factory=list)
    resolved_findings: list[Finding] = Field(default_factory=list)

    @property
    def is_baseline(self) -> bool:
        return self.baseline_scan_id is None

    @property
    def has_changes(self) -> bool:
        return any(
            (
                self.new_assets,
                self.removed_assets,
                self.changed_ips,
                self.new_endpoints,
                self.new_findings,
                self.resolved_findings,
            )
        )
