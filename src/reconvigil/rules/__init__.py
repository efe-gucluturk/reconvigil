"""Rule loading: YAML via `yaml.safe_load`, validated with strict pydantic models."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import yaml
from pydantic import Field, field_validator

from reconvigil.models import Severity, SeverityField, StrictModel


class TakeoverRule(StrictModel):
    service: str
    cname_patterns: list[str]
    fingerprints: list[str]
    statuses: list[int] = Field(default_factory=list)
    nxdomain_takeover: bool = False

    @field_validator("cname_patterns")
    @classmethod
    def _compile(cls, value: list[str]) -> list[str]:
        for pattern in value:
            re.compile(pattern)
        return value

    def matches_cname(self, target: str) -> bool:
        return any(re.search(p, target, re.IGNORECASE) for p in self.cname_patterns)


class Escalation(StrictModel):
    regex: str
    severity: SeverityField


class ExposureRule(StrictModel):
    id: str
    path: str
    title: str
    severity: SeverityField
    cwe: str
    description: str
    remediation: str
    status: list[int] = Field(default_factory=lambda: [200])
    reject_html: bool = True
    must_match: str | None = None
    json_keys_any: list[str] = Field(default_factory=list)
    must_contain_any: list[str] = Field(default_factory=list)
    informational: bool = False
    redact: bool = False
    escalate: list[Escalation] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value.startswith("/") or ".." in value or "//" in value:
            raise ValueError("rule path must be absolute, without '..' or '//'")
        return value

    @field_validator("must_match")
    @classmethod
    def _regex(cls, value: str | None) -> str | None:
        if value is not None:
            re.compile(value)
        return value


def _load_yaml(name: str, override: Path | None) -> list[dict]:
    if override is not None:
        text = override.read_text(encoding="utf-8")
    else:
        text = (resources.files("reconvigil") / "rules" / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, list):
        raise ValueError(f"{name}: expected a YAML list of rules")
    return data


def load_takeover_rules(path: Path | None = None) -> list[TakeoverRule]:
    return [TakeoverRule.model_validate(r) for r in _load_yaml("takeover_fingerprints.yaml", path)]


def load_exposure_rules(path: Path | None = None) -> list[ExposureRule]:
    return [ExposureRule.model_validate(r) for r in _load_yaml("exposed_paths.yaml", path)]


__all__ = [
    "ExposureRule",
    "Severity",
    "TakeoverRule",
    "load_exposure_rules",
    "load_takeover_rules",
]
