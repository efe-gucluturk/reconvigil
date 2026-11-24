"""Structured JSON export."""

from __future__ import annotations

import json

from reconvigil.reporters import ReportContext


def render(ctx: ReportContext) -> str:
    doc = {
        "tool": {"name": "reconvigil", "version": ctx.tool_version},
        "generated_at": ctx.when.isoformat(),
        "scan_id": ctx.scan_id,
        "summary": {
            "target": ctx.result.target,
            "assets": len(ctx.result.assets),
            "findings": len(ctx.result.findings),
            "severities": {k.value: v for k, v in ctx.severity_counts().items()},
        },
        "scan": ctx.result.model_dump(mode="json"),
        "drift": ctx.drift.model_dump(mode="json") if ctx.drift else None,
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
