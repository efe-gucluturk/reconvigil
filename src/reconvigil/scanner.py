"""Scan pipeline: discovery -> DNS records -> takeover/email audit -> web probing."""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import Field

from reconvigil.dnsio import DnsPythonResolver, Resolver
from reconvigil.models import SEVERITY_RANK, Asset, Finding, ScanResult, StrictModel
from reconvigil.recon import dns_recon, web_prober
from reconvigil.rules import load_exposure_rules, load_takeover_rules
from reconvigil.security.safe_http import GuardedFetcher, HttpLimits
from reconvigil.security.scope import DEFAULT_PORTS, TargetScope

MAX_WORDLIST_LINES = 100_000


class ScanConfig(StrictModel):
    target: str
    seeds: list[str] = Field(default_factory=list)
    words: list[str] | None = None  # None -> built-in list
    use_ct: bool = True
    block_private_ips: bool = True
    concurrency: int = Field(default=20, ge=1, le=50)
    max_candidates: int = Field(default=5000, ge=0, le=10_000)
    allowed_ports: list[int] | None = None  # None -> DEFAULT_PORTS
    http_port: int = Field(default=80, ge=1, le=65535)
    https_port: int = Field(default=443, ge=1, le=65535)


def load_wordlist(path: Path) -> list[str]:
    words: list[str] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= MAX_WORDLIST_LINES:
                break
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


async def run_scan(
    config: ScanConfig,
    *,
    resolver: Resolver | None = None,
    inner_transport: httpx.AsyncBaseTransport | None = None,
    ct_transport: httpx.AsyncBaseTransport | None = None,
    tls_fetcher: web_prober.TlsFetcher = web_prober.fetch_tls_info,
    limits: HttpLimits | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> ScanResult:
    started = datetime.now(UTC)
    resolver = resolver or DnsPythonResolver()
    ports = (frozenset(config.allowed_ports) if config.allowed_ports else DEFAULT_PORTS) | {
        config.http_port,
        config.https_port,
    }
    if config.https_port != 443 and tls_fetcher is web_prober.fetch_tls_info:
        tls_fetcher = functools.partial(web_prober.fetch_tls_info, port=config.https_port)
    scope = TargetScope(
        config.target,
        resolver=resolver,
        block_private_ips=config.block_private_ips,
        allowed_ports=ports,
    )
    limits = limits or HttpLimits(max_concurrent_requests=config.concurrency)
    takeover_rules = load_takeover_rules()
    exposure_rules = load_exposure_rules()
    findings: list[Finding] = []
    warnings: list[str] = []

    ct_client = dns_recon.make_ct_client(ct_transport) if config.use_ct else None
    try:
        disc = await dns_recon.discover(
            scope,
            resolver,
            ct_client=ct_client,
            words=config.words,
            seeds=config.seeds,
            concurrency=config.concurrency,
            max_candidates=config.max_candidates,
            sleep=sleep,
        )
    finally:
        if ct_client is not None:
            await ct_client.aclose()
    warnings.extend(disc.warnings)

    email_findings, email_warn = await dns_recon.audit_email_posture(resolver, scope.root)
    findings.extend(email_findings)
    warnings.extend(email_warn)

    host_sem = asyncio.Semaphore(config.concurrency)
    assets: list[Asset] = []

    async with GuardedFetcher(scope, limits, inner_transport=inner_transport) as fetcher:

        async def process(host: str) -> None:
            async with host_sem:
                rec = disc.records[host]
                extra = await dns_recon.collect_records(resolver, host, ("MX", "TXT"))
                rec.mx, rec.txt = extra.mx, extra.txt
                asset = Asset(
                    host=host, ips=rec.ips, cnames=rec.cname, sources=sorted(disc.hosts[host])
                )
                host_findings = await dns_recon.check_takeover(host, rec, fetcher, takeover_rules)
                if rec.ips:
                    web = await web_prober.probe_host(
                        host,
                        scope,
                        fetcher,
                        exposure_rules,
                        tls_fetcher=tls_fetcher,
                        http_port=config.http_port,
                        https_port=config.https_port,
                    )
                    asset.http, asset.tls, asset.endpoints = web.http, web.tls, web.endpoints
                    host_findings.extend(web.findings)
                assets.append(asset)
                findings.extend(host_findings)

        await asyncio.gather(*(process(h) for h in sorted(disc.records)))

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.asset, f.rule_id, f.location))
    assets.sort(key=lambda a: a.host)
    result = ScanResult(
        target=scope.root,
        started_at=started,
        finished_at=datetime.now(UTC),
        assets=assets,
        findings=findings,
        warnings=warnings,
    )
    return result
