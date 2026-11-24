from __future__ import annotations

from pathlib import Path

import httpx

from conftest import PUBLIC_IP, FakeResolver, req_host
from reconvigil.models import SEVERITY_RANK, Severity, TlsInfo
from reconvigil.scanner import ScanConfig, load_wordlist, run_scan
from reconvigil.storage.state_db import StateDB


def _world(*, include_ghost: bool) -> tuple[FakeResolver, httpx.MockTransport, httpx.MockTransport]:
    resolver = FakeResolver()
    resolver.add("target.com", PUBLIC_IP).add("www.target.com", PUBLIC_IP)
    resolver.add("target.com", "v=spf1 +all", rdtype="TXT")
    resolver.add("dangling.target.com", "bucket.s3.amazonaws.com", rdtype="CNAME")
    resolver.add("dangling.target.com", "52.216.0.1")
    resolver.add("internal.target.com", "10.9.9.9")
    names = ["www.target.com", "dangling.target.com", "internal.target.com", "evil.com"]
    if include_ghost:
        resolver.add("ghost.target.com", "8.8.4.4")
        names.append("ghost.target.com")

    seen_hosts: list[str] = []

    def web(request: httpx.Request) -> httpx.Response:
        host = req_host(request)
        seen_hosts.append(host)
        if host == "dangling.target.com":
            return httpx.Response(404, text="<Error><Code>NoSuchBucket</Code></Error>")
        if request.url.path == "/.git/HEAD":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text="ref: refs/heads/x"
            )
        if request.url.path == "/":
            return httpx.Response(200, text="<title>Site</title>")
        return httpx.Response(404, text="nf")

    def ct(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "crt.sh"
        return httpx.Response(200, json=[{"name_value": "\n".join(names)}])

    web_transport = httpx.MockTransport(web)
    web_transport.seen = seen_hosts  # type: ignore[attr-defined]
    return resolver, web_transport, httpx.MockTransport(ct)


async def _tls(host: str, ip: str) -> TlsInfo:
    return TlsInfo(subject=host, issuer="CA", days_remaining=100)


async def test_full_pipeline_and_drift_across_two_scans() -> None:
    results = []
    for ghost in (False, True):
        resolver, web, ct = _world(include_ghost=ghost)
        config = ScanConfig(target="target.com", words=["www"], concurrency=5)
        results.append(
            await run_scan(
                config, resolver=resolver, inner_transport=web, ct_transport=ct, tls_fetcher=_tls
            )
        )
        seen = web.seen  # type: ignore[attr-defined]
        assert "evil.com" not in seen and "internal.target.com" not in seen

    first, second = results
    ids = {(f.asset, f.rule_id) for f in first.findings}
    assert ("target.com", "spf-permissive-all") in ids
    assert ("target.com", "dmarc-missing") in ids
    assert ("dangling.target.com", "subdomain-takeover-aws-s3") in ids
    assert ("www.target.com", "exposed-git-head") in ids
    assert ("internal.target.com", "private-ip-resolution") in ids
    assert {a.host for a in first.assets} == {
        "target.com", "www.target.com", "dangling.target.com", "internal.target.com",
    }  # fmt: skip
    assert "evil.com" not in {a.host for a in first.assets}
    ranks = [SEVERITY_RANK[f.severity] for f in first.findings]
    assert ranks == sorted(ranks)  # most severe first
    top = first.findings[0]
    assert top.severity in (Severity.HIGH, Severity.CRITICAL)

    with StateDB(":memory:") as db:
        db.save_scan(first)
        drift = db.compute_drift(db.save_scan(second))
    assert drift.new_assets == ["ghost.target.com"]
    assert any(e.host == "ghost.target.com" for e in drift.new_endpoints)
    assert any(f.asset == "ghost.target.com" for f in drift.new_findings)
    assert drift.removed_assets == []


async def test_ct_outage_does_not_abort_scan() -> None:
    resolver, web, _ = _world(include_ghost=False)

    def dead(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("down", request=request)

    async def no_sleep(_: float) -> None:
        return None

    result = await run_scan(
        ScanConfig(target="target.com", words=["www"]),
        resolver=resolver, inner_transport=web, ct_transport=httpx.MockTransport(dead),
        tls_fetcher=_tls, sleep=no_sleep,
    )  # fmt: skip
    assert any("crt.sh" in w for w in result.warnings)
    assert "www.target.com" in {a.host for a in result.assets}  # still found via wordlist


def test_load_wordlist_skips_comments_and_blanks(tmp_path: Path) -> None:
    p = tmp_path / "w.txt"
    p.write_text("# c\n\nwww\n  dev  \n", encoding="utf-8")
    assert load_wordlist(p) == ["www", "dev"]
