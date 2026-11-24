from __future__ import annotations

import httpx
import pytest

from conftest import PUBLIC_IP, FakeResolver, make_fetcher, make_scope
from reconvigil.models import DnsRecords, Severity
from reconvigil.recon import dns_recon
from reconvigil.rules import load_takeover_rules


def ct_client(handler) -> httpx.AsyncClient:
    return dns_recon.make_ct_client(httpx.MockTransport(handler))


class Sleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


# ------------------------------------------------------------------ CT logs
async def test_ct_parses_filters_and_normalizes() -> None:
    payload = [
        {"name_value": "WWW.target.com\n*.target.com\napi.target.com"},
        {"name_value": "target.com"},
        {"name_value": "evil.com\ntarget.com.evil.com\neviltarget.com"},
        {"name_value": "admin@target.com\nbad host.target.com"},
        {"name_value": 12},
        "garbage",
    ]
    client = ct_client(lambda r: httpx.Response(200, json=payload))
    names, warnings = await dns_recon.fetch_ct_subdomains(client, make_scope(FakeResolver()))
    assert names == {"www.target.com", "api.target.com", "target.com"}
    assert warnings == []


async def test_ct_retries_then_succeeds() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(503)
        return httpx.Response(200, json=[{"name_value": "a.target.com"}])

    sleeper = Sleeper()
    names, warnings = await dns_recon.fetch_ct_subdomains(
        ct_client(handler), make_scope(FakeResolver()), sleep=sleeper
    )
    assert names == {"a.target.com"} and attempts == 3
    assert sleeper.calls == [1.5, 3.0]
    assert len(warnings) == 2


async def test_ct_timeouts_degrade_gracefully() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    sleeper = Sleeper()
    names, warnings = await dns_recon.fetch_ct_subdomains(
        ct_client(handler), make_scope(FakeResolver()), retries=3, sleep=sleeper
    )
    assert names == set()
    assert any("unavailable" in w for w in warnings)
    assert len(sleeper.calls) == 2


@pytest.mark.parametrize("body", [b"<html>rate limited</html>", b'{"not": "a list"}', b""])
async def test_ct_invalid_json_is_ignored(body: bytes) -> None:
    client = ct_client(lambda r: httpx.Response(200, content=body))
    names, warnings = await dns_recon.fetch_ct_subdomains(client, make_scope(FakeResolver()))
    assert names == set() and warnings


async def test_ct_non_retryable_status() -> None:
    names, warnings = await dns_recon.fetch_ct_subdomains(
        ct_client(lambda r: httpx.Response(404)), make_scope(FakeResolver())
    )
    assert names == set() and "404" in warnings[0]


# ------------------------------------------------------------------ discovery
def test_generate_candidates_is_deterministic_capped_and_valid() -> None:
    cands = dns_recon.generate_candidates(
        "target.com", ["www", "WWW", "bad label", "-x", "dev"], known=["api.target.com"]
    )
    assert "www.target.com" in cands and cands.count("www.target.com") == 1
    assert "dev-api.target.com" in cands and "api1.target.com" in cands
    assert not any("bad" in c or c.startswith("-") for c in cands)
    assert "api.target.com" not in cands
    assert len(dns_recon.generate_candidates("target.com", ["a", "b", "c"], max_candidates=2)) == 2


async def test_discover_merges_ct_and_bruteforce() -> None:
    resolver = (
        FakeResolver()
        .add("target.com", PUBLIC_IP)
        .add("api.target.com", PUBLIC_IP)
        .add("dev.target.com", "8.8.8.8")
        .add("dev-api.target.com", "8.8.4.4")
    )
    client = ct_client(lambda r: httpx.Response(200, json=[{"name_value": "api.target.com"}]))
    disc = await dns_recon.discover(
        make_scope(resolver), resolver, ct_client=client, words=["dev", "ghost"]
    )
    assert disc.hosts["api.target.com"] == {"ct"}
    assert disc.hosts["dev.target.com"] == {"bruteforce"}
    assert "dev-api.target.com" in disc.hosts  # permutation of a CT-found label
    assert "ghost.target.com" not in disc.hosts
    assert disc.hosts["target.com"] == {"root"}


async def test_wildcard_dns_filters_bruteforce_but_not_ct() -> None:
    resolver = FakeResolver().add("real.target.com", "5.5.5.5")
    resolver.wildcard = (".target.com", "1.1.1.1")
    client = ct_client(lambda r: httpx.Response(200, json=[{"name_value": "ctonly.target.com"}]))
    disc = await dns_recon.discover(
        make_scope(resolver), resolver, ct_client=client, words=["real", "ghost"]
    )
    assert "real.target.com" in disc.hosts  # distinct IP from wildcard
    assert "ghost.target.com" not in disc.hosts  # resolves only via wildcard
    assert "ctonly.target.com" in disc.hosts  # CT evidence trumps wildcard filter
    assert any("wildcard" in w for w in disc.warnings)


async def test_discover_rejects_out_of_scope_seed() -> None:
    from reconvigil.security.scope import ScopeError

    resolver = FakeResolver()
    with pytest.raises(ScopeError):
        await dns_recon.discover(
            make_scope(resolver), resolver, ct_client=None, words=[], seeds=["evil.com"]
        )


async def test_collect_records_follows_cname_chain_and_tolerates_errors() -> None:
    resolver = FakeResolver()
    resolver.add("a.target.com", "hop1.cdn.net", rdtype="CNAME")
    resolver.add("hop1.cdn.net", "hop2.cdn.net", rdtype="CNAME")
    resolver.add("a.target.com", "0 mail.target.com", rdtype="MX")
    resolver.failing.add(("a.target.com", "TXT"))
    rec = await dns_recon.collect_records(resolver, "a.target.com")
    assert rec.cname == ["hop1.cdn.net", "hop2.cdn.net"]
    assert rec.mx == ["0 mail.target.com"] and rec.errors


# ------------------------------------------------------------------ email posture
def _email_resolver(txt: list[str], dmarc: list[str]) -> FakeResolver:
    r = FakeResolver()
    for t in txt:
        r.add("target.com", t, rdtype="TXT")
    for d in dmarc:
        r.add("_dmarc.target.com", d, rdtype="TXT")
    return r


@pytest.mark.parametrize(
    ("txt", "dmarc", "expected"),
    [
        ([], [], {"spf-missing", "dmarc-missing"}),
        (["v=spf1 +all"], ["v=DMARC1; p=reject"], {"spf-permissive-all"}),
        (["v=spf1 all"], ["v=DMARC1; p=reject"], {"spf-permissive-all"}),
        (["v=spf1 include:x.net ?all"], ["v=DMARC1; p=reject"], {"spf-neutral-all"}),
        (["v=spf1 include:x.net ~all"], ["v=DMARC1; p=reject"], {"spf-softfail-all"}),
        (["v=spf1 mx"], ["v=DMARC1; p=reject"], {"spf-no-all"}),
        (["v=spf1 redirect=_spf.x.net"], ["v=DMARC1; p=reject"], set()),
        (["v=spf1 -all"], ["v=DMARC1; p=none; rua=mailto:a@b.c"], {"dmarc-policy-none"}),
        (["v=spf1 -all", "v=spf1 mx -all"], ["v=DMARC1; p=quarantine"], {"spf-multiple"}),
        (["v=spf1 -all", "google-site-verification=abc"], ["v=DMARC1; p=reject"], set()),
        (["v=spf1 -all"], ["v=DMARC1"], {"dmarc-policy-none"}),
    ],
)
async def test_email_posture(txt: list[str], dmarc: list[str], expected: set[str]) -> None:
    findings, _ = await dns_recon.audit_email_posture(_email_resolver(txt, dmarc), "target.com")
    assert {f.rule_id for f in findings} == expected
    for f in findings:
        assert f.cwe.startswith("CWE-") and f.remediation


async def test_email_severities() -> None:
    findings, _ = await dns_recon.audit_email_posture(
        _email_resolver(["v=spf1 +all"], []), "target.com"
    )
    sev = {f.rule_id: f.severity for f in findings}
    assert sev["spf-permissive-all"] == Severity.HIGH
    assert sev["dmarc-missing"] == Severity.MEDIUM


async def test_email_dns_failure_does_not_claim_missing() -> None:
    r = FakeResolver()
    r.failing.add(("target.com", "TXT"))
    findings, warnings = await dns_recon.audit_email_posture(r, "target.com")
    assert findings == [] and warnings


# ------------------------------------------------------------------ takeover
def test_takeover_rules_cover_required_services() -> None:
    services = {r.service for r in load_takeover_rules()}
    assert {
        "AWS S3", "GitHub Pages", "Heroku", "Netlify", "Vercel",
        "Azure App Service", "Shopify", "Fastly",
    } <= services  # fmt: skip


def _takeover_env(cname: str, status: int, body: str, *, ips: list[str] | None = None):
    host = "blog.target.com"
    resolver = FakeResolver().add(host, PUBLIC_IP)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url.scheme))
        return httpx.Response(status, text=body)

    rec = DnsRecords(host=host, a=[PUBLIC_IP] if ips is None else ips, cname=[cname])
    return host, rec, make_fetcher(make_scope(resolver), handler), calls


@pytest.mark.parametrize(
    ("cname", "status", "body", "rule"),
    [
        ("assets.s3.amazonaws.com", 404, "<Code>NoSuchBucket</Code>", "aws-s3"),
        ("assets.s3-website-us-east-1.amazonaws.com", 404, "NoSuchBucket", "aws-s3"),
        ("org.github.io", 404, "There isn't a GitHub Pages site here.", "github-pages"),
        ("app.herokuapp.com", 404, "<title>No such app</title>", "heroku"),
        ("site.netlify.app", 404, "Not Found - Request ID: 01H", "netlify"),
        ("proj.vercel.app", 404, "The deployment could not be found on Vercel.", "vercel"),
        ("app.azurewebsites.net", 404, "Error 404 - Web app not found.", "azure-app-service"),
        ("shop.myshopify.com", 404, "Sorry, this shop is currently unavailable.", "shopify"),
        ("x.global.ssl.fastly.net", 500, "Fastly error: unknown domain: blog.target.com", "fastly"),
    ],
)
async def test_takeover_detected(cname: str, status: int, body: str, rule: str) -> None:
    host, rec, fetcher, _ = _takeover_env(cname, status, body)
    async with fetcher:
        findings = await dns_recon.check_takeover(host, rec, fetcher, load_takeover_rules())
    assert [f.rule_id for f in findings] == [f"subdomain-takeover-{rule}"]
    f = findings[0]
    assert f.severity == Severity.HIGH and f.cwe == "CWE-672" and f.remediation
    assert cname in f.evidence


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (200, "<html>Welcome to my claimed bucket site</html>"),
        (404, "<html>Custom 404 page of a live site</html>"),
        (200, "NoSuchBucket mentioned in a blog post"),  # fingerprint but wrong status
    ],
)
async def test_takeover_not_flagged_for_live_services(status: int, body: str) -> None:
    host, rec, fetcher, _ = _takeover_env("assets.s3.amazonaws.com", status, body)
    async with fetcher:
        assert await dns_recon.check_takeover(host, rec, fetcher, load_takeover_rules()) == []


async def test_takeover_nxdomain_azure_without_http() -> None:
    host, rec, fetcher, calls = _takeover_env("gone.azurewebsites.net", 200, "", ips=[])
    async with fetcher:
        findings = await dns_recon.check_takeover(host, rec, fetcher, load_takeover_rules())
    assert [f.rule_id for f in findings] == ["subdomain-takeover-azure-app-service"]
    assert calls == []


async def test_dangling_unknown_cname_is_low() -> None:
    host, rec, fetcher, _ = _takeover_env("x.unknown-provider.net", 200, "", ips=[])
    async with fetcher:
        findings = await dns_recon.check_takeover(host, rec, fetcher, load_takeover_rules())
    assert [(f.rule_id, f.severity) for f in findings] == [("dangling-cname", Severity.LOW)]


async def test_no_cname_no_takeover_check() -> None:
    resolver = FakeResolver()
    fetcher = make_fetcher(make_scope(resolver), lambda r: httpx.Response(500))
    async with fetcher:
        rec = DnsRecords(host="a.target.com", a=[PUBLIC_IP])
        assert await dns_recon.check_takeover("a.target.com", rec, fetcher, []) == []
