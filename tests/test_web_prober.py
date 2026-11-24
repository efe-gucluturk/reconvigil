from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from conftest import PUBLIC_IP, FakeResolver, make_fetcher, make_scope, req_host
from reconvigil.models import Severity, TlsInfo
from reconvigil.recon import web_prober
from reconvigil.rules import load_exposure_rules

HOST = "www.target.com"
RULES = load_exposure_rules()


def _env(handler):
    resolver = FakeResolver().add(HOST, PUBLIC_IP)
    scope = make_scope(resolver)
    return scope, make_fetcher(scope, handler)


async def _audit(handler) -> tuple[dict[str, object], list[str]]:
    _, fetcher = _env(handler)
    async with fetcher:
        findings, urls = await web_prober.audit_exposed_paths(
            HOST, f"https://{HOST}", fetcher, RULES
        )
    return {f.rule_id: f for f in findings}, urls


# ------------------------------------------------------------- soft-404 suppression
async def test_soft_404_html_for_everything_yields_no_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><title>Home</title>Welcome</html>",
        )

    by_id, urls = await _audit(handler)
    assert by_id == {} and urls == []


async def test_soft_404_plain_text_identical_to_baseline_suppressed() -> None:
    # Body would satisfy the .env regex, but it is the site's catch-all page.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/plain"}, text="APP_NAME=catchall\n"
        )

    by_id, _ = await _audit(handler)
    assert "exposed-dotenv" not in by_id


@pytest.mark.parametrize("path", ["/.env", "/.git/HEAD"])
async def test_html_masquerading_as_secret_file_rejected(path: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == path:
            # Even a 200 with HTML and no content-type must not count.
            return httpx.Response(
                200, text="<!DOCTYPE html><html>ref: refs/heads/main FOO=bar</html>"
            )
        return httpx.Response(404, text="nope")

    by_id, _ = await _audit(handler)
    assert by_id == {}


async def test_spa_json_for_every_path_does_not_trigger_git_or_env() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"app": "spa", "route": request.url.path})

    by_id, _ = await _audit(handler)
    assert "exposed-git-head" not in by_id and "exposed-dotenv" not in by_id


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
async def test_non_200_on_sensitive_paths_ignored(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"location": "/login"}, text="ref: refs/heads/main")

    by_id, _ = await _audit(handler)
    assert by_id == {}


# ------------------------------------------------------------- true positives
async def test_real_git_head_and_env_detected() -> None:
    files = {
        "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
        "/.env": ("text/plain", "APP_ENV=prod\nDB_PASSWORD=hunter2hunter2\nDEBUG=false\n"),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        hit = files.get(request.url.path)
        if hit:
            return httpx.Response(200, headers={"content-type": hit[0]}, text=hit[1])
        return httpx.Response(404, text="Not Found")

    by_id, urls = await _audit(handler)
    git, env = by_id["exposed-git-head"], by_id["exposed-dotenv"]
    assert git.severity == Severity.HIGH and git.cwe == "CWE-538" and git.remediation
    assert env.severity == Severity.CRITICAL and env.cwe == "CWE-540"
    assert "DB_PASSWORD" in env.evidence and "hunter2" not in env.evidence  # values redacted
    assert f"https://{HOST}/.env" in urls and f"https://{HOST}/.git/HEAD" in urls


async def test_env_without_secret_keys_is_high_not_critical() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.env":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text="APP_ENV=prod\n"
            )
        return httpx.Response(404, text="nf")

    by_id, _ = await _audit(handler)
    assert by_id["exposed-dotenv"].severity == Severity.HIGH


async def test_api_docs_actuator_robots_security_txt() -> None:
    spec = {"openapi": "3.0.0", "paths": {}}
    files = {
        "/swagger.json": httpx.Response(200, json={"swagger": "2.0"}),
        "/openapi.json": httpx.Response(200, json=spec),
        "/actuator/health": httpx.Response(200, json={"status": "UP"}),
        "/robots.txt": httpx.Response(
            200, headers={"content-type": "text/plain"}, text="User-agent: *\nDisallow: /admin\n"
        ),
        "/.well-known/security.txt": httpx.Response(
            200, headers={"content-type": "text/plain"}, text="Contact: mailto:sec@target.com\n"
        ),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return files.get(request.url.path, httpx.Response(404, text="nf"))

    by_id, _ = await _audit(handler)
    assert by_id["exposed-swagger-json"].severity == Severity.MEDIUM
    assert by_id["exposed-openapi-json"].cwe == "CWE-200"
    assert by_id["exposed-actuator-health"].severity == Severity.LOW
    assert "/admin" in by_id["robots-txt-present"].evidence
    assert by_id["security-txt-present"].severity == Severity.INFO


async def test_json_without_expected_keys_not_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/swagger.json", "/openapi.json", "/actuator/health"):
            return httpx.Response(200, json={"error": "not found", "status_text": "x"})
        return httpx.Response(404, text="nf")

    by_id, _ = await _audit(handler)
    assert by_id == {}


# ------------------------------------------------------------- header grading
def _res(headers: dict[str, str]) -> web_prober.FetchResult:
    return web_prober.FetchResult(
        url=f"https://{HOST}/",
        status=200,
        headers=httpx.Headers(headers),
        final_url=f"https://{HOST}/",
    )


def test_weak_headers_graded() -> None:
    res = _res(
        {
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/7.4.3",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "content-security-policy": "default-src 'self' 'unsafe-inline'",
        }
    )
    ids = {f.rule_id: f for f in web_prober.grade_headers(HOST, res, https=True)}
    assert {
        "hdr-hsts-missing", "hdr-xfo-missing", "hdr-xcto-missing", "hdr-referrer-missing",
        "hdr-permissions-missing", "hdr-server-version", "hdr-x-powered-by-version",
        "cors-wildcard-credentials", "hdr-csp-unsafe",
    } <= set(ids)  # fmt: skip
    assert "hdr-csp-missing" not in ids
    assert ids["cors-wildcard-credentials"].severity == Severity.HIGH
    assert ids["cors-wildcard-credentials"].cwe == "CWE-942"
    assert all(f.cwe.startswith("CWE-") and f.remediation for f in ids.values())


def test_hardened_headers_are_clean() -> None:
    res = _res(
        {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "server": "nginx",
        }
    )
    assert web_prober.grade_headers(HOST, res, https=True) == []


def test_wildcard_cors_without_credentials_is_info_and_weak_hsts_low() -> None:
    res = _res({"access-control-allow-origin": "*", "strict-transport-security": "max-age=300"})
    ids = {f.rule_id: f.severity for f in web_prober.grade_headers(HOST, res, https=True)}
    assert ids["cors-wildcard"] == Severity.INFO
    assert ids["hdr-hsts-weak"] == Severity.LOW
    assert "cors-wildcard-credentials" not in ids


# ------------------------------------------------------------- TLS
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_parse_cert_valid() -> None:
    cert = {
        "subject": ((("commonName", HOST),),),
        "issuer": ((("organizationName", "Example CA"),), (("commonName", "Example CA R3"),)),
        "subjectAltName": (("DNS", HOST), ("DNS", "target.com"), ("IP Address", "1.2.3.4")),
        "notAfter": "Feb 15 00:00:00 2026 GMT",
    }
    info = web_prober.parse_cert(cert, now=NOW)
    assert info.subject == HOST and info.issuer == "Example CA"
    assert info.sans == [HOST, "target.com"]
    assert info.days_remaining == 45 and not info.expired and not info.self_signed
    assert web_prober.tls_findings(HOST, info) == []


def test_parse_cert_expired_and_expiring() -> None:
    expired = web_prober.parse_cert({"notAfter": "Dec 1 00:00:00 2025 GMT"}, now=NOW)
    assert expired.expired
    f = web_prober.tls_findings(HOST, expired)
    assert [(x.rule_id, x.severity, x.cwe) for x in f] == [
        ("tls-expired", Severity.HIGH, "CWE-298")
    ]
    soon = web_prober.parse_cert({"notAfter": "Jan 6 00:00:00 2026 GMT"}, now=NOW)
    assert [x.rule_id for x in web_prober.tls_findings(HOST, soon)] == ["tls-expiring-soon"]
    assert web_prober.tls_findings(HOST, soon)[0].severity == Severity.HIGH  # <= 7 days
    month = web_prober.parse_cert({"notAfter": "Jan 25 00:00:00 2026 GMT"}, now=NOW)
    assert web_prober.tls_findings(HOST, month)[0].severity == Severity.MEDIUM


def test_self_signed_and_verify_failures() -> None:
    cert = {"subject": ((("commonName", "x"),),), "issuer": ((("commonName", "x"),),)}
    info = web_prober.parse_cert(cert, now=NOW)
    assert [f.rule_id for f in web_prober.tls_findings(HOST, info)] == ["tls-self-signed"]
    mismatch = TlsInfo(hostname_mismatch=True, error="certificate verification failed: Hostname")
    assert "tls-hostname-mismatch" in {f.rule_id for f in web_prober.tls_findings(HOST, mismatch)}
    untrusted = TlsInfo(error="certificate verification failed: unable to get local issuer")
    assert [f.rule_id for f in web_prober.tls_findings(HOST, untrusted)] == ["tls-untrusted"]


# ------------------------------------------------------------- probe_host
async def _fake_tls(host: str, ip: str) -> TlsInfo:
    return TlsInfo(subject=host, issuer="CA", days_remaining=200)


async def test_probe_host_end_to_end() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.scheme, request.url.path))
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"location": f"https://{HOST}/"})
        if request.url.path == "/.git/HEAD":
            return httpx.Response(
                200, headers={"content-type": "text/plain"}, text="ref: refs/heads/dev"
            )
        if request.url.path == "/":
            origin = request.headers.get("origin", "")
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/html",
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                },
                text="<html><head><title> Hello &amp; Welcome </title></head></html>",
            )
        return httpx.Response(404, text="nf")

    scope, fetcher = _env(handler)
    async with fetcher:
        res = await web_prober.probe_host(HOST, scope, fetcher, RULES, tls_fetcher=_fake_tls)
    https = next(p for p in res.http if p.url.startswith("https"))
    assert https.status == 200 and https.title == "Hello & Welcome"
    ids = {f.rule_id for f in res.findings}
    assert {"cors-reflected-credentials", "exposed-git-head", "hdr-hsts-missing"} <= ids
    assert "http-no-redirect" not in ids and "no-https" not in ids
    assert res.tls is not None and res.tls.days_remaining == 200
    assert f"https://{HOST}/.git/HEAD" in res.endpoints and f"https://{HOST}/" in res.endpoints


async def test_probe_host_http_only_and_no_redirect() -> None:
    def https_down(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, text="<html></html>")

    scope, fetcher = _env(https_down)
    async with fetcher:
        res = await web_prober.probe_host(HOST, scope, fetcher, [], tls_fetcher=_fake_tls)
    assert "no-https" in {f.rule_id for f in res.findings}

    def both_up(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html></html>")

    scope, fetcher = _env(both_up)
    async with fetcher:
        res = await web_prober.probe_host(HOST, scope, fetcher, [], tls_fetcher=_fake_tls)
    assert "http-no-redirect" in {f.rule_id for f in res.findings}


async def test_probe_host_out_of_scope_redirect_not_followed() -> None:
    hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append(req_host(request))
        return httpx.Response(302, headers={"location": "https://evil.com/phish"})

    scope, fetcher = _env(handler)
    async with fetcher:
        res = await web_prober.probe_host(HOST, scope, fetcher, [], tls_fetcher=_fake_tls)
    assert set(hosts) == {HOST}
    redirect = [f for f in res.findings if f.rule_id == "redirect-out-of-scope"]
    assert redirect and redirect[0].severity == Severity.INFO
    assert res.http[0].redirect_to == "https://evil.com/phish"


async def test_probe_host_skips_private_resolution() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    resolver = FakeResolver().add("internal.target.com", "10.0.0.7")
    scope = make_scope(resolver)
    async with make_fetcher(scope, handler) as fetcher:
        res = await web_prober.probe_host(
            "internal.target.com", scope, fetcher, RULES, tls_fetcher=_fake_tls
        )
    assert calls == 0 and res.tls is None
    assert [f.rule_id for f in res.findings] == ["private-ip-resolution"]
