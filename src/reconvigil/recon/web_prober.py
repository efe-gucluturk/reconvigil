"""HTTP/TLS probing, security-header grading and sensitive-path exposure auditing."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import html
import json
import re
import secrets
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from reconvigil.dnsio import DNSLookupError
from reconvigil.models import Finding, HttpProbe, Severity, TlsInfo
from reconvigil.rules import ExposureRule
from reconvigil.security.safe_http import FetchResult, GuardedFetcher
from reconvigil.security.scope import ScopeError, TargetScope

CORS_PROBE_ORIGIN = "https://reconvigil-cors-probe.invalid"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_VERSION_RE = re.compile(r"\d+\.\d+")
TlsFetcher = Callable[[str, str], Awaitable[TlsInfo]]


@dataclass
class WebResult:
    http: list[HttpProbe] = field(default_factory=list)
    tls: TlsInfo | None = None
    endpoints: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def _f(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    host: str,
    description: str,
    remediation: str,
    *,
    location: str = "",
    evidence: str = "",
    category: str = "web",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        cwe=cwe,
        asset=host,
        location=location,
        description=description,
        remediation=remediation,
        evidence=evidence,
        category=category,
    )


# --------------------------------------------------------------------------- TLS
async def fetch_tls_info(
    host: str, ip: str, *, port: int = 443, deadline: float = 8.0, now: datetime | None = None
) -> TlsInfo:
    """Handshake against the already-validated `ip` with SNI/verification for `host`."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        async with asyncio.timeout(deadline):
            _, writer = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        return _tls_from_verify_error(exc)
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return TlsInfo(error=f"{type(exc).__name__}: {exc}"[:200])
    try:
        cert = writer.get_extra_info("ssl_object").getpeercert()
    finally:
        writer.close()
        with contextlib.suppress(OSError, TimeoutError, ssl.SSLError):
            await asyncio.wait_for(writer.wait_closed(), 3)
    return parse_cert(cert or {}, now=now)


def _tls_from_verify_error(exc: ssl.SSLCertVerificationError) -> TlsInfo:
    msg = (exc.verify_message or str(exc)).lower()
    return TlsInfo(
        expired="expired" in msg,
        self_signed="self-signed" in msg or "self signed" in msg,
        hostname_mismatch="hostname mismatch" in msg or "doesn't match" in msg,
        error=f"certificate verification failed: {exc.verify_message or exc}"[:200],
    )


def _rdn(seq: Any) -> dict[str, str]:
    return {k: v for rdn in seq for (k, v) in rdn}


def parse_cert(cert: dict[str, Any], *, now: datetime | None = None) -> TlsInfo:
    now = now or datetime.now(UTC)
    subject = _rdn(cert.get("subject", ()))
    issuer = _rdn(cert.get("issuer", ()))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    not_after = None
    days = None
    if "notAfter" in cert:
        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), UTC)
        days = (not_after - now).days
    return TlsInfo(
        subject=subject.get("commonName"),
        issuer=issuer.get("organizationName") or issuer.get("commonName"),
        sans=sans,
        not_after=not_after,
        days_remaining=days,
        expired=days is not None and not_after is not None and not_after < now,
        self_signed=bool(subject) and subject == issuer,
    )


def tls_findings(host: str, tls: TlsInfo) -> list[Finding]:
    out: list[Finding] = []
    detail = tls.error or ""
    if tls.expired:
        out.append(
            _f(
                "tls-expired",
                "TLS certificate expired",
                Severity.HIGH,
                "CWE-298",
                host,
                "The certificate has expired; clients will reject or warn.",
                "Renew and deploy a valid certificate; automate renewal.",
                evidence=detail or f"notAfter={tls.not_after}",
                category="tls",
            )
        )
    elif tls.days_remaining is not None and tls.days_remaining <= 30:
        sev = Severity.HIGH if tls.days_remaining <= 7 else Severity.MEDIUM
        out.append(
            _f(
                "tls-expiring-soon",
                "TLS certificate expires soon",
                sev,
                "CWE-298",
                host,
                f"Certificate expires in {tls.days_remaining} day(s).",
                "Renew the certificate and automate renewal.",
                evidence=f"notAfter={tls.not_after}",
                category="tls",
            )
        )
    if tls.self_signed:
        out.append(
            _f(
                "tls-self-signed",
                "Self-signed TLS certificate",
                Severity.MEDIUM,
                "CWE-295",
                host,
                "The certificate is self-signed/untrusted.",
                "Use a certificate from a trusted CA.",
                evidence=detail,
                category="tls",
            )
        )
    if tls.hostname_mismatch:
        out.append(
            _f(
                "tls-hostname-mismatch",
                "TLS certificate hostname mismatch",
                Severity.MEDIUM,
                "CWE-297",
                host,
                "The certificate does not cover this hostname.",
                "Issue a certificate whose SANs include this host.",
                evidence=detail,
                category="tls",
            )
        )
    if (
        tls.error
        and not (tls.expired or tls.self_signed or tls.hostname_mismatch)
        and "verification failed" in tls.error
    ):
        out.append(
            _f(
                "tls-untrusted",
                "TLS certificate not trusted",
                Severity.MEDIUM,
                "CWE-295",
                host,
                "Certificate chain validation failed.",
                "Serve the full chain from a trusted CA.",
                evidence=detail,
                category="tls",
            )
        )
    return out


# --------------------------------------------------------------------------- headers
def grade_headers(host: str, res: FetchResult, *, https: bool) -> list[Finding]:
    h = res.headers
    out: list[Finding] = []
    loc = res.final_url or res.url

    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(
                _f(
                    "hdr-hsts-missing",
                    "Missing Strict-Transport-Security",
                    Severity.MEDIUM,
                    "CWE-319",
                    host,
                    "Browsers are not told to enforce HTTPS.",
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                    location=loc,
                )
            )
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if not m or int(m.group(1)) < 15552000:
                out.append(
                    _f(
                        "hdr-hsts-weak",
                        "Weak Strict-Transport-Security max-age",
                        Severity.LOW,
                        "CWE-319",
                        host,
                        "HSTS max-age is under 180 days.",
                        "Use max-age of at least 31536000.",
                        location=loc,
                        evidence=hsts,
                    )
                )

    csp = h.get("content-security-policy")
    if not csp:
        out.append(
            _f(
                "hdr-csp-missing",
                "Missing Content-Security-Policy",
                Severity.LOW,
                "CWE-693",
                host,
                "No CSP to mitigate XSS/data injection.",
                "Define a restrictive Content-Security-Policy.",
                location=loc,
            )
        )
    elif re.search(r"(script-src|default-src)[^;]*'unsafe-(inline|eval)'", csp, re.IGNORECASE):
        out.append(
            _f(
                "hdr-csp-unsafe",
                "CSP allows unsafe-inline/unsafe-eval",
                Severity.LOW,
                "CWE-693",
                host,
                "CSP script policy permits inline/eval execution.",
                "Use nonces/hashes and remove unsafe-inline/unsafe-eval.",
                location=loc,
                evidence=csp,
            )
        )
    if not h.get("x-frame-options") and not (csp and "frame-ancestors" in csp.lower()):
        out.append(
            _f(
                "hdr-xfo-missing",
                "Missing clickjacking protection",
                Severity.LOW,
                "CWE-1021",
                host,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                location=loc,
            )
        )
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(
            _f(
                "hdr-xcto-missing",
                "Missing X-Content-Type-Options: nosniff",
                Severity.LOW,
                "CWE-693",
                host,
                "MIME sniffing is not disabled.",
                "Send X-Content-Type-Options: nosniff.",
                location=loc,
            )
        )
    if not h.get("referrer-policy"):
        out.append(
            _f(
                "hdr-referrer-missing",
                "Missing Referrer-Policy",
                Severity.INFO,
                "CWE-200",
                host,
                "Full URLs may leak via the Referer header.",
                "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
                location=loc,
            )
        )
    if not h.get("permissions-policy"):
        out.append(
            _f(
                "hdr-permissions-missing",
                "Missing Permissions-Policy",
                Severity.INFO,
                "CWE-693",
                host,
                "Browser feature access is not restricted.",
                "Send a Permissions-Policy denying unneeded features.",
                location=loc,
            )
        )
    for name in ("server", "x-powered-by"):
        value = h.get(name)
        if value and _VERSION_RE.search(value):
            out.append(
                _f(
                    f"hdr-{name}-version",
                    f"Version disclosure via {name}",
                    Severity.LOW,
                    "CWE-200",
                    host,
                    "Software version disclosed, aiding targeted attacks.",
                    f"Remove or genericize the {name} header.",
                    location=loc,
                    evidence=f"{name}: {value}",
                )
            )

    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials") or "").strip().lower() == "true"
    if acao:
        if acao.strip() == "*" and acac:
            out.append(
                _f(
                    "cors-wildcard-credentials",
                    "CORS wildcard origin with credentials",
                    Severity.HIGH,
                    "CWE-942",
                    host,
                    "Access-Control-Allow-Origin: * combined with Allow-Credentials: true.",
                    "Never combine wildcard origins with credentials; use an allowlist.",
                    location=loc,
                    evidence=f"ACAO={acao}, ACAC=true",
                )
            )
        elif acao.strip() == CORS_PROBE_ORIGIN and acac:
            out.append(
                _f(
                    "cors-reflected-credentials",
                    "CORS reflects arbitrary origin with credentials",
                    Severity.HIGH,
                    "CWE-942",
                    host,
                    "An attacker-controlled Origin is reflected with credentials allowed.",
                    "Validate Origin against a strict allowlist.",
                    location=loc,
                    evidence=f"ACAO={acao}, ACAC=true",
                )
            )
        elif acao.strip() == "*":
            out.append(
                _f(
                    "cors-wildcard",
                    "CORS allows any origin",
                    Severity.INFO,
                    "CWE-942",
                    host,
                    "Access-Control-Allow-Origin: * is set (no credentials).",
                    "Restrict to required origins if responses are not fully public.",
                    location=loc,
                )
            )
    return out


def _title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body[:65536].decode("utf-8", errors="replace"))
    if not m:
        return None
    title = " ".join(html.unescape(m.group(1)).split())
    return title[:200] or None


def _probe(url: str, res: FetchResult) -> HttpProbe:
    redirect_to = res.blocked_redirect
    if redirect_to is None and res.status in (301, 302, 303, 307, 308):
        redirect_to = res.headers.get("location")
    return HttpProbe(
        url=url,
        status=res.status,
        title=_title(res.body) if res.status else None,
        server=res.headers.get("server") if res.status else None,
        final_url=res.final_url if res.status else None,
        redirect_to=redirect_to,
        truncated=res.truncated,
        error=res.error,
    )


# --------------------------------------------------------------------------- exposure
def _looks_html(res: FetchResult) -> bool:
    ctype = res.headers.get("content-type", "").lower()
    head = res.body[:512].lstrip().lower()
    return "html" in ctype or head.startswith((b"<!doctype", b"<html", b"<head", b"<body"))


def evaluate_exposure(
    host: str, rule: ExposureRule, res: FetchResult, baseline_hash: str | None
) -> Finding | None:
    """Strict validation: status + content checks + soft-404 baseline comparison."""
    if res.error or res.status not in rule.status or not res.body:
        return None
    if baseline_hash and hashlib.sha256(res.body).hexdigest() == baseline_hash:
        return None  # identical to the site's "not found" page
    if rule.reject_html and _looks_html(res):
        return None
    text = res.text
    if rule.json_keys_any:
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return None
        if not isinstance(data, dict) or not any(k in data for k in rule.json_keys_any):
            return None
    if rule.must_match and not re.search(rule.must_match, text):
        return None
    if rule.must_contain_any and not any(s in text for s in rule.must_contain_any):
        return None

    severity = rule.severity
    for esc in rule.escalate:
        if re.search(esc.regex, text):
            severity = esc.severity
            break
    if rule.redact:
        keys = re.findall(r"(?m)^[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]+)[ \t]*=", text)
        evidence = f"{len(keys)} variable(s), values redacted: {', '.join(keys[:15])}"
    elif rule.id == "robots-txt-present":
        paths = re.findall(r"(?im)^disallow:\s*(\S+)", text)
        evidence = "Disallow: " + ", ".join(paths[:10]) if paths else "no Disallow entries"
    elif rule.json_keys_any:
        evidence = f"JSON document, {len(res.body)} bytes"
    else:
        evidence = text.strip().splitlines()[0][:120] if text.strip() else ""
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity,
        cwe=rule.cwe,
        asset=host,
        location=rule.path,
        description=rule.description,
        remediation=rule.remediation,
        evidence=evidence,
        category="exposure",
    )


async def audit_exposed_paths(
    host: str,
    base_url: str,
    fetcher: GuardedFetcher,
    rules: list[ExposureRule],
    *,
    concurrency: int = 4,
) -> tuple[list[Finding], list[str]]:
    """Return (findings, exposed URLs). Never follows redirects for path probes."""
    base = base_url.rstrip("/")
    baseline = await fetcher.get(f"{base}/reconvigil-{secrets.token_hex(8)}", max_redirects=0)
    baseline_hash = (
        hashlib.sha256(baseline.body).hexdigest()
        if baseline.status == 200 and baseline.body
        else None
    )
    sem = asyncio.Semaphore(concurrency)

    async def one(rule: ExposureRule) -> tuple[ExposureRule, FetchResult]:
        async with sem:
            return rule, await fetcher.get(f"{base}{rule.path}", max_redirects=0)

    findings: list[Finding] = []
    urls: list[str] = []
    for rule, res in await asyncio.gather(*(one(r) for r in rules)):
        finding = evaluate_exposure(host, rule, res, baseline_hash)
        if finding:
            findings.append(finding)
            urls.append(f"{base}{rule.path}")
    return findings, urls


# --------------------------------------------------------------------------- orchestration
async def probe_host(
    host: str,
    scope: TargetScope,
    fetcher: GuardedFetcher,
    rules: list[ExposureRule],
    *,
    tls_fetcher: TlsFetcher = fetch_tls_info,
    http_port: int = 80,
    https_port: int = 443,
) -> WebResult:
    out = WebResult()
    https_base = f"https://{host}" + ("" if https_port == 443 else f":{https_port}")
    http_base = f"http://{host}" + ("" if http_port == 80 else f":{http_port}")
    cors_headers = {"Origin": CORS_PROBE_ORIGIN}
    https_res, http_res = await asyncio.gather(
        fetcher.get(f"{https_base}/", headers=cors_headers),
        fetcher.get(f"{http_base}/", headers=cors_headers),
    )
    for url, res in ((f"{https_base}/", https_res), (f"{http_base}/", http_res)):
        out.http.append(_probe(url, res))
        if res.status is not None:
            out.endpoints.append(url)
        if res.blocked_redirect:
            out.findings.append(
                _f(
                    "redirect-out-of-scope",
                    "Redirect to out-of-scope host (not followed)",
                    Severity.INFO,
                    "CWE-601",
                    host,
                    "The service redirects outside the target scope; ReconVigil did not follow it.",
                    "Verify the redirect target is intended.",
                    location=url,
                    evidence=res.blocked_redirect,
                )
            )
        if res.ssrf_blocked:
            out.findings.append(
                _f(
                    "private-ip-resolution",
                    "Public hostname resolves to private/reserved IP",
                    Severity.LOW,
                    "CWE-200",
                    host,
                    "DNS for this host returns a non-public address (topology disclosure); "
                    "it was not probed.",
                    "Remove internal addresses from public DNS.",
                    evidence=res.error or "",
                    category="dns",
                )
            )
            return out  # SSRF guard refused; do nothing else for this host

    https_live, http_live = https_res.status is not None, http_res.status is not None
    graded = https_res if https_live else http_res if http_live else None
    if graded is not None:
        out.findings.extend(grade_headers(host, graded, https=graded is https_res))
    if http_live and not https_live:
        out.findings.append(
            _f(
                "no-https",
                "Service served over HTTP only",
                Severity.MEDIUM,
                "CWE-319",
                host,
                "No working HTTPS endpoint; traffic is exposed to interception and tampering.",
                "Deploy TLS and redirect HTTP to HTTPS.",
                location=f"{http_base}/",
            )
        )
    elif (
        http_live
        and https_live
        and (http_res.final_url or "").startswith("http://")
        and (http_res.status or 500) < 400
    ):
        out.findings.append(
            _f(
                "http-no-redirect",
                "HTTP does not redirect to HTTPS",
                Severity.LOW,
                "CWE-319",
                host,
                "Plain HTTP serves content instead of redirecting to HTTPS.",
                "Redirect all HTTP traffic to HTTPS (and enable HSTS).",
                location=f"{http_base}/",
            )
        )

    # TLS metadata against a validated, pinned address.
    if https_live or https_res.error:
        try:
            ips = await scope.resolve_public(host)
        except (ScopeError, DNSLookupError):
            ips = []
        if ips:
            out.tls = await tls_fetcher(host, ips[0])
            if out.tls.error is None or "verification failed" in (out.tls.error or ""):
                out.findings.extend(tls_findings(host, out.tls))

    base = https_base if https_live else http_base if http_live else None
    if base:
        found, urls = await audit_exposed_paths(host, base, fetcher, rules)
        out.findings.extend(found)
        out.endpoints.extend(urls)
    return out


@dataclass(frozen=True)
class PostureRule:
    """Catalog entry for built-in header/CORS/TLS checks (shown by `reconvigil rules`)."""

    id: str
    title: str
    severity: Severity
    cwe: str
    remediation: str


_S = Severity
POSTURE_RULES: tuple[PostureRule, ...] = (
    PostureRule("hdr-hsts-missing", "Missing Strict-Transport-Security", _S.MEDIUM, "CWE-319",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    PostureRule("hdr-hsts-weak", "Weak HSTS max-age", _S.LOW, "CWE-319",
                "Use max-age of at least 31536000."),
    PostureRule("hdr-csp-missing", "Missing Content-Security-Policy", _S.LOW, "CWE-693",
                "Define a restrictive Content-Security-Policy."),
    PostureRule("hdr-csp-unsafe", "CSP allows unsafe-inline/unsafe-eval", _S.LOW, "CWE-693",
                "Use nonces/hashes and remove unsafe-inline/unsafe-eval."),
    PostureRule("hdr-xfo-missing", "Missing clickjacking protection", _S.LOW, "CWE-1021",
                "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    PostureRule("hdr-xcto-missing", "Missing X-Content-Type-Options: nosniff", _S.LOW, "CWE-693",
                "Send X-Content-Type-Options: nosniff."),
    PostureRule("hdr-referrer-missing", "Missing Referrer-Policy", _S.INFO, "CWE-200",
                "Send Referrer-Policy: strict-origin-when-cross-origin or stricter."),
    PostureRule("hdr-permissions-missing", "Missing Permissions-Policy", _S.INFO, "CWE-693",
                "Send a Permissions-Policy denying unneeded features."),
    PostureRule("hdr-server-version", "Version disclosure via Server", _S.LOW, "CWE-200",
                "Remove or genericize the Server header."),
    PostureRule("hdr-x-powered-by-version", "Version disclosure via X-Powered-By", _S.LOW,
                "CWE-200", "Remove or genericize the X-Powered-By header."),
    PostureRule("cors-wildcard-credentials", "CORS wildcard origin with credentials", _S.HIGH,
                "CWE-942", "Never combine wildcard origins with credentials; use an allowlist."),
    PostureRule("cors-reflected-credentials", "CORS reflects arbitrary origin with credentials",
                _S.HIGH, "CWE-942", "Validate Origin against a strict allowlist."),
    PostureRule("cors-wildcard", "CORS allows any origin", _S.INFO, "CWE-942",
                "Restrict to required origins if responses are not fully public."),
    PostureRule("no-https", "Service served over HTTP only", _S.MEDIUM, "CWE-319",
                "Deploy TLS and redirect HTTP to HTTPS."),
    PostureRule("http-no-redirect", "HTTP does not redirect to HTTPS", _S.LOW, "CWE-319",
                "Redirect all HTTP traffic to HTTPS (and enable HSTS)."),
    PostureRule("tls-expired", "TLS certificate expired", _S.HIGH, "CWE-298",
                "Renew and deploy a valid certificate; automate renewal."),
    PostureRule("tls-expiring-soon", "TLS certificate expires within 30 days", _S.MEDIUM,
                "CWE-298", "Renew the certificate and automate renewal (HIGH within 7 days)."),
    PostureRule("tls-self-signed", "Self-signed TLS certificate", _S.MEDIUM, "CWE-295",
                "Use a certificate from a trusted CA."),
    PostureRule("tls-hostname-mismatch", "TLS certificate hostname mismatch", _S.MEDIUM,
                "CWE-297", "Issue a certificate whose SANs include this host."),
    PostureRule("tls-untrusted", "TLS certificate not trusted", _S.MEDIUM, "CWE-295",
                "Serve the full chain from a trusted CA."),
)  # fmt: skip


__all__ = [
    "POSTURE_RULES",
    "PostureRule",
    "WebResult",
    "audit_exposed_paths",
    "evaluate_exposure",
    "fetch_tls_info",
    "grade_headers",
    "parse_cert",
    "probe_host",
    "tls_findings",
]
