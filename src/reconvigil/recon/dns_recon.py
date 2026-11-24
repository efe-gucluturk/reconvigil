"""Subdomain discovery (CT + brute force), DNS records, email posture, takeover detection."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

import httpx

from reconvigil.dnsio import DNSLookupError, Resolver
from reconvigil.models import DnsRecords, Finding, Severity
from reconvigil.rules import TakeoverRule
from reconvigil.security.safe_http import CT_MAX_BYTES, USER_AGENT, GuardedFetcher, read_capped
from reconvigil.security.scope import ScopeError, TargetScope, normalize_hostname

CT_URL = "https://crt.sh/"
ALL_RDTYPES = ("A", "AAAA", "CNAME", "MX", "TXT")
BASIC_RDTYPES = ("A", "AAAA", "CNAME")
MAX_CNAME_HOPS = 8
TAKEOVER_CWE = "CWE-672"
TAKEOVER_SEVERITY = Severity.HIGH
TAKEOVER_REMEDIATION = "Remove the dangling DNS record, or re-claim the resource at the provider."

DEFAULT_WORDS = [
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "sftp",
    "vpn",
    "remote",
    "api",
    "app",
    "apps",
    "admin",
    "portal",
    "dev",
    "test",
    "staging",
    "stage",
    "qa",
    "uat",
    "prod",
    "beta",
    "demo",
    "sandbox",
    "internal",
    "intranet",
    "extranet",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "jira",
    "wiki",
    "docs",
    "help",
    "support",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "prometheus",
    "db",
    "sql",
    "mysql",
    "redis",
    "cdn",
    "static",
    "assets",
    "img",
    "media",
    "files",
    "upload",
    "download",
    "blog",
    "shop",
    "store",
    "pay",
    "payments",
    "auth",
    "sso",
    "login",
    "id",
    "accounts",
    "dashboard",
    "console",
    "gateway",
    "proxy",
    "ns1",
    "ns2",
    "mx",
    "m",
    "mobile",
    "old",
    "new",
    "v1",
    "v2",
]
PERMUTATION_PREFIXES = ("dev", "staging", "test", "qa", "uat", "prod", "internal", "old", "new")
_LABEL_OK = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass
class Discovery:
    hosts: dict[str, set[str]] = field(default_factory=dict)  # host -> sources
    records: dict[str, DnsRecords] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- CT logs
def make_ct_client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0),
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=False,
        trust_env=False,
    )


async def fetch_ct_subdomains(
    client: httpx.AsyncClient,
    scope: TargetScope,
    *,
    retries: int = 3,
    backoff: float = 1.5,
    total_timeout: float = 45.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> tuple[set[str], list[str]]:
    """Query crt.sh JSON. Never raises on network/parse problems; returns (names, warnings)."""
    params = {"q": f"%.{scope.root}", "output": "json"}
    warnings: list[str] = []
    for attempt in range(1, retries + 1):
        try:
            async with asyncio.timeout(total_timeout):
                async with client.stream("GET", CT_URL, params=params) as resp:
                    status = resp.status_code
                    body, truncated = await read_capped(resp, CT_MAX_BYTES)
            if status == 429 or status >= 500:
                warnings.append(f"crt.sh HTTP {status} (attempt {attempt}/{retries})")
            elif status != 200:
                warnings.append(f"crt.sh unexpected HTTP {status}; skipping CT")
                return set(), warnings
            else:
                if truncated:
                    warnings.append("crt.sh response exceeded size cap; results incomplete")
                return _parse_ct(body, scope, warnings), warnings
        except (TimeoutError, httpx.HTTPError) as exc:
            warnings.append(f"crt.sh {type(exc).__name__} (attempt {attempt}/{retries})")
        if attempt < retries:
            await sleep(backoff * 2 ** (attempt - 1))
    warnings.append("crt.sh unavailable; continuing without CT data")
    return set(), warnings


def _parse_ct(body: bytes, scope: TargetScope, warnings: list[str]) -> set[str]:
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        warnings.append("crt.sh returned invalid JSON; ignoring")
        return set()
    if not isinstance(data, list):
        warnings.append("crt.sh returned unexpected JSON shape; ignoring")
        return set()
    names: set[str] = set()
    for entry in data:
        value = entry.get("name_value") if isinstance(entry, dict) else None
        if not isinstance(value, str):
            continue
        for raw in value.splitlines():
            candidate = raw.strip().lower().removeprefix("*.")
            try:
                host = normalize_hostname(candidate)
            except ScopeError:
                continue
            if scope.in_scope(host):  # CT data is untrusted: drop anything out of scope
                names.add(host)
    return names


# --------------------------------------------------------------------------- DNS records
async def collect_records(
    resolver: Resolver, host: str, rdtypes: Iterable[str] = ALL_RDTYPES
) -> DnsRecords:
    kinds = tuple(rdtypes)
    results = await asyncio.gather(
        *(resolver.query(host, k) for k in kinds), return_exceptions=True
    )
    rec = DnsRecords(host=host)
    for kind, res in zip(kinds, results, strict=True):
        if isinstance(res, DNSLookupError):
            rec.errors.append(str(res))
        elif isinstance(res, BaseException):
            raise res
        else:
            getattr(rec, kind.lower()).extend(res)
    if rec.cname:
        seen = {host, rec.cname[0]}
        current = rec.cname[0]
        for _ in range(MAX_CNAME_HOPS):
            try:
                nxt = await resolver.query(current, "CNAME")
            except DNSLookupError as exc:
                rec.errors.append(str(exc))
                break
            if not nxt or nxt[0] in seen:
                break
            rec.cname.append(nxt[0])
            seen.add(nxt[0])
            current = nxt[0]
    return rec


def _has_presence(rec: DnsRecords) -> bool:
    return bool(rec.a or rec.aaaa or rec.cname)


async def detect_wildcard(resolver: Resolver, root: str) -> tuple[frozenset[str], tuple[str, ...]]:
    probe = f"rv-{secrets.token_hex(6)}.{root}"
    rec = await collect_records(resolver, probe, BASIC_RDTYPES)
    return frozenset(rec.ips), tuple(rec.cname)


# --------------------------------------------------------------------------- candidates
def generate_candidates(
    root: str,
    words: Iterable[str],
    known: Iterable[str] = (),
    *,
    max_candidates: int = 5000,
) -> list[str]:
    """Wordlist + simple permutations over already-known labels; deterministic and capped."""
    labels = []
    for word in words:
        w = word.strip().lower()
        if _LABEL_OK.fullmatch(w) and w not in labels:
            labels.append(w)
    out: dict[str, None] = {f"{w}.{root}": None for w in labels}
    bases = sorted(
        {h.removesuffix("." + root).split(".")[-1] for h in known if h.endswith("." + root)}
    )[:100]
    for base in bases:
        if not _LABEL_OK.fullmatch(base):
            continue
        for prefix in PERMUTATION_PREFIXES:
            out[f"{prefix}-{base}.{root}"] = None
            out[f"{base}-{prefix}.{root}"] = None
            out[f"{prefix}.{base}.{root}"] = None
        for n in ("1", "2", "01"):
            out[f"{base}{n}.{root}"] = None
    for host in known:
        out.pop(host, None)
    return list(out)[:max_candidates]


async def discover(
    scope: TargetScope,
    resolver: Resolver,
    *,
    ct_client: httpx.AsyncClient | None,
    words: Iterable[str] | None = None,
    seeds: Iterable[str] = (),
    concurrency: int = 50,
    max_candidates: int = 5000,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Discovery:
    disc = Discovery()
    sources: dict[str, set[str]] = {scope.root: {"root"}}
    for seed in seeds:
        sources.setdefault(scope.require_in_scope(seed), set()).add("seed")
    ct_names: set[str] = set()
    if ct_client is not None:
        ct_names, ct_warn = await fetch_ct_subdomains(ct_client, scope, sleep=sleep)
        disc.warnings.extend(ct_warn)
        for name in ct_names:
            sources.setdefault(name, set()).add("ct")
    candidates = generate_candidates(
        scope.root,
        DEFAULT_WORDS if words is None else words,
        known=sources.keys(),
        max_candidates=max_candidates,
    )
    for cand in candidates:
        sources.setdefault(cand, set()).add("bruteforce")

    wildcard_ips, wildcard_cname = await detect_wildcard(resolver, scope.root)
    if wildcard_ips or wildcard_cname:
        disc.warnings.append("wildcard DNS detected; filtering brute-forced matches")

    sem = asyncio.Semaphore(concurrency)

    async def resolve(host: str) -> None:
        async with sem:
            rec = await collect_records(resolver, host, BASIC_RDTYPES)
        if not _has_presence(rec):
            return
        brute_only = sources[host] == {"bruteforce"}
        is_wildcard_hit = set(rec.ips) <= wildcard_ips and tuple(rec.cname) == wildcard_cname
        if brute_only and (wildcard_ips or wildcard_cname) and is_wildcard_hit:
            return
        disc.records[host] = rec
        disc.hosts[host] = sources[host]

    await asyncio.gather(*(resolve(h) for h in sources))
    return disc


# --------------------------------------------------------------------------- email posture
_SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    cwe: str,
    asset: str,
    description: str,
    remediation: str,
    *,
    location: str = "",
    evidence: str = "",
    category: str = "dns",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        cwe=cwe,
        asset=asset,
        location=location,
        description=description,
        remediation=remediation,
        evidence=evidence,
        category=category,
    )


async def audit_email_posture(resolver: Resolver, domain: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    try:
        txt = await resolver.query(domain, "TXT")
        dmarc_txt = await resolver.query(f"_dmarc.{domain}", "TXT")
    except DNSLookupError as exc:
        return [], [f"email posture skipped: {exc}"]

    spf = [t for t in txt if t.strip().lower().startswith("v=spf1")]
    spoof = "CWE-290"
    if not spf:
        findings.append(
            _finding(
                "spf-missing",
                "Missing SPF record",
                Severity.MEDIUM,
                spoof,
                domain,
                "No SPF record published; anyone can send mail appearing to come from this domain.",
                "Publish a v=spf1 TXT record listing authorized senders and ending in -all.",
                category="email",
            )
        )
    else:
        if len(spf) > 1:
            findings.append(
                _finding(
                    "spf-multiple",
                    "Multiple SPF records",
                    Severity.LOW,
                    spoof,
                    domain,
                    "More than one SPF record causes a permanent error (RFC 7208), disabling SPF.",
                    "Merge into a single SPF TXT record.",
                    evidence=" | ".join(spf),
                    category="email",
                )
            )
        tokens = spf[0].split()
        qualifier = next(
            (m.group(1) or "+" for t in reversed(tokens) if (m := _SPF_ALL.match(t))), None
        )
        has_redirect = any(t.lower().startswith("redirect=") for t in tokens)
        if qualifier == "+":
            findings.append(
                _finding(
                    "spf-permissive-all",
                    "SPF allows all senders (+all)",
                    Severity.HIGH,
                    spoof,
                    domain,
                    "SPF ends in +all (or bare all), authorizing every host on the internet.",
                    "Replace with -all (or ~all while rolling out) after listing real senders.",
                    evidence=spf[0],
                    category="email",
                )
            )
        elif qualifier == "?":
            findings.append(
                _finding(
                    "spf-neutral-all",
                    "SPF neutral policy (?all)",
                    Severity.MEDIUM,
                    spoof,
                    domain,
                    "SPF ends in ?all, giving receivers no basis to reject spoofed mail.",
                    "Use -all (or at minimum ~all).",
                    evidence=spf[0],
                    category="email",
                )
            )
        elif qualifier == "~":
            findings.append(
                _finding(
                    "spf-softfail-all",
                    "SPF soft-fail policy (~all)",
                    Severity.LOW,
                    spoof,
                    domain,
                    "SPF soft-fails unauthorized senders instead of rejecting them.",
                    "Move to -all once legitimate senders are confirmed.",
                    evidence=spf[0],
                    category="email",
                )
            )
        elif qualifier is None and not has_redirect:
            findings.append(
                _finding(
                    "spf-no-all",
                    "SPF record has no 'all' terminator",
                    Severity.LOW,
                    spoof,
                    domain,
                    "Without a terminating all mechanism, unlisted senders get a neutral result.",
                    "Terminate the SPF record with -all.",
                    evidence=spf[0],
                    category="email",
                )
            )

    dmarc = [t for t in dmarc_txt if t.strip().lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(
            _finding(
                "dmarc-missing",
                "Missing DMARC record",
                Severity.MEDIUM,
                spoof,
                domain,
                "No DMARC policy at _dmarc; receivers cannot be told to reject spoofed mail.",
                "Publish v=DMARC1; p=quarantine (then reject) with rua= reporting.",
                location="_dmarc",
                category="email",
            )
        )
    else:
        tags = {
            k.strip().lower(): v.strip().lower()
            for k, _, v in (p.partition("=") for p in dmarc[0].split(";"))
            if k.strip()
        }
        if tags.get("p", "none") == "none":
            findings.append(
                _finding(
                    "dmarc-policy-none",
                    "DMARC policy is p=none",
                    Severity.LOW,
                    spoof,
                    domain,
                    "DMARC is monitor-only; spoofed mail is still delivered.",
                    "Move to p=quarantine, then p=reject after reviewing aggregate reports.",
                    location="_dmarc",
                    evidence=dmarc[0],
                    category="email",
                )
            )
    return findings, warnings


# --------------------------------------------------------------------------- takeover
async def check_takeover(
    host: str,
    records: DnsRecords,
    fetcher: GuardedFetcher,
    rules: list[TakeoverRule],
) -> list[Finding]:
    if not records.cname:
        return []
    chain = " -> ".join([host, *records.cname])
    rule = next((r for r in rules if any(r.matches_cname(t) for t in records.cname)), None)
    cwe = TAKEOVER_CWE
    if rule is None:
        if not records.ips:
            return [
                _finding(
                    "dangling-cname",
                    "Dangling CNAME (target does not resolve)",
                    Severity.LOW,
                    cwe,
                    host,
                    "The CNAME target does not resolve. If it points at a claimable third-party "
                    "resource this may become a takeover.",
                    "Remove the stale CNAME or restore the target.",
                    evidence=chain,
                    category="takeover",
                )
            ]
        return []

    def make(why: str) -> Finding:
        return _finding(
            f"subdomain-takeover-{rule.service.lower().replace(' ', '-')}",
            f"Subdomain takeover candidate ({rule.service})",
            TAKEOVER_SEVERITY,
            cwe,
            host,
            f"{host} points at {rule.service} but the resource appears unclaimed: {why}. "
            "An attacker may register it and serve content on this subdomain.",
            TAKEOVER_REMEDIATION,
            evidence=f"{chain}; {why}",
            category="takeover",
        )

    if not records.ips:
        return [make("CNAME target does not resolve (NXDOMAIN)")] if rule.nxdomain_takeover else []
    for scheme in ("https", "http"):
        res = await fetcher.get(f"{scheme}://{host}/", max_redirects=0)
        if res.status is None:
            continue
        if rule.statuses and res.status not in rule.statuses:
            continue
        body = res.text
        for fp in rule.fingerprints:
            if fp in body:
                return [make(f"HTTP {res.status} body matches fingerprint {fp!r}")]
    return []
