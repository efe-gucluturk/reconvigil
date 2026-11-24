"""Guarded HTTP client: scope + SSRF checks on every hop, pinned IPs, capped streaming bodies."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from reconvigil.dnsio import DNSLookupError
from reconvigil.security.scope import ScopeError, SSRFBlockedError, TargetScope

MAX_BODY_BYTES = 1024 * 1024  # 1 MB hard cap (tarpit / OOM protection)
CT_MAX_BYTES = 8 * 1024 * 1024  # bounded exception for crt.sh JSON only
USER_AGENT = "ReconVigil/0.1 (+authorized-security-testing)"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class HttpLimits:
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 20.0  # wall-clock deadline per request chain (anti slow-drip tarpit)
    max_body: int = MAX_BODY_BYTES
    max_redirects: int = 3
    max_concurrent_requests: int = 20

    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.read_timeout,
            pool=self.connect_timeout,
        )


async def read_capped(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Stream a response body, stopping at `max_bytes`. Returns (body, truncated)."""
    buf = bytearray()
    async for chunk in response.aiter_bytes():
        remaining = max_bytes - len(buf)
        if len(chunk) > remaining:
            buf += chunk[:remaining]
            return bytes(buf), True
        buf += chunk
    return bytes(buf), False


@dataclass
class FetchResult:
    url: str
    status: int | None = None
    headers: httpx.Headers = field(default_factory=httpx.Headers)
    body: bytes = b""
    truncated: bool = False
    final_url: str | None = None
    chain: list[str] = field(default_factory=list)
    blocked_redirect: str | None = None  # out-of-scope redirect target that was NOT followed
    error: str | None = None
    blocked: bool = False  # refused by scope/SSRF guard
    ssrf_blocked: bool = False  # specifically: host resolved to a blocked address

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class GuardedTransport(httpx.AsyncBaseTransport):
    """Validates scope + resolves/blocks IPs for every request, then pins the connection IP."""

    def __init__(self, scope: TargetScope, inner: httpx.AsyncBaseTransport) -> None:
        self._scope = scope
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        self._scope.require_in_scope(host)
        ips = await self._scope.resolve_public(host)
        original = request.url
        last_exc: Exception | None = None
        for ip in ips[:3]:
            # Pin the validated IP: DNS cannot change between check and connect (rebinding).
            request.url = original.copy_with(host=ip)
            request.extensions = {**request.extensions, "sni_hostname": host}
            try:
                return await self._inner.handle_async_request(request)
            except httpx.ConnectError as exc:
                last_exc = exc
        raise last_exc if last_exc else DNSLookupError(f"{host}: no usable address")

    async def aclose(self) -> None:
        await self._inner.aclose()


class GuardedFetcher:
    """GET-only fetcher enforcing scope, SSRF, redirect re-validation, timeouts and body cap."""

    def __init__(
        self,
        scope: TargetScope,
        limits: HttpLimits | None = None,
        *,
        inner_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.scope = scope
        self.limits = limits or HttpLimits()
        inner = inner_transport or httpx.AsyncHTTPTransport(
            verify=True,
            retries=0,
            limits=httpx.Limits(max_connections=self.limits.max_concurrent_requests),
        )
        self._client = httpx.AsyncClient(
            transport=GuardedTransport(scope, inner),
            follow_redirects=False,
            timeout=self.limits.timeout(),
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            trust_env=False,
        )
        self._sem = asyncio.Semaphore(self.limits.max_concurrent_requests)

    async def __aenter__(self) -> GuardedFetcher:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_redirects: int | None = None,
    ) -> FetchResult:
        hops_allowed = self.limits.max_redirects if max_redirects is None else max_redirects
        result = FetchResult(url=url)
        try:
            current = self.scope.validate_url(url).url
        except ScopeError as exc:
            result.error, result.blocked = f"blocked: {exc}", True
            return result
        try:
            async with self._sem, asyncio.timeout(self.limits.total_timeout):
                while True:
                    result.chain.append(current)
                    async with self._client.stream("GET", current, headers=headers) as resp:
                        body, truncated = await read_capped(resp, self.limits.max_body)
                    result.status, result.headers = resp.status_code, resp.headers
                    result.body, result.truncated, result.final_url = body, truncated, current
                    location = resp.headers.get("location")
                    if resp.status_code not in REDIRECT_STATUSES or not location:
                        return result
                    if len(result.chain) - 1 >= hops_allowed:
                        return result
                    target = urljoin(current, location)
                    try:
                        current = self.scope.validate_url(target).url
                    except ScopeError:
                        # Re-validate scope on every hop; never follow out-of-scope redirects.
                        result.blocked_redirect = target
                        return result
        except TimeoutError:
            result.error = "timeout (total deadline exceeded)"
        except SSRFBlockedError as exc:
            result.error, result.blocked, result.ssrf_blocked = f"blocked: {exc}", True, True
        except ScopeError as exc:
            result.error, result.blocked = f"blocked: {exc}", True
        except DNSLookupError as exc:
            result.error = f"dns: {exc}"
        except httpx.HTTPError as exc:
            result.error = f"{type(exc).__name__}: {exc}"[:200]
        return result
