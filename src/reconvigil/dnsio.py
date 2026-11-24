"""Async DNS access behind a small protocol so tests can inject fakes."""

from __future__ import annotations

import asyncio
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver


class DNSLookupError(Exception):
    """Operational DNS failure (timeout, SERVFAIL). NXDOMAIN is *not* an error."""


class Resolver(Protocol):
    async def query(self, name: str, rdtype: str) -> list[str]:
        """Return normalized text answers; [] for NXDOMAIN / no data. Raise DNSLookupError."""
        ...


class DnsPythonResolver:
    """`dns.asyncresolver` backed resolver with bounded concurrency."""

    def __init__(
        self,
        nameservers: list[str] | None = None,
        *,
        timeout: float = 3.0,
        lifetime: float = 6.0,
        concurrency: int = 50,
    ) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=True)
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        self._sem = asyncio.Semaphore(concurrency)

    async def query(self, name: str, rdtype: str) -> list[str]:
        async with self._sem:
            try:
                answer = await self._resolver.resolve(name, rdtype, raise_on_no_answer=True)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                raise DNSLookupError(f"{rdtype} {name}: {type(exc).__name__}") from exc
            except dns.exception.DNSException as exc:
                raise DNSLookupError(f"{rdtype} {name}: {exc}") from exc
        return [_format(rdtype, rdata) for rdata in answer]


def _format(rdtype: str, rdata: Any) -> str:
    kind = rdtype.upper()
    if kind in ("A", "AAAA"):
        return str(rdata.address)
    if kind == "CNAME":
        return str(rdata.target.to_text()).rstrip(".").lower()
    if kind == "MX":
        host = str(rdata.exchange.to_text()).rstrip(".").lower()
        return f"{rdata.preference} {host}"
    if kind == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    return str(rdata.to_text())
