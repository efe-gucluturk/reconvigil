"""Target scope validation and the SSRF / DNS-rebinding guard.

Everything that decides "may we talk to this host/URL/IP?" lives here.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import NamedTuple
from urllib.parse import unquote, urlsplit

from reconvigil.dnsio import DNSLookupError, Resolver

__all__ = [
    "DEFAULT_PORTS",
    "DNSLookupError",
    "SSRFBlockedError",
    "ScopeError",
    "TargetScope",
    "ValidatedURL",
    "is_blocked_ip",
    "normalize_hostname",
    "normalize_root_domain",
]

DEFAULT_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888})

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
_FORBIDDEN_HOST_CHARS = frozenset("/\\@:?#%[]*<>\"' \t\r\n\x00")

_BLOCKED_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)
# Cloud metadata endpoints: blocked even with --allow-private.
_METADATA_IPS = frozenset(
    ipaddress.ip_address(a) for a in ("169.254.169.254", "fd00:ec2::254", "100.100.100.200")
)


class ScopeError(ValueError):
    """Host/URL is malformed or out of scope."""


class SSRFBlockedError(ScopeError):
    """Host resolves to a blocked (private/loopback/link-local/reserved) address."""


class ValidatedURL(NamedTuple):
    url: str
    scheme: str
    host: str
    port: int | None


def normalize_hostname(raw: str, *, min_labels: int = 1) -> str:
    """Normalize and strictly validate a DNS hostname (no IPs, ports, creds, paths)."""
    if not isinstance(raw, str):
        raise ScopeError("hostname must be a string")
    value = raw.strip().lower()
    if not value or len(value) > 254:
        raise ScopeError("empty or too long hostname")
    if "://" in value or any(ch in _FORBIDDEN_HOST_CHARS for ch in value):
        raise ScopeError(f"malformed hostname (URL, credentials, path or port?): {raw!r}")
    if value.endswith("."):
        value = value[:-1]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname encoding: {raw!r}") from exc
    if len(value) > 253:
        raise ScopeError("hostname too long")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ScopeError("IP literals are not valid targets; use a domain name")
    labels = value.split(".")
    if len(labels) < min_labels:
        raise ScopeError(f"hostname needs at least {min_labels} label(s): {raw!r}")
    if labels[-1].isdigit():
        raise ScopeError("numeric TLD / IPv4-like hostname rejected")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise ScopeError(f"invalid DNS label {label!r} in {raw!r}")
    return value


def normalize_root_domain(raw: str) -> str:
    return normalize_hostname(raw, min_labels=2)


def is_blocked_ip(
    ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool = False
) -> bool:
    """True if connecting to `ip` must be refused."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable -> fail closed
    # Unwrap embedded IPv4 so ::ffff:127.0.0.1 / 6to4 / Teredo cannot smuggle private targets.
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        for embedded in (addr.ipv4_mapped, addr.sixtofour):
            if embedded is not None:
                candidates.append(embedded)
        if addr.teredo is not None:
            candidates.extend(addr.teredo)
    if any(c in _METADATA_IPS for c in candidates):
        return True
    if allow_private:
        return False
    return any(
        any(c in net for net in _BLOCKED_NETS) or not c.is_global or c.is_multicast
        for c in candidates
    )


class TargetScope:
    """Strict in-scope matching (`target.com` + `*.target.com`) and SSRF-safe resolution."""

    def __init__(
        self,
        root: str,
        *,
        resolver: Resolver,
        block_private_ips: bool = True,
        allowed_ports: frozenset[int] | None = DEFAULT_PORTS,
    ) -> None:
        self.root = normalize_root_domain(root)
        self.resolver = resolver
        self.block_private_ips = block_private_ips
        self.allowed_ports = allowed_ports

    # -- host / URL scope -------------------------------------------------
    def in_scope(self, host: str) -> bool:
        try:
            value = normalize_hostname(host)
        except ScopeError:
            return False
        return value == self.root or value.endswith("." + self.root)

    def require_in_scope(self, host: str) -> str:
        value = normalize_hostname(host)
        if not (value == self.root or value.endswith("." + self.root)):
            raise ScopeError(f"{value} is out of scope for {self.root}")
        return value

    def validate_url(self, url: str) -> ValidatedURL:
        if (
            not isinstance(url, str)
            or not url
            or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url)
        ):
            raise ScopeError("URL empty or contains whitespace/control characters")
        if "\\" in url:
            raise ScopeError("backslash in URL rejected")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError as exc:
            raise ScopeError(f"malformed URL: {exc}") from exc
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"scheme {parts.scheme!r} not allowed")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ScopeError("URLs with embedded credentials are rejected")
        if not parts.hostname:
            raise ScopeError("URL has no host")
        host = self.require_in_scope(parts.hostname)
        if port is not None and self.allowed_ports is not None and port not in self.allowed_ports:
            raise ScopeError(f"port {port} not allowed")
        if ".." in unquote(unquote(parts.path)).split("/"):
            raise ScopeError("path traversal rejected")
        return ValidatedURL(url, parts.scheme, host, port)

    # -- SSRF guard -------------------------------------------------------
    async def resolve_ips(self, host: str) -> list[str]:
        host = self.require_in_scope(host)
        a, aaaa = await asyncio.gather(
            self.resolver.query(host, "A"), self.resolver.query(host, "AAAA")
        )
        return sorted({*a, *aaaa})

    async def resolve_public(self, host: str) -> list[str]:
        """Resolve A/AAAA and refuse if ANY answer is blocked (rebinding/multi-record safe)."""
        ips = await self.resolve_ips(host)
        if not ips:
            raise DNSLookupError(f"{host} did not resolve to any address")
        for ip in ips:
            if is_blocked_ip(ip, allow_private=not self.block_private_ips):
                raise SSRFBlockedError(f"{host} resolves to blocked address {ip}")
        return ips
