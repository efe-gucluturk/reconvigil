from __future__ import annotations

import pytest

from conftest import PUBLIC_IP, FakeResolver, make_scope
from reconvigil.dnsio import DNSLookupError
from reconvigil.security.scope import (
    ScopeError,
    SSRFBlockedError,
    is_blocked_ip,
    normalize_hostname,
    normalize_root_domain,
)


@pytest.mark.parametrize(
    "bad",
    [
        "http://target.com",
        "user:pw@target.com",
        "target.com/../etc",
        "target.com/path",
        "target.com:8080",
        "-bad.target.com",
        "a..target.com",
        "127.0.0.1",
        "::1",
        "",
        "   ",
        "ta rget.com",
        "target.com\\evil",
        "*.target.com",
        "target.com?x=1",
        "a" * 64 + ".target.com",
        "2130706433",
        "1.2.3.4.5",
    ],
)
def test_malformed_hostnames_rejected(bad: str) -> None:
    with pytest.raises(ScopeError):
        normalize_hostname(bad)


def test_root_domain_needs_two_labels() -> None:
    with pytest.raises(ScopeError):
        normalize_root_domain("localhost")


def test_normalization() -> None:
    assert normalize_root_domain(" Target.COM. ") == "target.com"
    assert normalize_hostname("bücher.example").startswith("xn--")


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("target.com", True),
        ("www.target.com", True),
        ("a.b.target.com", True),
        ("WWW.Target.Com.", True),
        ("evil-target.com", False),
        ("eviltarget.com", False),
        ("target.com.evil.com", False),
        ("www.target.com.evil.com", False),
        ("target.co", False),
        ("com", False),
        ("not a host", False),
        ("127.0.0.1", False),
    ],
)
def test_scope_boundary(host: str, expected: bool) -> None:
    assert make_scope(FakeResolver()).in_scope(host) is expected


def test_require_in_scope_raises() -> None:
    with pytest.raises(ScopeError):
        make_scope(FakeResolver()).require_in_scope("evil.com")


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pw@api.target.com/",
        "https://api.target.com@evil.com/",
        "https://evil.com@api.target.com/x",
        "http://evil.com/",
        "https://target.com.evil.com/",
        "ftp://api.target.com/",
        "file:///etc/passwd",
        "https://api.target.com/a/../../etc/passwd",
        "https://api.target.com/%2e%2e/x",
        "https://api.target.com/%252e%252e/x",
        "https://api.target.com:22/",
        "https://api.target.com\\@evil.com/",
        "https://api.target.com/ x",
        "http://127.0.0.1/",
        "",
    ],
)
def test_validate_url_rejects(url: str) -> None:
    with pytest.raises(ScopeError):
        make_scope(FakeResolver()).validate_url(url)


def test_validate_url_accepts_in_scope() -> None:
    scope = make_scope(FakeResolver())
    v = scope.validate_url("https://Api.target.com:8443/v1/x?y=1")
    assert (v.scheme, v.host, v.port) == ("https", "api.target.com", 8443)


# ------------------------------------------------------------------ SSRF guard
@pytest.mark.parametrize(
    "ip",
    [
        "169.254.169.254",
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.5",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.1.1",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "not-an-ip",
    ],
)
def test_blocked_ips(ip: str) -> None:
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", [PUBLIC_IP, "8.8.8.8", "2606:4700:4700::1111", "172.32.0.1"])
def test_public_ips_allowed(ip: str) -> None:
    assert is_blocked_ip(ip) is False


@pytest.mark.parametrize("ip", ["169.254.169.254", "127.0.0.1", "10.0.0.5", "::1"])
async def test_resolve_public_blocks_private(ip: str) -> None:
    resolver = FakeResolver().add("app.target.com", ip)
    with pytest.raises(SSRFBlockedError):
        await make_scope(resolver).resolve_public("app.target.com")


async def test_rebinding_multi_record_blocked() -> None:
    resolver = FakeResolver().add("app.target.com", "8.8.8.8", "127.0.0.1")
    with pytest.raises(SSRFBlockedError):
        await make_scope(resolver).resolve_public("app.target.com")


async def test_ipv6_private_answer_blocked() -> None:
    resolver = FakeResolver().add("app.target.com", PUBLIC_IP).add("app.target.com", "::1")
    with pytest.raises(SSRFBlockedError):
        await make_scope(resolver).resolve_public("app.target.com")


async def test_public_resolution_ok() -> None:
    resolver = FakeResolver().add("app.target.com", PUBLIC_IP)
    assert await make_scope(resolver).resolve_public("app.target.com") == [PUBLIC_IP]


async def test_allow_private_permits_loopback_but_never_metadata() -> None:
    resolver = (
        FakeResolver().add("lab.target.com", "127.0.0.1").add("imds.target.com", "169.254.169.254")
    )
    scope = make_scope(resolver, block_private_ips=False)
    assert await scope.resolve_public("lab.target.com") == ["127.0.0.1"]
    with pytest.raises(SSRFBlockedError):
        await scope.resolve_public("imds.target.com")


async def test_unresolvable_host_fails_closed() -> None:
    with pytest.raises(DNSLookupError):
        await make_scope(FakeResolver()).resolve_public("ghost.target.com")


async def test_out_of_scope_host_never_resolved() -> None:
    resolver = FakeResolver().add("evil.com", PUBLIC_IP)
    with pytest.raises(ScopeError):
        await make_scope(resolver).resolve_public("evil.com")
    assert resolver.queries == []


@pytest.mark.parametrize(
    "ip",
    ["64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "::7f00:1", "fec0::1", "::ffff:0:7f00:1"],
)
def test_embedded_ipv4_ipv6_forms_blocked(ip: str) -> None:
    assert is_blocked_ip(ip)
