from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import httpx
import pytest

from conftest import PUBLIC_IP, FakeResolver, make_fetcher, make_scope, req_host
from reconvigil.security.safe_http import MAX_BODY_BYTES, GuardedFetcher, HttpLimits


def _resolver(*hosts: str) -> FakeResolver:
    r = FakeResolver()
    for h in hosts:
        r.add(h, PUBLIC_IP)
    return r


# --------------------------------------------------------------- redirects
@pytest.mark.parametrize(
    "location",
    [
        "https://evil.com/x",
        "https://target.com.evil.com/",
        "https://eviltarget.com/",
        "https://user:pw@www.target.com/",
        "http://169.254.169.254/latest/meta-data/",
        "//evil.com/x",
    ],
)
async def test_redirect_to_out_of_scope_is_blocked(location: str) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(req_host(request))
        return httpx.Response(302, headers={"location": location})

    resolver = _resolver("www.target.com", "evil.com", "eviltarget.com", "target.com.evil.com")
    async with make_fetcher(make_scope(resolver), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert res.status == 302
    assert res.blocked_redirect is not None
    assert seen == ["www.target.com"]  # the out-of-scope host was never contacted


async def test_in_scope_redirect_followed_and_revalidated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if req_host(request) == "www.target.com":
            return httpx.Response(301, headers={"location": "https://app.target.com/home"})
        return httpx.Response(200, text="<title>Home</title>")

    resolver = _resolver("www.target.com", "app.target.com")
    async with make_fetcher(make_scope(resolver), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert res.status == 200
    assert res.chain == ["https://www.target.com/", "https://app.target.com/home"]
    assert res.blocked_redirect is None


async def test_redirect_to_in_scope_host_with_private_ip_blocked() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(req_host(request))
        return httpx.Response(302, headers={"location": "https://internal.target.com/admin"})

    resolver = _resolver("www.target.com").add("internal.target.com", "10.1.2.3")
    async with make_fetcher(make_scope(resolver), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert res.ssrf_blocked and res.blocked
    assert calls == ["www.target.com"]


async def test_redirect_loop_is_bounded() -> None:
    n = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        return httpx.Response(302, headers={"location": "/again"})

    async with make_fetcher(
        make_scope(_resolver("www.target.com")), handler, HttpLimits(max_redirects=3)
    ) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert n == 4 and res.status == 302


async def test_zero_redirects_returns_3xx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "/x"})

    async with make_fetcher(make_scope(_resolver("www.target.com")), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/", max_redirects=0)
    assert res.status == 301


# --------------------------------------------------------------- SSRF
@pytest.mark.parametrize("ip", ["169.254.169.254", "127.0.0.1"])
async def test_ssrf_private_ip_never_requested(ip: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, text="secret")

    resolver = FakeResolver().add("meta.target.com", ip)
    async with make_fetcher(make_scope(resolver), handler) as fetcher:
        res = await fetcher.get("http://meta.target.com/latest/meta-data/")
    assert res.ssrf_blocked and res.status is None
    assert calls == 0


async def test_out_of_scope_initial_url_blocked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not be called")

    async with make_fetcher(make_scope(_resolver("evil.com")), handler) as fetcher:
        res = await fetcher.get("https://evil.com/")
    assert res.blocked and res.status is None


async def test_ip_is_pinned_and_host_header_preserved() -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers["host"]))
        assert request.extensions["sni_hostname"] == "www.target.com"
        return httpx.Response(200, text="ok")

    async with make_fetcher(make_scope(_resolver("www.target.com")), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert res.status == 200
    assert seen == [(PUBLIC_IP, "www.target.com")]


# --------------------------------------------------------------- 1 MB cap
async def test_oversized_response_truncated_at_1mb() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * (3 * 1024 * 1024))

    async with make_fetcher(make_scope(_resolver("www.target.com")), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert len(res.body) == MAX_BODY_BYTES == 1024 * 1024
    assert res.truncated is True


async def test_exact_limit_not_flagged_truncated() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * MAX_BODY_BYTES)

    async with make_fetcher(make_scope(_resolver("www.target.com")), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert len(res.body) == MAX_BODY_BYTES and res.truncated is False


async def test_endless_stream_is_cut_off() -> None:
    produced = 0

    async def endless() -> AsyncIterator[bytes]:
        nonlocal produced
        while True:
            produced += 1
            yield b"B" * 65536

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=endless())

    async with make_fetcher(make_scope(_resolver("www.target.com")), handler) as fetcher:
        res = await fetcher.get("https://www.target.com/")
    assert res.truncated and len(res.body) == MAX_BODY_BYTES
    assert produced <= 20  # stopped reading right after the cap, did not drain the stream


# --------------------------------------------------------------- real local servers
async def _serve(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _lab_fetcher(port: int, limits: HttpLimits) -> GuardedFetcher:
    resolver = FakeResolver().add("lab.target.com", "127.0.0.1")
    scope = make_scope(resolver, block_private_ips=False, allowed_ports=frozenset({port}))
    return GuardedFetcher(scope, limits)  # real httpx transport against a local server


async def _read_request(reader: asyncio.StreamReader) -> None:
    await reader.readuntil(b"\r\n\r\n")


async def test_local_server_5mb_body_is_capped() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await _read_request(reader)
            total = 5 * 1024 * 1024
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n".encode()
            )
            for _ in range(total // 65536):
                writer.write(b"C" * 65536)
                await writer.drain()
        except OSError:
            pass  # client hung up after reaching its cap; expected
        finally:
            writer.close()

    server, port = await _serve(handle)
    try:
        async with _lab_fetcher(port, HttpLimits()) as fetcher:
            res = await fetcher.get(f"http://lab.target.com:{port}/")
    finally:
        server.close()
    assert res.status == 200 and res.truncated and len(res.body) == MAX_BODY_BYTES


async def test_local_server_tarpit_hits_total_deadline() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await _read_request(reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            for _ in range(100):
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0.1)
        except OSError:
            pass  # client gave up; expected
        finally:
            writer.close()

    server, port = await _serve(handle)
    try:
        limits = HttpLimits(total_timeout=0.7, read_timeout=5.0)
        async with _lab_fetcher(port, limits) as fetcher:
            res = await fetcher.get(f"http://lab.target.com:{port}/")
    finally:
        server.close()
    assert res.error is not None and "timeout" in res.error


async def test_local_server_pinned_ip_reaches_loopback_only_when_allowed() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _read_request(reader)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
        await writer.drain()
        writer.close()

    server, port = await _serve(handle)
    try:
        async with _lab_fetcher(port, HttpLimits()) as fetcher:
            ok = await fetcher.get(f"http://lab.target.com:{port}/")
        # Same server, but with the default guard on: must be refused before any connection.
        resolver = FakeResolver().add("lab.target.com", "127.0.0.1")
        guarded = GuardedFetcher(make_scope(resolver, allowed_ports=frozenset({port})))
        async with guarded as fetcher:
            blocked = await fetcher.get(f"http://lab.target.com:{port}/")
    finally:
        server.close()
    assert ok.body == b"hi"
    assert blocked.ssrf_blocked and blocked.status is None
