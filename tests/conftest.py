"""Shared offline test helpers: fake DNS, scope factory, MockTransport fetchers."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable

import httpx
import pytest

from reconvigil.dnsio import DNSLookupError
from reconvigil.security.safe_http import GuardedFetcher, HttpLimits
from reconvigil.security.scope import DEFAULT_PORTS, TargetScope

PUBLIC_IP = "93.184.216.34"


class FakeResolver:
    """Dict-backed resolver. Keys are (name, RDTYPE). Optional wildcard A for a suffix."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None) -> None:
        self.records: dict[tuple[str, str], list[str]] = {
            (n.lower(), t.upper()): list(v) for (n, t), v in (records or {}).items()
        }
        self.failing: set[tuple[str, str]] = set()
        self.wildcard: tuple[str, str] | None = None  # (suffix, ip)
        self.queries: list[tuple[str, str]] = []

    def add(self, name: str, *values: str, rdtype: str | None = None) -> FakeResolver:
        kind = rdtype or ("AAAA" if ":" in values[0] else "A")
        self.records.setdefault((name.lower(), kind), []).extend(values)
        return self

    async def query(self, name: str, rdtype: str) -> list[str]:
        key = (name.lower(), rdtype.upper())
        self.queries.append(key)
        if key in self.failing:
            raise DNSLookupError(f"{rdtype} {name}: timeout")
        if key in self.records:
            return list(self.records[key])
        if self.wildcard and key[1] == "A" and key[0].endswith(self.wildcard[0]):
            return [self.wildcard[1]]
        return []


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


def make_scope(
    resolver: FakeResolver,
    root: str = "target.com",
    *,
    block_private_ips: bool = True,
    allowed_ports: frozenset[int] | None = DEFAULT_PORTS,
) -> TargetScope:
    return TargetScope(
        root, resolver=resolver, block_private_ips=block_private_ips, allowed_ports=allowed_ports
    )


def make_fetcher(
    scope: TargetScope,
    handler: Callable[[httpx.Request], httpx.Response],
    limits: HttpLimits | None = None,
) -> GuardedFetcher:
    return GuardedFetcher(scope, limits, inner_transport=httpx.MockTransport(handler))


def req_host(request: httpx.Request) -> str:
    """Original hostname (the transport rewrites the URL to the pinned IP; Host is preserved)."""
    return request.headers["host"].split(":")[0]


class LabServer:
    """Tiny HTTP/1.1 server on 127.0.0.1 in its own thread/loop (so CLI asyncio.run works).

    `routes` maps path -> (status, headers, body); unknown paths get a 404.
    """

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], str]]) -> None:
        self.routes = routes
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()
        self._server: asyncio.AbstractServer | None = None
        self._dead: asyncio.AbstractServer | None = None
        self.dead_port = 0  # accepts then instantly closes (fast, deterministic 'TLS failure')

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(
            asyncio.start_server(self._handle, "127.0.0.1", 0)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._dead = self._loop.run_until_complete(
            asyncio.start_server(self._hang_up, "127.0.0.1", 0)
        )
        self.dead_port = self._dead.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    async def _hang_up(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            path = head.split(b" ", 2)[1].decode("latin-1").split("?")[0]
            status, headers, body = self.routes.get(
                path, (404, {"Content-Type": "text/plain"}, "nf")
            )
            data = body.encode()
            lines = [f"HTTP/1.1 {status} X", f"Content-Length: {len(data)}", "Connection: close"]
            lines += [f"{k}: {v}" for k, v in headers.items()]
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + data)
            await writer.drain()
        except (TimeoutError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    def __enter__(self) -> LabServer:
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc: object) -> None:
        async def _stop() -> None:
            for srv in (self._server, self._dead):
                if srv:
                    srv.close()

        asyncio.run_coroutine_threadsafe(_stop(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()
