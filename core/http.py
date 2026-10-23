#!/usr/bin/env python3
"""
core/http.py — HTTP transport layer for php2shell
Author: ATHEX BLACK HAT

Design:
  - Async core (exchange, read_response, upload_body)
  - Sync wrapper (send_request) for use from ThreadPoolExecutor
  - Per-thread event loop reuse (no asyncio.run() per request)
  - Built-in rate limiting (per-host + global) via token bucket
  - Optional retry with exponential backoff
  - Optional HTTP proxy (Burp-style CONNECT tunnel)
  - h11 for strict HTTP/1.1 protocol handling
  - Streaming upload with backpressure
  - gzip response decoding with size cap
"""

from __future__ import annotations

import asyncio
import os
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urljoin, quote, urlunsplit

import h11

from core.config import (
    CONNECT_TIMEOUT,
    BODY_READ_LIMIT,
    EXCERPT_LIMIT,
    MAX_RESPONSE_HEADER_BYTES,
    UPLOAD_CHUNK_SIZE,
    READ_BUFFER_HIGH_WATER,
    READ_BUFFER_LOW_WATER,
    WRITE_BUFFER_HIGH_WATER,
    WRITE_BUFFER_LOW_WATER,
    MAX_REDIRECTS,
    DEFAULT_USER_AGENT,
    DEFAULT_ACCEPT,
    DEFAULT_ACCEPT_ENCODING,
    SENSITIVE_HEADERS,
    HEADER_NAME_PATTERN,
    DEFAULT_RATE_PER_HOST,
    DEFAULT_GLOBAL_RATE,
)
from core.logger import Logger


# ═══════════════════════════════════════════════════════════════════════════
#  EXCEPTIONS
# ═══════════════════════════════════════════════════════════════════════════

class HTTPError(Exception):
    """Base class for all HTTP transport errors."""


class HTTPTransportError(HTTPError):
    """Well-formed HTTP exchange could not be completed."""


class HTTPRateLimitError(HTTPError):
    """Rate limiter blocked the request (should be retried)."""


class HTTPProxyError(HTTPError):
    """Proxy connection or tunnel failed."""


# ═══════════════════════════════════════════════════════════════════════════
#  RESULT DATACLASS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class HTTPResult:
    """
    Response from a single HTTP exchange.

    Attributes are populated as available — on error, `error` is set
    and status_code/headers/body may be partially filled.
    """
    # Request info
    method: str = "GET"
    url: str = ""
    final_url: str = ""             # after redirects
    bytes_sent: int = 0
    bytes_received: int = 0
    request_headers: Dict[str, str] = field(default_factory=dict)

    # Response info
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    http_version: str = "HTTP/1.1"

    # Timing
    elapsed: float = 0.0            # total seconds (incl. redirects)
    ttfb: float = 0.0               # time to first byte
    dns_time: float = 0.0
    connect_time: float = 0.0
    tls_time: float = 0.0

    # Diagnostics
    error: Optional[str] = None
    redirects: List[str] = field(default_factory=list)
    retries: int = 0
    from_cache: bool = False

    # ── Convenience accessors ──

    def header(self, name: str) -> str:
        """Case-insensitive header lookup (returns first match)."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    def header_all(self, name: str) -> List[str]:
        """Return all values for a header (comma-joined)."""
        return [
            v for k, v in self.headers.items() if k.lower() == name.lower()
        ]

    @property
    def powered_by(self) -> str:
        return self.header("x-powered-by")

    @property
    def server(self) -> str:
        return self.header("server")

    @property
    def content_type(self) -> str:
        return self.header("content-type")

    @property
    def body_text(self) -> str:
        """UTF-8 decoded body, truncated to EXCERPT_LIMIT."""
        return self.body[:EXCERPT_LIMIT].decode("utf-8", errors="replace")

    @property
    def is_success(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

    @property
    def is_blocked(self) -> bool:
        """True if status suggests a WAF/proxy block."""
        return self.status_code in (403, 406, 429, 501, 503)

    def summary(self) -> str:
        """One-line summary for logging."""
        if self.error:
            return f"{self.method} {self.url} → ERROR: {self.error}"
        return (
            f"{self.method} {self.url} → HTTP {self.status_code} "
            f"({self.bytes_received}B, {self.elapsed*1000:.0f}ms)"
        )


# ═══════════════════════════════════════════════════════════════════════════
#  RATE LIMITER (token bucket, per-host + global)
# ═══════════════════════════════════════════════════════════════════════════

class TokenBucket:
    """
    Async-safe token bucket.

    - `capacity`: max burst size
    - `refill_rate`: tokens per second
    """

    __slots__ = ("capacity", "refill_rate", "tokens", "last_refill", "_lock")

    def __init__(self, capacity: float, refill_rate: float):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0, timeout: Optional[float] = None) -> None:
        """Block until tokens are available. Raises HTTPRateLimitError on timeout."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            async with self._lock:
                now = time.monotonic()
                delta = now - self.last_refill
                self.tokens = min(self.capacity, self.tokens + delta * self.refill_rate)
                self.last_refill = now
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return
                needed = tokens - self.tokens
                wait_s = needed / self.refill_rate if self.refill_rate > 0 else 1.0
            if deadline is not None and time.monotonic() + wait_s > deadline:
                raise HTTPRateLimitError(
                    f"rate limit timeout (needed {needed:.2f} tokens)"
                )
            await asyncio.sleep(min(wait_s, 0.5))


class RateLimiter:
    """
    Two-level rate limiter:
      - global bucket (all hosts combined)
      - per-host bucket (individual host)

    Both must grant before request proceeds.
    """

    def __init__(
        self,
        per_host_rate: float = DEFAULT_RATE_PER_HOST,
        global_rate: float = DEFAULT_GLOBAL_RATE,
        burst: int = 5,
    ):
        self.per_host_rate = max(0.1, per_host_rate)
        self.global_rate = max(0.1, global_rate)
        self.burst = max(1, burst)
        self._global = TokenBucket(capacity=self.burst, refill_rate=self.global_rate)
        self._hosts: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def _get_host_bucket(self, host: str) -> TokenBucket:
        async with self._lock:
            bucket = self._hosts.get(host)
            if bucket is None:
                bucket = TokenBucket(capacity=self.burst, refill_rate=self.per_host_rate)
                self._hosts[host] = bucket
            return bucket

    async def acquire(self, host: str, timeout: Optional[float] = None) -> None:
        # Global first (cheaper to fail fast)
        await self._global.acquire(timeout=timeout)
        bucket = await self._get_host_bucket(host)
        await bucket.acquire(timeout=timeout)


# ═══════════════════════════════════════════════════════════════════════════
#  PROXY (HTTP CONNECT tunnel)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ProxyConfig:
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    @classmethod
    def parse(cls, proxy_url: str) -> "ProxyConfig":
        if "://" not in proxy_url:
            proxy_url = "http://" + proxy_url
        parsed = urlsplit(proxy_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"unsupported proxy scheme: {parsed.scheme}")
        return cls(
            host=parsed.hostname or "127.0.0.1",
            port=parsed.port or 8080,
            username=parsed.username,
            password=parsed.password,
        )

    def auth_header(self) -> Optional[bytes]:
        if self.username is None:
            return None
        import base64
        creds = f"{self.username}:{self.password or ''}".encode()
        return b"Basic " + base64.b64encode(creds)


# ═══════════════════════════════════════════════════════════════════════════
#  ASYNCIO PROTOCOL (streaming upload + backpressure)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _ConnectionEnd:
    error: Optional[Exception]


class DuplexHTTPProtocol(asyncio.Protocol):
    """
    Bidirectional HTTP protocol with proper backpressure.

    - Reading: pauses transport when queue > HIGH_WATER
    - Writing: pauses on `pause_writing()`, resumes on `resume_writing()`
    """

    def __init__(self) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.incoming: asyncio.Queue[bytes | _ConnectionEnd] = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False
        self.ended = False
        self.end_error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        transport.set_write_buffer_limits(  # type: ignore[attr-defined]
            high=WRITE_BUFFER_HIGH_WATER,
            low=WRITE_BUFFER_LOW_WATER,
        )

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        if (
            self.buffered_bytes >= READ_BUFFER_HIGH_WATER
            and not self.reading_paused
            and self.transport is not None
        ):
            self.transport.pause_reading()  # type: ignore[attr-defined]
            self.reading_paused = True

    def eof_received(self) -> Optional[bool]:
        self._finish(None)
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._finish(exc)

    def pause_writing(self) -> None:
        self.writable.clear()

    def resume_writing(self) -> None:
        self.writable.set()

    def _finish(self, error: Optional[Exception]) -> None:
        if self.ended:
            return
        self.ended = True
        self.end_error = error
        self.writable.set()
        self.incoming.put_nowait(_ConnectionEnd(error))

    async def write(self, data: bytes) -> None:
        await self.writable.wait()
        if self.ended or self.transport is None:
            raise self.end_error or BrokenPipeError("connection closed while uploading")
        self.transport.write(data)  # type: ignore[attr-defined]
        await asyncio.sleep(0)

    async def read(self) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, _ConnectionEnd):
            if item.error is not None:
                raise item.error
            return b""
        self.buffered_bytes -= len(item)
        if (
            self.reading_paused
            and self.buffered_bytes <= READ_BUFFER_LOW_WATER
            and self.transport is not None
            and not self.ended
        ):
            self.transport.resume_reading()  # type: ignore[attr-defined]
            self.reading_paused = False
        return item

    def abort(self) -> None:
        if self.transport is not None:
            self.transport.abort()


# ═══════════════════════════════════════════════════════════════════════════
#  REQUEST/RESPONSE SERIALIZATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def request_target(parsed) -> bytes:
    """Build URL path+query for the HTTP request line (ASCII-safe)."""
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
        encoding="utf-8",
        errors="strict",
    )
    if parsed.query:
        path += "?" + quote(
            parsed.query,
            safe="/?%:@!$&'()*+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    return path.encode("ascii")


def host_header(parsed) -> str:
    """Build Host: header value (IDNA-encoded, with port if non-default)."""
    if not parsed.hostname:
        raise ValueError("target URL does not contain a hostname")
    hostname = parsed.hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"  # IPv6
    if parsed.port is not None:
        hostname += f":{parsed.port}"
    return hostname


def wire_headers(
    parsed,
    headers: Dict[str, str],
    body_size: int,
    method: str,
) -> List[Tuple[bytes, bytes]]:
    """
    Convert header dict to h11 wire format.

    - Ensures Host: present
    - Adds Content-Length: for POST/PUT/PATCH if body present
    - Skips user-supplied Content-Length/Transfer-Encoding (we control those)
    """
    supplied_host = ""
    for k, v in headers.items():
        if k.lower() == "host":
            supplied_host = v
            break
    host = supplied_host or host_header(parsed)

    wire: List[Tuple[bytes, bytes]] = [(b"Host", host.encode("latin-1"))]
    for name, value in headers.items():
        low = name.lower()
        if low in ("host", "content-length", "transfer-encoding"):
            continue
        wire.append((name.encode("ascii"), value.encode("latin-1")))

    if method in ("POST", "PUT", "PATCH"):
        wire.append((b"Content-Length", str(body_size).encode("ascii")))

    return wire


def response_headers(raw: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    """Merge duplicate headers (e.g. Set-Cookie) with comma (except Set-Cookie)."""
    result: Dict[str, str] = {}
    for raw_name, raw_value in raw:
        name = raw_name.decode("ascii", errors="replace")
        value = raw_value.decode("latin-1", errors="replace")
        if name in result:
            if name.lower() == "set-cookie":
                result[name] += "\n" + value
            else:
                result[name] += ", " + value
        else:
            result[name] = value
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  BODY UPLOAD / DECODE
# ═══════════════════════════════════════════════════════════════════════════

async def upload_body(
    connection: h11.Connection,
    protocol: DuplexHTTPProtocol,
    body: bytes,
) -> None:
    """Stream body in chunks to avoid buffering everything at once."""
    for offset in range(0, len(body), UPLOAD_CHUNK_SIZE):
        data = connection.send(
            h11.Data(data=body[offset : offset + UPLOAD_CHUNK_SIZE])
        )
        if data:
            await protocol.write(data)
    end = connection.send(h11.EndOfMessage())
    if end:
        await protocol.write(end)


async def decode_gzip(
    decoder: zlib._Decompress,
    data: bytes,
    body: bytearray,
) -> zlib._Decompress:
    """Stream-decode gzip data into `body` (respects BODY_READ_LIMIT)."""
    pending = data
    if decoder.eof and pending:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    while pending:
        try:
            decoded = decoder.decompress(pending, UPLOAD_CHUNK_SIZE)
        except zlib.error as exc:
            raise HTTPTransportError(f"invalid gzip response: {exc}") from exc

        remaining = BODY_READ_LIMIT - len(body)
        if remaining > 0:
            body.extend(decoded[:remaining])

        if decoder.eof:
            pending = decoder.unused_data
            if pending:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        else:
            pending = decoder.unconsumed_tail

        if pending:
            await asyncio.sleep(0)
    return decoder


async def read_response(
    connection: h11.Connection,
    protocol: DuplexHTTPProtocol,
    result: HTTPResult,
) -> HTTPResult:
    """Parse a single HTTP response from the wire into `result`."""
    decoder: Optional[zlib._Decompress] = None
    body = bytearray()
    first_byte_at: Optional[float] = None

    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            data = await protocol.read()
            connection.receive_data(data)
            continue

        if event is h11.PAUSED:
            raise HTTPTransportError("unexpected additional HTTP response")

        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise HTTPTransportError("HTTP protocol upgrades are not supported")
            continue

        if isinstance(event, h11.Response):
            result.status_code = event.status_code
            result.reason = event.reason.decode("latin-1", errors="replace")
            result.headers = response_headers(list(event.headers))
            result.http_version = f"HTTP/1.{event.http_version[1]}"
            ce = result.header("content-encoding").strip().lower()
            if ce == "gzip":
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                result.headers = {k: v for k, v in result.headers.items()
                                  if k.lower() not in ("content-encoding", "content-length")}
            elif ce not in ("", "identity"):
                raise HTTPTransportError(f"unsupported content encoding: {ce}")
            continue

        if isinstance(event, h11.Data):
            if result.status_code is None:
                raise HTTPTransportError("received body before headers")
            if first_byte_at is None:
                first_byte_at = time.perf_counter()
            if decoder is not None:
                decoder = await decode_gzip(decoder, event.data, body)
            else:
                remaining = BODY_READ_LIMIT - len(body)
                if remaining > 0:
                    body.extend(event.data[:remaining])
            continue

        if isinstance(event, h11.EndOfMessage):
            if result.status_code is None:
                raise HTTPTransportError("response ended before headers")
            if decoder is not None:
                try:
                    tail = decoder.flush()
                except zlib.error as exc:
                    raise HTTPTransportError(f"invalid gzip: {exc}") from exc
                remaining = BODY_READ_LIMIT - len(body)
                body.extend(tail[:remaining])
                if not decoder.eof:
                    raise HTTPTransportError("truncated gzip response")
            result.body = bytes(body)
            result.bytes_received = len(result.body)
            return result

        if isinstance(event, h11.ConnectionClosed):
            raise HTTPTransportError("connection closed before response completed")


# ═══════════════════════════════════════════════════════════════════════════
#  CONNECTION SETUP
# ═══════════════════════════════════════════════════════════════════════════

async def _open_proxy_tunnel(
    proxy: ProxyConfig,
    target_host: str,
    target_port: int,
    timeout: float,
) -> Tuple[asyncio.Transport, DuplexHTTPProtocol]:
    """
    Open a TCP connection to proxy, send CONNECT, return raw transport
    for TLS wrapping by caller.
    """
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await asyncio.wait_for(
            loop.create_connection(DuplexHTTPProtocol, host=proxy.host, port=proxy.port),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise HTTPProxyError(f"cannot connect to proxy {proxy.host}:{proxy.port}: {exc}") from exc

    if not isinstance(proto, DuplexHTTPProtocol):
        transport.abort()
        raise HTTPProxyError("proxy protocol init failed")

    # Send CONNECT
    connect_lines = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    auth = proxy.auth_header()
    if auth:
        connect_lines.append(f"Proxy-Authorization: {auth.decode('latin-1')}")
    connect_lines.append("")
    connect_lines.append("")
    transport.write("\r\n".join(connect_lines).encode("latin-1"))

    # Read response headers (until \r\n\r\n)
    buffer = b""
    deadline = time.monotonic() + timeout
    while b"\r\n\r\n" not in buffer:
        if time.monotonic() > deadline:
            transport.abort()
            raise HTTPProxyError("proxy CONNECT timeout")
        chunk = await proto.read()
        if not chunk:
            transport.abort()
            raise HTTPProxyError("proxy closed connection during CONNECT")
        buffer += chunk

    header_blob, _, leftover = buffer.partition(b"\r\n\r\n")
    first_line = header_blob.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if " 200 " not in first_line:
        transport.abort()
        raise HTTPProxyError(f"proxy CONNECT failed: {first_line}")

    return transport, proto


async def _connect(
    parsed,
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig],
    sni_hostname: Optional[str],
) -> Tuple[asyncio.Transport, DuplexHTTPProtocol]:
    """Establish TCP (and TLS if needed) connection to target."""
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL does not contain a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    use_tls = parsed.scheme == "https"
    ssl_ctx: Optional[ssl.SSLContext] = None
    if use_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.set_alpn_protocols(["http/1.1"])
        if not verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_running_loop()
    connect_timeout = min(CONNECT_TIMEOUT, timeout)

    if proxy is None:
        # Direct connection
        kwargs = {}
        if use_tls:
            kwargs = {
                "ssl": ssl_ctx,
                "server_hostname": sni_hostname or hostname,
                "ssl_handshake_timeout": connect_timeout,
            }
        try:
            transport, proto = await asyncio.wait_for(
                loop.create_connection(
                    DuplexHTTPProtocol,
                    host=hostname,
                    port=port,
                    happy_eyeballs_delay=0.25,
                    **kwargs,
                ),
                timeout=connect_timeout,
            )
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
            raise HTTPTransportError(f"connection failed: {exc}") from exc
        if not isinstance(proto, DuplexHTTPProtocol):
            transport.abort()
            raise HTTPTransportError("protocol init failed")
        return transport, proto

    # ── Via proxy ──
    raw_transport, raw_proto = await _open_proxy_tunnel(
        proxy, hostname, port, connect_timeout
    )

    if not use_tls:
        return raw_transport, raw_proto

    # TLS-wrap the tunneled socket
    ssl_transport, ssl_proto = await asyncio.wait_for(
        loop.start_tls(
            raw_transport, raw_proto, ssl_ctx,
            server_hostname=sni_hostname or hostname,
            ssl_handshake_timeout=connect_timeout,
        ),
        timeout=connect_timeout,
    )
    if not isinstance(ssl_proto, DuplexHTTPProtocol):
        ssl_transport.abort()
        raise HTTPTransportError("TLS protocol init failed")
    return ssl_transport, ssl_proto


# ═══════════════════════════════════════════════════════════════════════════
#  CORE EXCHANGE
# ═══════════════════════════════════════════════════════════════════════════

async def exchange(
    target_url: str,
    method: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: float,
    verify_ssl: bool,
    proxy: Optional[ProxyConfig] = None,
) -> HTTPResult:
    """Perform a single HTTP request/response cycle (no redirects)."""
    parsed = urlsplit(target_url)
    if not parsed.hostname:
        raise ValueError("target URL does not contain a hostname")

    result = HTTPResult(method=method.upper(), url=target_url)
    result.request_headers = dict(headers)

    t0 = time.perf_counter()
    transport, proto = await _connect(
        parsed, timeout, verify_ssl, proxy,
        sni_hostname=parsed.hostname,
    )
    result.connect_time = time.perf_counter() - t0

    upload_task: Optional[asyncio.Task] = None
    try:
        connection = h11.Connection(
            h11.CLIENT,
            max_incomplete_event_size=MAX_RESPONSE_HEADER_BYTES,
        )
        request = h11.Request(
            method=method.upper().encode("ascii"),
            target=request_target(parsed),
            headers=wire_headers(parsed, headers, len(body), method.upper()),
        )
        head = connection.send(request)
        if head:
            await proto.write(head)

        if body:
            upload_task = asyncio.create_task(upload_body(connection, proto, body))
        elif method.upper() in ("POST", "PUT", "PATCH"):
            end = connection.send(h11.EndOfMessage())
            if end:
                await proto.write(end)

        result = await read_response(connection, proto, result)
        result.elapsed = time.perf_counter() - t0
        result.bytes_sent = len(body)
        return result

    finally:
        if upload_task is not None:
            if not upload_task.done():
                upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        proto.abort()


# ═══════════════════════════════════════════════════════════════════════════
#  PER-THREAD EVENT LOOP (major performance win vs asyncio.run)
# ═══════════════════════════════════════════════════════════════════════════

_thread_state = threading.local()


def _get_thread_loop() -> asyncio.AbstractEventLoop:
    """Get or create an event loop for the current thread."""
    loop = getattr(_thread_state, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _thread_state.loop = loop
        _thread_state.rate_limiter = RateLimiter()
    return loop


def _get_thread_rate_limiter() -> RateLimiter:
    _get_thread_loop()
    return _thread_state.rate_limiter  # type: ignore[attr-defined]


def shutdown_thread_loop() -> None:
    """Close the current thread's event loop (call at thread exit)."""
    loop = getattr(_thread_state, "loop", None)
    if loop is not None and not loop.is_closed():
        loop.close()
    _thread_state.loop = None
    _thread_state.rate_limiter = None


def _run_coro(coro, timeout: float):
    """Run a coroutine in the thread-local event loop."""
    loop = _get_thread_loop()
    return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))


# ═══════════════════════════════════════════════════════════════════════════
#  PUBLIC SYNC API
# ═══════════════════════════════════════════════════════════════════════════

def send_request(
    target_url: str,
    method: str = "GET",
    body: bytes = b"",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    verify_ssl: bool = True,
    follow_redirects: bool = False,
    proxy: Optional[ProxyConfig] = None,
    retries: int = 0,
    rate_limit: bool = True,
) -> HTTPResult:
    """
    Send an HTTP request (sync). Handles redirects, retries, rate limiting.

    Args:
        target_url: URL (http:// or https://)
        method: GET, POST, PUT, DELETE, etc.
        body: request body bytes
        headers: custom headers dict
        timeout: per-attempt timeout (seconds)
        verify_ssl: verify TLS certs
        follow_redirects: follow 3xx up to MAX_REDIRECTS
        proxy: ProxyConfig or None
        retries: retry count on transient errors (0 = no retry)
        rate_limit: apply per-host + global rate limit

    Returns:
        HTTPResult (check .error for failures)
    """
    hdrs = dict(headers or {})
    if "User-Agent" not in hdrs and "user-agent" not in {k.lower() for k in hdrs}:
        hdrs["User-Agent"] = DEFAULT_USER_AGENT
    if "Accept" not in hdrs and "accept" not in {k.lower() for k in hdrs}:
        hdrs["Accept"] = DEFAULT_ACCEPT
    if "Accept-Encoding" not in hdrs and "accept-encoding" not in {k.lower() for k in hdrs}:
        hdrs["Accept-Encoding"] = DEFAULT_ACCEPT_ENCODING
    if "Connection" not in hdrs and "connection" not in {k.lower() for k in hdrs}:
        hdrs["Connection"] = "close"

    method = method.upper()
    original_url = target_url
    current_url = target_url
    redirects: List[str] = []
    total_start = time.perf_counter()

    attempt = 0
    max_attempts = max(0, retries) + 1
    last_result: Optional[HTTPResult] = None

    while attempt < max_attempts:
        attempt += 1
        redirect_chain = [] if attempt > 1 else redirects
        current = current_url

        for hop in range(MAX_REDIRECTS + 1 if follow_redirects else 1):
            parsed = urlsplit(current)
            if parsed.hostname is None:
                r = HTTPResult(method=method, url=current)
                r.error = "invalid URL: no hostname"
                return r

            # Rate limit
            if rate_limit:
                try:
                    limiter = _get_thread_rate_limiter()
                    _run_coro(
                        limiter.acquire(parsed.hostname.lower(), timeout=timeout),
                        timeout=timeout,
                    )
                except HTTPRateLimitError as exc:
                    if attempt >= max_attempts:
                        r = HTTPResult(method=method, url=current)
                        r.error = f"rate limit: {exc}"
                        return r
                    time.sleep(min(2 ** (attempt - 1), 30))
                    break  # retry outer loop

            # Attempt exchange
            try:
                result = _run_coro(
                    exchange(
                        current, method, body, hdrs, timeout, verify_ssl, proxy,
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                result = HTTPResult(method=method, url=current)
                result.error = "request timed out"
            except ssl.SSLError as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"SSL error: {exc}"
            except HTTPProxyError as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"proxy error: {exc}"
            except HTTPTransportError as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"transport error: {exc}"
            except h11.RemoteProtocolError as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"response parse error: {exc}"
            except (h11.LocalProtocolError, ValueError, UnicodeError) as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"request error: {exc}"
            except OSError as exc:
                result = HTTPResult(method=method, url=current)
                result.error = f"connection error: {exc}"

            result.final_url = current
            result.redirects = list(redirect_chain)
            last_result = result

            # Retry on transient errors
            if result.error and attempt < max_attempts:
                is_transient = any(
                    kw in result.error.lower()
                    for kw in ("timed out", "connection error", "transport error",
                               "reset", "refused", "temporary")
                )
                if is_transient:
                    backoff = min(2 ** (attempt - 1), 30)
                    Logger.debug(
                        f"Retry {attempt}/{max_attempts - 1} after {backoff}s: {result.error}",
                    )
                    time.sleep(backoff)
                    break  # retry outer loop

            # Handle redirects
            location = result.header("Location").strip()
            if (
                follow_redirects
                and result.status_code in (301, 302, 303, 307, 308)
                and location
            ):
                if hop == MAX_REDIRECTS:
                    result.error = f"too many redirects (limit {MAX_REDIRECTS})"
                    result.elapsed = time.perf_counter() - total_start
                    return result
                next_url = urljoin(current, location)
                old, new = urlsplit(current), urlsplit(next_url)
                if new.scheme not in ("http", "https") or not new.hostname:
                    result.error = f"redirect to unsupported URL: {location}"
                    result.elapsed = time.perf_counter() - total_start
                    return result
                # Strip sensitive headers on host change
                if (old.scheme.lower(), old.netloc.lower()) != (
                    new.scheme.lower(), new.netloc.lower()
                ):
                    for name in list(hdrs):
                        if name.lower() in SENSITIVE_HEADERS or name.lower() == "host":
                            del hdrs[name]
                redirect_chain.append(next_url)
                current = next_url
                # For 303, switch to GET
                if result.status_code == 303:
                    method = "GET"
                    body = b""
                continue

            # Non-redirect response: done
            result.elapsed = time.perf_counter() - total_start
            result.bytes_sent = len(body) * max(1, len(redirect_chain) + 1)
            return result

        else:
            # Loop ended via break (retry) — continue outer
            continue

    # All retries exhausted
    if last_result is None:
        last_result = HTTPResult(method=method, url=original_url)
        last_result.error = "unknown error"
    last_result.elapsed = time.perf_counter() - total_start
    return last_result


# ═══════════════════════════════════════════════════════════════════════════
#  CONVENIENCE WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════

def http_get(url: str, **kwargs) -> HTTPResult:
    """Convenience GET."""
    return send_request(url, "GET", b"", **kwargs)


def http_post(url: str, body: bytes = b"", **kwargs) -> HTTPResult:
    """Convenience POST."""
    return send_request(url, "POST", body, **kwargs)


def http_head(url: str, **kwargs) -> HTTPResult:
    """Convenience HEAD."""
    return send_request(url, "HEAD", b"", **kwargs)


# ═══════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return copy of headers with sensitive values redacted (for logging)."""
    return {
        k: ("<redacted>" if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def validate_header_name(name: str) -> bool:
    """Check if header name is RFC 7230 valid."""
    import re
    return bool(re.fullmatch(HEADER_NAME_PATTERN, name))


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORTS
# ═══════════════════════════════════════════════════════════════════════════

__all__ = [
    # Exceptions
    "HTTPError", "HTTPTransportError", "HTTPRateLimitError", "HTTPProxyError",
    # Types
    "HTTPResult", "ProxyConfig", "RateLimiter", "TokenBucket",
    # Sync API
    "send_request", "http_get", "http_post", "http_head",
    # Helpers
    "redact_headers", "validate_header_name",
    # Lifecycle
    "shutdown_thread_loop",
]