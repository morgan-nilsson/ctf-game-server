"""Strict per-version HTTP clients for the referee (SETUP §6 "Stage-1 prober").

RULES §6: "up" means *answers correctly for that specific version*. A liveness
ping is not enough, and a server that answers HTTP/1.1 to every request must
not pass the HTTP/1.0 rung by accident. So each version gets its own client
with its own correctness bar:

  0.9  request is a bare `GET <path>CRLF`; the response MUST be a naked body
       with no status line, terminated by connection close.
  1.0  status line MUST be `HTTP/1.0`; body framed by Content-Length or by
       close; the server MUST close (no implicit keep-alive).
  1.1  status line MUST be `HTTP/1.1`; Host is mandatory; body framed by
       Content-Length or chunked transfer-coding; the connection MUST survive
       a second request on the same socket unless the server said `close`.
  2    h2c with prior knowledge: preface + SETTINGS exchange, HPACK'd HEADERS,
       DATA, END_STREAM. No Upgrade dance (that is a 1.1 feature).

Nothing here uses http.client: the referee has to judge wire bytes, not have a
library normalise them away.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field

from . import hpack

CRLF = b"\r\n"
MAX_BODY = 1 << 20          # a note is tiny; anything larger is a broken server
MAX_HEADER = 64 << 10
MAX_CHUNKS = 4096           # a note-sized body needs one


class ProtocolError(Exception):
    """The peer answered, but not correctly for this version."""


class Budget:
    """A hard wall-clock ceiling for one request.

    THE PROBER IS ATTACK SURFACE. It is the one channel that must stay open
    into a hostile service (RULES §1 stops a service *dialing* the referee;
    it cannot stop the referee reading player-controlled bytes), so every
    read here is bounded three ways: by a declared-size cap, by a per-recv
    socket timeout, and by this budget.

    The socket timeout alone is not enough. A service that dribbles one byte
    just inside the timeout, forever, keeps a recv alive indefinitely — the
    probe never returns, and its pool thread is consumed for the rest of the
    game. That is a two-line denial of service against the referee, from the
    sanctioned reply channel, and only a wall clock catches it.
    """

    __slots__ = ("deadline", "seconds")

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds

    def left(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError(f"request exceeded its {self.seconds:.1f}s budget")
        return remaining

    def arm(self, sock: socket.socket, per_op: float) -> None:
        sock.settimeout(min(per_op, self.left()))


@dataclass
class Response:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    closed: bool = False

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def ok(self) -> bool:
        # status None only happens on an h2 response whose :status was
        # Huffman-coded; framing was still valid (see hpack module docstring).
        return self.status is None or 200 <= self.status < 300


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def _read_until(sock: socket.socket, marker: bytes, limit: int,
                budget: Budget, per_op: float) -> tuple[bytes, bytes]:
    buf = b""
    while marker not in buf:
        if len(buf) > limit:
            raise ProtocolError("header section too large")
        budget.arm(sock, per_op)
        chunk = sock.recv(8192)
        if not chunk:
            raise ProtocolError("connection closed mid-header")
        buf += chunk
    head, _, rest = buf.partition(marker)
    return head, rest


def _read_all(sock: socket.socket, budget: Budget, per_op: float,
              prefix: bytes = b"") -> bytes:
    buf = bytearray(prefix)
    while True:
        if len(buf) > MAX_BODY:
            raise ProtocolError(f"body exceeded {MAX_BODY} bytes")
        budget.arm(sock, per_op)
        try:
            chunk = sock.recv(8192)
        except (TimeoutError, socket.timeout):
            raise ProtocolError("timed out waiting for connection close")
        if not chunk:
            return bytes(buf)
        buf += chunk


def _read_exact(sock: socket.socket, n: int, budget: Budget, per_op: float,
                prefix: bytes = b"") -> bytes:
    # The caller checks the declared length against MAX_BODY before we get
    # here; this is the belt to that braces.
    if n > MAX_BODY:
        raise ProtocolError(f"declared body of {n} bytes exceeds {MAX_BODY}")
    buf = bytearray(prefix)
    while len(buf) < n:
        budget.arm(sock, per_op)
        chunk = sock.recv(min(8192, n - len(buf)))
        if not chunk:
            raise ProtocolError("connection closed mid-body")
        buf += chunk
    return bytes(buf[:n])


def _parse_headers(block: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in block.split(CRLF):
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise ProtocolError("obsolete header line folding")
        name, sep, value = line.partition(b":")
        if not sep or name != name.strip():
            raise ProtocolError(f"malformed header line: {line[:60]!r}")
        headers[name.decode("latin-1").lower()] = value.strip().decode("latin-1")
    return headers


def _dechunk(sock: socket.socket, rest: bytes, budget: Budget, per_op: float) -> bytes:
    body = bytearray()
    buf = rest
    for _ in range(MAX_CHUNKS):
        while CRLF not in buf:
            if len(buf) > MAX_HEADER:
                raise ProtocolError("chunk size line too long")
            budget.arm(sock, per_op)
            chunk = sock.recv(8192)
            if not chunk:
                raise ProtocolError("connection closed inside chunked body")
            buf += chunk
        line, _, buf = buf.partition(CRLF)
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ProtocolError(f"bad chunk size {size_text!r}")
        if size == 0:
            return bytes(body)
        # Check the DECLARED size before buffering a byte of it. Without
        # this, a server advertising a 4 GiB chunk and then streaming has the
        # referee allocate until it dies.
        if size > MAX_BODY or len(body) + size > MAX_BODY:
            raise ProtocolError(f"chunk of {size} bytes would exceed {MAX_BODY}")
        while len(buf) < size + 2:
            budget.arm(sock, per_op)
            chunk = sock.recv(8192)
            if not chunk:
                raise ProtocolError("connection closed inside chunk")
            buf += chunk
        body += buf[:size]
        if buf[size:size + 2] != CRLF:
            raise ProtocolError("chunk not CRLF-terminated")
        buf = buf[size + 2:]
    raise ProtocolError(f"more than {MAX_CHUNKS} chunks")


# --------------------------------------------------------------------------
# HTTP/0.9 — liveness rung only (RULES §3: carries no note app)
# --------------------------------------------------------------------------
class Http09:
    version = "0.9"

    def __init__(self, host: str, port: int, timeout: float, budget: float | None = None):
        self.host, self.port, self.timeout = host, port, timeout
        self.budget_seconds = budget or default_budget(timeout)

    def request(self, method: str, path: str, headers=None, body: bytes = b"") -> Response:
        if method != "GET":
            raise ProtocolError("HTTP/0.9 has only GET")
        budget = Budget(self.budget_seconds)
        sock = _connect(self.host, self.port, self.timeout)
        try:
            sock.sendall(b"GET " + path.encode() + CRLF)
            data = _read_all(sock, budget, self.timeout)
        finally:
            sock.close()
        if not data:
            raise ProtocolError("empty HTTP/0.9 response")
        if data.startswith(b"HTTP/"):
            raise ProtocolError("HTTP/0.9 response carried a status line")
        return Response(status=200, body=data, closed=True)

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------
# HTTP/1.x
# --------------------------------------------------------------------------
class Http1:
    def __init__(self, host: str, port: int, timeout: float, version: str,
                 budget: float | None = None):
        if version not in ("1.0", "1.1"):
            raise ValueError(version)
        self.host, self.port, self.timeout = host, port, timeout
        self.version = version
        self.budget_seconds = budget or default_budget(timeout)
        self.sock: socket.socket | None = None

    def _ensure(self) -> socket.socket:
        if self.sock is None:
            self.sock = _connect(self.host, self.port, self.timeout)
        return self.sock

    def request(self, method: str, path: str, headers=None, body: bytes = b"") -> Response:
        headers = dict(headers or {})
        budget = Budget(self.budget_seconds)
        sock = self._ensure()
        lines = [f"{method} {path} HTTP/{self.version}".encode()]
        if self.version == "1.1":
            headers.setdefault("Host", f"{self.host}:{self.port}")
        else:
            headers.setdefault("Host", f"{self.host}:{self.port}")
            headers.setdefault("Connection", "close")
        if body:
            headers["Content-Length"] = str(len(body))
        for k, v in headers.items():
            lines.append(f"{k}: {v}".encode())
        wire = CRLF.join(lines) + CRLF + CRLF + body
        try:
            sock.sendall(wire)
            head, rest = _read_until(sock, CRLF + CRLF, MAX_HEADER, budget, self.timeout)
        except (TimeoutError, socket.timeout) as exc:
            self.close()
            raise ProtocolError(f"timeout: {exc}") from exc
        except OSError as exc:
            self.close()
            raise ProtocolError(f"socket error: {exc}") from exc

        status_line, _, header_block = head.partition(CRLF)
        parts = status_line.split(b" ", 2)
        if len(parts) < 2:
            raise ProtocolError(f"malformed status line {status_line[:60]!r}")
        proto, code = parts[0], parts[1]
        expected = f"HTTP/{self.version}".encode()
        if proto != expected:
            raise ProtocolError(f"expected {expected.decode()}, got {proto.decode('latin-1', 'replace')}")
        if not code.isdigit():
            raise ProtocolError(f"non-numeric status {code!r}")
        headers_out = _parse_headers(header_block)

        te = headers_out.get("transfer-encoding", "").lower()
        clen = headers_out.get("content-length")
        try:
            payload, closed = self._read_body(sock, te, clen, rest, budget)
        except (TimeoutError, socket.timeout) as exc:
            self.close()
            raise ProtocolError(f"timeout reading body: {exc}") from exc
        except OSError as exc:
            self.close()
            raise ProtocolError(f"socket error reading body: {exc}") from exc

        wants_close = headers_out.get("connection", "").lower() == "close"
        if self.version == "1.0":
            # Persistence is not an HTTP/1.0 guarantee; drop the socket.
            self.close()
            closed = True
        elif wants_close or closed:
            self.close()
            closed = True
        return Response(status=int(code), headers=headers_out, body=payload, closed=closed)

    def _read_body(self, sock, te: str, clen: str | None, rest: bytes,
                   budget: Budget) -> tuple[bytes, bool]:
        """Frame the body per version. Every path is size-capped and
        budget-bounded: this is hostile input (see Budget)."""
        if te and te != "identity":
            if self.version == "1.0":
                raise ProtocolError("transfer-encoding is not an HTTP/1.0 feature")
            if te != "chunked":
                raise ProtocolError(f"unsupported transfer-coding {te!r}")
            return _dechunk(sock, rest, budget, self.timeout), False
        if clen is not None:
            try:
                n = int(clen)
            except ValueError:
                raise ProtocolError(f"bad content-length {clen!r}")
            if n < 0:
                raise ProtocolError(f"negative content-length {clen!r}")
            # Cap the DECLARED length. A service is free to claim 4 GiB; if we
            # believe it and start reading, the referee allocates until it is
            # OOM-killed — measured at 8.9 GiB RSS in 9 seconds before this
            # check existed.
            if n > MAX_BODY:
                raise ProtocolError(f"content-length {n} exceeds the {MAX_BODY} byte cap")
            return _read_exact(sock, n, budget, self.timeout, rest), False
        if self.version == "1.1":
            raise ProtocolError("HTTP/1.1 response without content-length or chunked framing")
        return _read_all(sock, budget, self.timeout, rest), True

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None


# --------------------------------------------------------------------------
# HTTP/2 over cleartext, prior knowledge (h2c)
# --------------------------------------------------------------------------
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE = 0, 1, 3, 4, 6, 7, 8
END_STREAM, END_HEADERS = 0x1, 0x4


class Http2:
    version = "2"

    def __init__(self, host: str, port: int, timeout: float, budget: float | None = None):
        self.host, self.port, self.timeout = host, port, timeout
        self.budget_seconds = budget or default_budget(timeout)
        self.budget = Budget(self.budget_seconds)
        self.sock: socket.socket | None = None
        self.decoder = hpack.Decoder()
        self.next_stream = 1
        self.buf = b""

    def _ensure(self) -> socket.socket:
        if self.sock is not None:
            return self.sock
        sock = _connect(self.host, self.port, self.timeout)
        self.sock = sock
        sock.sendall(PREFACE + self._frame(SETTINGS, 0, 0, b""))
        kind, _, _, _ = self._await_frame({SETTINGS})
        return sock

    @staticmethod
    def _frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + \
            stream.to_bytes(4, "big") + payload

    def _recv(self, n: int) -> bytes:
        assert self.sock is not None
        if n > MAX_BODY:
            raise ProtocolError(f"frame of {n} bytes exceeds the {MAX_BODY} byte cap")
        while len(self.buf) < n:
            self.budget.arm(self.sock, self.timeout)
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProtocolError("connection closed mid-frame")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_frame(self) -> tuple[int, int, int, bytes]:
        head = self._recv(9)
        length = int.from_bytes(head[:3], "big")
        if length > (1 << 20):
            raise ProtocolError(f"frame length {length} exceeds sane bound")
        kind, flags = head[3], head[4]
        stream = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
        return kind, flags, stream, self._recv(length)

    def _await_frame(self, kinds: set[int]) -> tuple[int, int, int, bytes]:
        for _ in range(64):
            kind, flags, stream, payload = self._read_frame()
            if kind == SETTINGS and not flags & 0x1:
                self.sock.sendall(self._frame(SETTINGS, 0x1, 0, b""))   # ack
            elif kind == PING and not flags & 0x1:
                self.sock.sendall(self._frame(PING, 0x1, 0, payload))
            elif kind == GOAWAY:
                code = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else -1
                raise ProtocolError(f"GOAWAY, error code {code}")
            if kind in kinds:
                return kind, flags, stream, payload
        raise ProtocolError("too many control frames while waiting for a response")

    def request(self, method: str, path: str, headers=None, body: bytes = b"") -> Response:
        self.budget = Budget(self.budget_seconds)      # one budget per request
        sock = self._ensure()
        stream = self.next_stream
        self.next_stream += 2
        fields = [
            (":method", method), (":scheme", "http"),
            (":authority", f"{self.host}:{self.port}"), (":path", path),
        ]
        for k, v in (headers or {}).items():
            if k.lower() in ("host", "connection", "transfer-encoding"):
                continue                     # connection-specific headers are illegal in h2
            fields.append((k.lower(), v))
        if body:
            fields.append(("content-length", str(len(body))))
        block = hpack.encode(fields)
        flags = END_HEADERS | (0 if body else END_STREAM)
        try:
            sock.sendall(self._frame(HEADERS, flags, stream, block))
            if body:
                sock.sendall(self._frame(DATA, END_STREAM, stream, body))
            return self._read_response(stream)
        except (TimeoutError, socket.timeout) as exc:
            self.close()
            raise ProtocolError(f"timeout: {exc}") from exc
        except OSError as exc:
            self.close()
            raise ProtocolError(f"socket error: {exc}") from exc

    def _read_response(self, stream: int) -> Response:
        status: int | None = None
        headers: dict[str, str] = {}
        payload = bytearray()
        seen_headers = False
        for _ in range(512):
            kind, flags, sid, data = self._await_frame({HEADERS, DATA, RST_STREAM})
            if sid != stream:
                continue
            if kind == RST_STREAM:
                code = int.from_bytes(data[:4], "big") if len(data) >= 4 else -1
                raise ProtocolError(f"RST_STREAM, error code {code}")
            if kind == HEADERS:
                seen_headers = True
                if not flags & END_HEADERS:
                    raise ProtocolError("CONTINUATION frames are not supported by the prober")
                for name, value in self.decoder.decode(data):
                    if name == ":status" and value is not None:
                        status = int(value) if value.isdigit() else None
                    elif not name.startswith(":"):
                        headers[name] = value or ""
            elif kind == DATA:
                payload += data
                if len(payload) > MAX_BODY:
                    raise ProtocolError("body too large")
                if len(data) > 0:
                    self.sock.sendall(self._frame(WINDOW_UPDATE, 0, 0, len(data).to_bytes(4, "big")))
                    self.sock.sendall(self._frame(WINDOW_UPDATE, 0, stream, len(data).to_bytes(4, "big")))
            if flags & END_STREAM and seen_headers:
                return Response(status=status, headers=headers, body=bytes(payload))
        raise ProtocolError("response never ended the stream")

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.sendall(self._frame(GOAWAY, 0, 0, b"\x00" * 8))
            except OSError:
                pass
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.buf = b""
                self.decoder = hpack.Decoder()
                self.next_stream = 1


def default_budget(timeout: float) -> float:
    """Wall-clock ceiling for one request: enough slack for a slow but honest
    stack, far less than a tick."""
    return max(3.0 * timeout, timeout + 5.0)


def client_for(version: str, host: str, port: int, timeout: float,
               budget: float | None = None):
    if version == "0.9":
        return Http09(host, port, timeout, budget)
    if version in ("1.0", "1.1"):
        return Http1(host, port, timeout, version, budget)
    if version == "2":
        return Http2(host, port, timeout, budget)
    raise ValueError(f"no in-process client for HTTP/{version}")


def udp_echo(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    """RULES §3 UDP rung. The kernel validates the UDP checksum on receive, so
    a reply that arrives at all had a correct checksum (SETUP §6)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()
