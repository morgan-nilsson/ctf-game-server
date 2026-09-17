"""A stand-in player service, used only to test the referee.

It implements docs/NOTE-API.md over HTTP/0.9, 1.0, 1.1, h2c and the UDP rung.
It is NOT an example of a legal competition entry: it leans on nothing the
players may not use, but it also does not build a transport from scratch —
its job is to be a known-good target so the prober can be trusted.

  python3 tests/fake_service.py --tcp 8080 --udp 8080 [--break 1.1]
"""
from __future__ import annotations

import argparse
import secrets
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator import hpack                                    # noqa: E402

CRLF = b"\r\n"
NOTES: dict[str, tuple[str, bytes]] = {}       # id -> (token, body)
TOKENS: set[str] = set()
UDP_FLAGS: dict[str, str] = {}
BREAK = ""


def route(method: str, path: str, headers: dict, body: bytes) -> tuple[int, bytes]:
    auth = headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    if method == "GET" and path == "/health":
        return 200, b"ok"
    if method == "POST" and path == "/register":
        new = secrets.token_urlsafe(18)
        TOKENS.add(new)
        return 200, new.encode()
    if method == "PUT" and path == "/note":
        if token not in TOKENS:
            return 401, b"no"
        note_id = secrets.token_hex(8)
        NOTES[note_id] = (token, body)
        return 200, note_id.encode()
    if method == "GET" and path.startswith("/note/"):
        note_id = path[len("/note/"):]
        rec = NOTES.get(note_id)
        if rec is None:
            return 404, b"no such note"
        owner, payload = rec
        if owner != token:                     # the IDOR the players are meant to leave in
            return 403, b"not yours"
        return 200, payload
    return 404, b"not found"


def serve_http1(conn: socket.socket, version_hint: str) -> None:
    buf = b""
    while True:
        while CRLF + CRLF not in buf:
            if CRLF in buf and b"HTTP/" not in buf.split(CRLF)[0]:
                break                          # HTTP/0.9 request line
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        line = buf.split(CRLF)[0]
        parts = line.split(b" ")
        if len(parts) == 2:                    # HTTP/0.9
            status, body = route("GET", parts[1].decode(), {}, b"")
            conn.sendall(body)
            return
        method, path, proto = parts[0].decode(), parts[1].decode(), parts[2].decode()
        head, _, rest = buf.partition(CRLF + CRLF)
        headers = {}
        for h in head.split(CRLF)[1:]:
            k, _, v = h.partition(b":")
            headers[k.decode().lower()] = v.strip().decode()
        length = int(headers.get("content-length", 0))
        while len(rest) < length:
            rest += conn.recv(4096)
        body, buf = rest[:length], rest[length:]

        status, payload = route(method, path, headers, body)
        ver = "1.0" if proto == "HTTP/1.0" else "1.1"
        if BREAK == ver:
            conn.sendall(b"HTTP/9.9 500 broken\r\n\r\n")
            return
        keepalive = ver == "1.1" and headers.get("connection", "").lower() != "close"
        out = [f"HTTP/{ver} {status} {'OK' if status == 200 else 'ERR'}".encode(),
               b"Content-Type: text/plain",
               f"Content-Length: {len(payload)}".encode()]
        if not keepalive:
            out.append(b"Connection: close")
        conn.sendall(CRLF.join(out) + CRLF + CRLF + payload)
        if not keepalive:
            return


PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + \
        stream.to_bytes(4, "big") + payload


def serve_h2(conn: socket.socket, initial: bytes) -> None:
    buf = initial[len(PREFACE):]
    conn.sendall(frame(4, 0, 0, b""))                    # SETTINGS
    decoder = hpack.Decoder()
    streams: dict[int, tuple[dict, bytearray]] = {}

    def recv(n: int) -> bytes:
        nonlocal buf
        while len(buf) < n:
            chunk = conn.recv(65536)
            if not chunk:
                raise ConnectionError
            buf += chunk
        out, buf = buf[:n], buf[n:]
        return out

    try:
        while True:
            head = recv(9)
            length = int.from_bytes(head[:3], "big")
            kind, flags = head[3], head[4]
            sid = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
            payload = recv(length)
            if kind == 4 and not flags & 1:
                conn.sendall(frame(4, 1, 0, b""))
            elif kind == 6 and not flags & 1:
                conn.sendall(frame(6, 1, 0, payload))
            elif kind == 1:                                # HEADERS
                fields = dict((k, v) for k, v in decoder.decode(payload) if v is not None)
                streams[sid] = (fields, bytearray())
                if flags & 0x1:
                    respond_h2(conn, sid, streams.pop(sid))
            elif kind == 0:                                # DATA
                if sid in streams:
                    streams[sid][1].extend(payload)
                    if flags & 0x1:
                        respond_h2(conn, sid, streams.pop(sid))
            elif kind == 7:                                # GOAWAY
                return
    except (ConnectionError, OSError):
        return


def respond_h2(conn: socket.socket, sid: int, stream) -> None:
    fields, body = stream
    headers = {k: v for k, v in fields.items() if not k.startswith(":")}
    status, payload = route(fields.get(":method", "GET"), fields.get(":path", "/"),
                            headers, bytes(body))
    block = hpack.encode([(":status", str(status)), ("content-length", str(len(payload)))])
    conn.sendall(frame(1, 0x4, sid, block))
    conn.sendall(frame(0, 0x1, sid, payload))


def tcp_worker(conn: socket.socket) -> None:
    conn.settimeout(15)
    try:
        peek = conn.recv(len(PREFACE), socket.MSG_PEEK)
        if peek == PREFACE:
            serve_h2(conn, conn.recv(len(PREFACE)))
        else:
            serve_http1(conn, "1.1")
    except (OSError, ConnectionError):
        pass
    finally:
        conn.close()


def tcp_server(port: int, host: str) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=tcp_worker, args=(conn,), daemon=True).start()


def udp_server(port: int, host: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((host, port))
    while True:
        data, addr = srv.recvfrom(65535)
        text = data.decode("utf-8", "replace").strip()
        if text.startswith("ECHO "):
            srv.sendto(data, addr)
        elif text.startswith("SET "):
            _, key, value = text.split(" ", 2)
            UDP_FLAGS[key] = value
            srv.sendto(b"OK", addr)
        elif text.startswith("GET "):
            srv.sendto(UDP_FLAGS.get(text.split(" ", 1)[1], "").encode(), addr)


def main() -> int:
    global BREAK
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp", type=int, default=8080)
    ap.add_argument("--udp", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--break", dest="brk", default="", help="make one version answer wrongly")
    args = ap.parse_args()
    BREAK = args.brk
    threading.Thread(target=tcp_server, args=(args.tcp, args.host), daemon=True).start()
    threading.Thread(target=udp_server, args=(args.udp, args.host), daemon=True).start()
    print(f"fake service on tcp/{args.tcp} udp/{args.udp}", flush=True)
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
