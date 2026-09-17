"""A deliberately malicious 'player service', for testing the prober.

Every mode below is a *legal-looking* HTTP response that a player could serve
from their own hand-rolled stack. The prober is the one channel that must stay
open into hostile code (see docs/THREAT-MODEL.md §1), so each of these must be
contained by a declared-size cap or the wall-clock budget — never by luck.

  python3 tests/hostile_service.py <mode>      # prints its port on stdout

modes:
  clen        Content-Length: 4 GiB, then stream forever
  chunked     a single chunk declaring 0xffffffff bytes, then stream forever
  drip        honest length, delivered one byte every 2s, forever
  headers     a header section that never ends
  manychunks  an endless series of 1-byte chunks
"""
import socket
import sys
import threading
import time

MODES = ("clen", "chunked", "drip", "headers", "manychunks")


def handle(conn: socket.socket, mode: str) -> None:
    blob = b"A" * 65536
    try:
        conn.recv(4096)
        if mode == "clen":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4294967296\r\n\r\n")
            while True:
                conn.sendall(blob)
        elif mode == "chunked":
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffff\r\n")
            while True:
                conn.sendall(blob)
        elif mode == "drip":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
            while True:
                conn.sendall(b"A")
                time.sleep(2.0)
        elif mode == "headers":
            conn.sendall(b"HTTP/1.1 200 OK\r\n")
            while True:
                conn.sendall(b"X-Pad: " + blob + b"\r\n")
        elif mode == "manychunks":
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            while True:
                conn.sendall(b"1\r\nA\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def serve(mode: str) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    print(srv.getsockname()[1], flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn, mode), daemon=True).start()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "clen"
    if mode not in MODES:
        print(f"unknown mode {mode!r}; pick one of {MODES}", file=sys.stderr)
        raise SystemExit(2)
    serve(mode)
