"""SETUP §7 — the submission API. Bound on the viewer edge ONLY.

A submission scores iff the flag is fresh, belongs to another player, and was
planted over a declared transport (RULES §6). With N players "the other
player" means any owner that is not the submitter, and a given flag may be
stolen by several attackers — each scores once; a repeat by the same attacker
is a duplicate, not a second capture.

Exploit class (RULES §7) is 50 / 75 / 100. The class is derived from where the
flag lived, and an attacker may *claim* a higher class with a write-up: the
derived tier is paid immediately and the difference is held `pending` until an
operator runs `ctfctl review`. That is the spot-check SETUP §7 asks for, minus
the honour system.
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import re
import socket
import sys
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import load as load_config
from .state import Store

log = logging.getLogger("submit")

FLAG_RE = re.compile(r"^FLAG_[A-Za-z0-9]{32}$")
CLASSES = ("app", "transport", "rce")
RATE_WINDOW, RATE_MAX = 60.0, 30          # submissions per player per minute
MAX_BODY = 64 * 1024

# Where a flag lived decides its floor tier: the note app is app-layer, the
# UDP fixture is transport-layer. Anything above that needs a write-up.
AUTO_CLASS = {"udp": "transport", "0.9": "app", "1.0": "app",
              "1.1": "app", "2": "app", "3": "app"}


class Referee:
    def __init__(self, cfg, store: Store):
        self.cfg, self.store = cfg, store
        self.tokens = {p.name: p.submit_token for p in cfg.players}
        self.points = cfg.attack_points
        self.hits: dict[str, deque] = {}

    def rate_limited(self, who: str) -> bool:
        now = time.monotonic()
        q = self.hits.setdefault(who, deque())
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_MAX:
            return True
        q.append(now)
        return False

    def submit(self, by: str, token: str, flag: str, claimed: str | None,
               writeup: str, src: str) -> tuple[int, dict]:
        expected = self.tokens.get(by)
        if expected is None or not hmac.compare_digest(str(token or ""), str(expected)):
            log.warning("bad token for %r from %s", by, src)
            return 403, {"verdict": "bad-token"}
        if self.rate_limited(by):
            return 429, {"verdict": "rate-limited"}
        if not FLAG_RE.match(flag or ""):
            return 400, {"verdict": "malformed-flag"}
        if claimed and claimed not in CLASSES:
            return 400, {"verdict": "unknown-class", "classes": list(CLASSES)}

        store, tick = self.store, self.store.tick
        row = store.find_live_flag(flag, tick)
        if row is None:
            self._record(by, flag, None, None, "invalid-or-expired", None, claimed, 0, 0, writeup, src)
            return 200, {"verdict": "invalid-or-expired"}

        owner, protocol = row["player"], row["protocol"]
        if owner == by:
            self._record(by, flag, owner, protocol, "own-flag", None, claimed, 0, 0, writeup, src)
            return 200, {"verdict": "own-flag"}

        manifest = store.manifest(owner) or {}
        declared = set(manifest.get("transports", [])) | set(manifest.get("http_versions", []))
        if protocol not in declared:
            # Belt and braces: flags are only planted on declared protocols,
            # but a manifest can shrink between plant and submit.
            self._record(by, flag, owner, protocol, "undeclared-transport", None, claimed, 0, 0, writeup, src)
            return 200, {"verdict": "undeclared-transport"}

        already = store.db.execute(
            "SELECT 1 FROM submissions WHERE by=? AND flag=? AND verdict='accepted'", (by, flag)
        ).fetchone()
        if already:
            self._record(by, flag, owner, protocol, "duplicate", None, claimed, 0, 0, writeup, src)
            return 200, {"verdict": "duplicate"}

        auto = AUTO_CLASS.get(protocol, "app")
        klass, pending = auto, 0
        if claimed and CLASSES.index(claimed) > CLASSES.index(auto):
            if not writeup.strip():
                return 400, {"verdict": "writeup-required",
                             "detail": f"claiming {claimed} above the {auto} floor needs a write-up"}
            pending = 1                       # pay the floor now, hold the delta
        awarded = self.points.get(klass, 0)

        store.mark_stolen(flag, by, tick)
        sid = self._record(by, flag, owner, protocol, "accepted", klass, claimed,
                           awarded, pending, writeup, src)
        store.event("steal", by, f"{owner}/{protocol} +{awarded}")
        store.render_board(tick, self.cfg.path_of("scoreboard"))
        log.info("ACCEPTED #%d %s stole %s/%s for +%d%s", sid, by, owner, protocol,
                 awarded, f" (claims {claimed}, pending review)" if pending else "")
        body = {"verdict": f"+{awarded}", "points": awarded, "class": klass,
                "owner": owner, "protocol": protocol, "id": sid}
        if pending:
            body["pending_review"] = claimed
        return 200, body

    def _record(self, by, flag, owner, protocol, verdict, klass, claimed,
                points, pending, writeup, src) -> int:
        cur = self.store.db.execute(
            """INSERT INTO submissions(ts,by,flag,owner,protocol,verdict,klass,claimed,
                                       points,pending,writeup,src)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (time.time(), by, flag, owner, protocol, verdict, klass, claimed,
             points, pending, writeup[:4000], src),
        )
        return int(cur.lastrowid or 0)


USAGE = b"""CTF submission API (RULES/SETUP \xc2\xa77)

  POST /submit   Content-Type: application/json
  {"by": "<player>", "token": "<your submit token>", "flag": "FLAG_...",
   "class": "app|transport|rce",   (optional, needs "writeup" above the floor)
   "writeup": "how you got it"}

  verdicts: +N | own-flag | invalid-or-expired | duplicate | bad-token
            | malformed-flag | undeclared-transport | rate-limited

Submit from your workstation or attacker foothold, never from a service.
"""


def make_handler(referee: Referee):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ctf-referee/1.0"
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, payload: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _json(self, code: int, obj: dict) -> None:
            self._send(code, json.dumps(obj).encode() + b"\n", "application/json")

        def do_GET(self):
            if self.path == "/health":
                self._json(200, {"ok": True, "tick": referee.store.tick})
            else:
                self._send(200, USAGE, "text/plain; charset=utf-8")

        def do_POST(self):
            if self.path.split("?")[0] != "/submit":
                return self._json(404, {"verdict": "no-such-endpoint"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"verdict": "bad-length"})
            if length <= 0 or length > MAX_BODY:
                return self._json(400, {"verdict": "bad-length"})
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("not an object")
            except ValueError:
                return self._json(400, {"verdict": "bad-json"})
            try:
                code, body = referee.submit(
                    by=str(data.get("by", ""))[:64],
                    token=str(data.get("token", ""))[:256],
                    flag=str(data.get("flag", ""))[:128],
                    claimed=(str(data["class"]) if data.get("class") else None),
                    writeup=str(data.get("writeup", ""))[:4000],
                    src=self.client_address[0],
                )
            except Exception:
                log.exception("submission handling failed")
                return self._json(500, {"verdict": "referee-error"})
            self._json(code, body)

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.client_address[0], fmt % args)

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CTF submission API (viewer edge)")
    ap.add_argument("-c", "--config", default=None)
    ap.add_argument("--bind", default=None, help="override net.viewer_bind")
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config(args.config)
    store = Store(cfg.path_of("state_db"),
                  cfg.p("game", "sqlite_synchronous", default="FULL"))
    store.sync_roster(cfg.players)

    bind = args.bind or cfg.p("net", "viewer_bind", default="127.0.0.1")
    port = args.port or int(cfg.p("net", "submit_port", default=8001))
    if bind in ("0.0.0.0", "::"):
        # RULES §9: services must not be able to reach the submission API.
        log.error("refusing to bind the submission API to %s — bind the viewer address only", bind)
        return 2
    for pl in cfg.players:
        if not pl.submit_token or pl.submit_token.startswith("CHANGE-ME"):
            log.error("player %s still has a placeholder submit_token", pl.name)
            return 2

    referee = Referee(cfg, store)
    srv = Server((bind, port), make_handler(referee))
    log.info("submission API on http://%s:%d/submit (%d players)", bind, port, len(cfg.players))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
