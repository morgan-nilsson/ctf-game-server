"""SETUP §8 — live leaderboard. Bound on the viewer edge ONLY.

Reads the scoreboard.json the tick loop renders; it never opens the state
database and therefore cannot leak a flag token (RULES §10). Stdlib only, no
framework, and it scales to N players — the table just grows.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import load as load_config

log = logging.getLogger("leaderboard")

PAGE = """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>CTF Leaderboard</title>
<style>
 :root{color-scheme:dark}
 body{background:#0b0e14;color:#c8d3f5;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:2rem}
 h1{font-size:1.1rem;letter-spacing:.06em;color:#82aaff;margin:0}
 .sub{color:#7a88a8;font-size:.78rem;margin-top:.3rem}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{padding:.4rem .7rem;border-bottom:1px solid #1c2333;text-align:left;vertical-align:top}
 th{color:#7a88a8;font-weight:600;text-transform:uppercase;font-size:.72rem;white-space:nowrap}
 .tot{color:#c3e88d;font-weight:700}.atk{color:#ff9e64}.up{color:#82aaff}
 .g span{display:inline-block;min-width:1.1rem;padding:0 .25rem;margin:0 .15rem .15rem 0;
         text-align:center;border-radius:3px;font-size:.75rem}
 .ok{background:#1b3a2b;color:#c3e88d}.no{background:#3a1b1b;color:#ff757f}
 .gr{background:#3a341b;color:#ffcb6b}
 .tick{color:#7a88a8;margin-top:1rem;font-size:.8rem}
 .warn{color:#ffcb6b}.dead{color:#ff757f}
 td.name{color:#eeffff;font-weight:600}
 .pend{color:#ffcb6b;font-size:.72rem}
</style>
<h1>&#9873; ATTACK / DEFENSE &mdash; LEADERBOARD</h1>
<div class=sub>uptime is per declared protocol per tick &middot; attack is per fresh steal &middot; tokens are never shown</div>
<div id=board>loading&hellip;</div>
<div class=tick id=tickline></div>
<script>
const CELL = v => v === "grace" ? '<span class=gr title=grace>~</span>'
                : v ? '<span class=ok>\\u2713</span>' : '<span class=no>\\u2717</span>';
const grid = u => Object.keys(u||{}).length === 0 ? '<span class=no>no manifest</span>'
  : Object.entries(u).map(([k,v]) => CELL(v) + ' ' + k).join(' ');

function row(n, p, i){
  const st = p.status === 'running' ? '' :
    ` <span class=${p.status === 'failed' ? 'dead' : 'warn'}>[${p.status}]</span>`;
  const pend = p.pending ? ` <span class=pend>(${p.pending} pending review)</span>` : '';
  return `<tr><td>${i+1}</td><td class=name>${n}${st}</td>
    <td class=tot>${p.total}</td><td class=atk>${p.attack}${pend}</td>
    <td class=up>${p.uptime}</td><td>${p.captured}</td><td>${p.stolen_from}</td>
    <td class=g>${grid(p.up)}</td></tr>`;
}

async function refresh(){
  let b;
  try { b = await (await fetch('/state', {cache:'no-store'})).json(); }
  catch (e) { tickline.textContent = 'referee unreachable'; return; }
  const rows = Object.entries(b.players)
    .sort((a,c) => c[1].total - a[1].total || a[0].localeCompare(c[0]))
    .map(([n,p],i) => row(n,p,i)).join('');
  board.innerHTML = `<table><tr><th>#</th><th>player</th><th>total</th>
    <th>attack</th><th>uptime</th><th>caps</th><th>lost</th>
    <th>declared protocols &mdash; up this tick</th></tr>${rows}</table>`;
  tickline.innerHTML = `tick ${b.tick} \\u00b7 updated ${b.updated}`
    + (b.frozen ? ' \\u00b7 <span class=warn>SCORING FROZEN</span>' : '');
}
const tickline = document.getElementById('tickline'), board = document.getElementById('board');
refresh(); setInterval(refresh, 2000);
</script>"""

EMPTY = b'{"tick":0,"players":{},"updated":"never"}'


def make_handler(state_path: Path):
    page = PAGE.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "ctf-leaderboard/1.0"
        protocol_version = "HTTP/1.1"

        def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/state":
                try:
                    body = state_path.read_bytes()
                except OSError:
                    body = EMPTY
                self._send(body, "application/json")
            elif path == "/health":
                self._send(b'{"ok":true}', "application/json")
            elif path in ("/", "/index.html"):
                self._send(page, "text/html; charset=utf-8")
            else:
                self._send(b"not found\n", "text/plain; charset=utf-8", 404)

        def log_message(self, *a):
            pass

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CTF leaderboard (viewer edge)")
    ap.add_argument("-c", "--config", default=None)
    ap.add_argument("--bind", default=None)
    ap.add_argument("--port", type=int, default=None)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config(args.config)
    bind = args.bind or cfg.p("net", "viewer_bind", default="127.0.0.1")
    port = args.port or int(cfg.p("net", "leaderboard_port", default=8000))
    if bind in ("0.0.0.0", "::"):
        log.error("refusing to bind the leaderboard to %s — viewer address only (RULES §9)", bind)
        return 2

    srv = Server((bind, port), make_handler(cfg.path_of("scoreboard")))
    log.info("leaderboard on http://%s:%d/", bind, port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
