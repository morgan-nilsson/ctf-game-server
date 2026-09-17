# SETUP — Central Host, Sandboxes, Orchestrator & Leaderboard

The concrete build of the architecture in `RULES.md`. One central host runs
everything, split across **three network planes** so "referee unattackable,
services attackable, leaderboard human-viewable" is true by construction.

---

## 1. Network planes

| Plane | Members | Reachability |
|---|---|---|
| **control** | orchestrator internals, sandboxed builder, flag store | Nothing else routes here. Services **cannot** reach it. |
| **game** | the two service microVMs, each attacker foothold | Services reachable/attackable here. Blind-vantage enforced (§5). |
| **viewer** | human workstations | Reach leaderboard + submission API. **Cannot** be reached from services. |

The orchestrator has a leg on **control** (internal) and exposes only the
**leaderboard + submission API** on **viewer**. Services live on **game** with
**no route** to control or viewer.

> Two-network simplification for two friends: collapse `control`+`viewer` into
> one management network your workstations sit on, keep `game` separate, and
> ensure services have no route to management. You drive exploits from a
> foothold on `game`; you view/submit from management.

```
          ┌─────────────── control (internal) ───────────────┐
          │  orchestrator ── builder ── flag store ── tick    │
          └──────────────┬────────────────────┬──────────────┘
                         │ (viewer edge)       │ (deploy only)
                 leaderboard + submission      │
                         │                     ▼
   workstations ── viewer network       ┌── game network ──┐
   (view / submit / drive footholds)    │  svc-morgan (VM) │◄─ foothold-friend
                                         │  svc-friend (VM) │◄─ foothold-morgan
                                         └──────────────────┘
```

---

## 2. Service isolation — microVM (because RCE is in scope)

Each service runs in a **Firecracker or QEMU/KVM microVM**: real guest kernel,
real TUN inside, isolation at the hypervisor. Rationale:

- An in-service **RCE stays contained** only if the boundary isn't a shared
  kernel — so containers are insufficient once memory-corruption flags exist.
- Your build-your-own transport needs a **real TUN + raw sockets + `NET_ADMIN`
  inside the guest**. This is exactly what **gVisor breaks** (it intercepts
  syscalls and runs its own userspace netstack) — do **not** use it here.

**Precondition to verify first:** microVMs need **KVM / nested virt**. On a
cloud host without it, Firecracker won't boot — fall back to QEMU-TCG (slow) or,
if you drop RCE to logical-only bugs, containers. Check `ls /dev/kvm`.

Per-service tap wiring (host side, one per VM):

```bash
# host: create a tap the microVM's virtio-net binds to, on the game bridge
sudo ip tuntap add dev tap-morgan mode tap user $USER
sudo ip link set tap-morgan master br-game up
# Firecracker/QEMU attaches its NIC to tap-morgan; the guest gets 10.0.1.0/24
```

---

## 3. TUN inside the guest (your stack's L3 boundary)

Inside each VM your stack opens a **TUN** device and speaks IP up. The kernel
treats your stack as a *remote host through `tun0`*, so it never claims `.2`
locally and never emits the stray RST the raw-socket approach fights.

```python
import fcntl, struct, os
TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454ca, 0x0001, 0x1000

def open_tun(name="tun0"):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd

fd = open_tun()
while True:
    pkt = os.read(fd, 65535)      # one full IP packet, header included
    proto = pkt[9]                # 1=ICMP 6=TCP 17=UDP  → dispatch to your stack
    # ... parse IP, verify checksum, hand to TCP/UDP/QUIC ...
    # os.write(fd, reply)
```

```bash
# inside the guest
sudo ip tuntap add dev tun0 mode tun user app     # persistent; app runs unprivileged
sudo ip addr add 10.0.1.1/24 dev tun0             # kernel side; stack answers .2+
sudo ip link set tun0 up
sudo ethtool -K tun0 tx off rx off                # else L4 checksums arrive unfilled
```

`IFF_NO_PI` gives bare IP packets. Gotchas: device creation needs
`CAP_NET_ADMIN`; TUN is `NOARP` and full-packet (no `IP_HDRINCL`, no ARP);
**offload must be off on both hosts identically** or SLA flakes.

**Subnet allocation:** `svc-morgan = 10.0.1.0/24`, `svc-friend = 10.0.2.0/24`.
Route each to the other over the VPN. Blind vantage: each foothold sits where
it can **send** to the peer subnet but **cannot sniff** the peer's `tun0`
(separate netns/segment) — RULES §5.

---

## 4. The manifest — the only interface between repo and orchestrator

Each player repo ships `service.toml`. This is where the **transport/HTTP menu**
is declared.

```toml
[service]
name = "morgan"

# Transport menu — declare any subset. quic REQUIRES udp.
# You score and are attackable ONLY on declared transports.
transports    = ["tcp", "udp", "quic"]

# HTTP version menu — 0.9/1.0/1.1/2 require tcp; 3 requires quic.
http_versions = ["0.9", "1.0", "1.1", "2", "3"]

build    = "./build.sh"                # runs in sandboxed builder: no flags, no secrets, no egress
run      = "./run.sh"                  # starts your stack in the guest; binds the ports below
tcp_port = 8080
udp_port = 8080                        # UDP rung and/or QUIC
docroot  = "$DOCROOT"                  # orchestrator plants flag fixtures here
caps     = ["NET_RAW", "NET_ADMIN"]    # for your TUN stack, inside the guest
health   = "GET /health"               # kernel-interop SLA target (probed per HTTP version)
```

**Validation (deploy fails on violation):**

```python
def validate(m):
    t, v = set(m["transports"]), set(m["http_versions"])
    assert t <= {"tcp", "udp", "quic"}, "unknown transport"
    if "quic" in t: assert "udp" in t, "quic requires udp"
    if v & {"0.9", "1.0", "1.1", "2"}: assert "tcp" in t, "http<=2 requires tcp"
    if "3" in v: assert "quic" in t, "http/3 requires quic"
```

---

## 5. Build pipeline (CI that doubles as the patch mechanic)

Per player repo, the orchestrator:

1. **Polls or takes a webhook** on push (rate-limited to 1 / 90 s — RULES §8).
2. **Builds in a throwaway builder** with **no flag access, no secrets, egress
   allow-listed to mirrors or fully offline** (an open-network build is an
   exfil / supply-chain hole).
3. **Deploys** the artifact into the service microVM, applies `caps`, plants
   docroot fixtures.
4. **Healthchecks** (kernel-interop connect); on pass, hands off to the tick
   loop with a **2-tick SLA grace** window.

A push therefore *is* a shipped patch — no separate defense channel.

---

## 6. Tick loop (referee) — plant / retrieve / expire, per declared transport

Extends the Stage-1 prober with the flag contract and per-transport dispatch.
Runs on the **control** plane. `PLAYERS` maps to each guest's stack address.

```python
import socket, time, json, secrets, pathlib

TICK, K = 60, 5
STATE = pathlib.Path("/srv/ctf/scoreboard.json")   # read by the leaderboard (§8)
FLAGDB = {}                                          # (player, transport, tick) -> {flag, creds}

UPTIME = {"udp": 2, "0.9": 1, "1.0": 1, "1.1": 3, "2": 6, "3": 10}

PLAYERS = {
    "morgan": {"host": "10.0.1.2", "tcp": 8080, "udp": 8080,
               "transports": ["tcp", "udp", "quic"],
               "http_versions": ["0.9", "1.0", "1.1", "2", "3"]},
    "friend": {"host": "10.0.2.2", "tcp": 8080, "udp": 8080,
               "transports": ["tcp"], "http_versions": ["1.0", "1.1"]},
}

def new_flag():
    return "FLAG_" + secrets.token_urlsafe(24)[:32]

# --- protocol probes: each returns True iff *correct for that version* ---
def probe_http(host, port, ver): ...   # strict per-version check (see Stage-1 prober)
def probe_udp_echo(host, port):  ...   # send datagram, expect echo w/ valid checksum

# --- flag contract over a carrying protocol (http >= 1.0) ---
def plant_note(host, port, ver, flag): ...   # register throwaway user, PUT /note -> returns (id, creds)
def fetch_note(host, port, ver, ref):  ...   # GET /note/{id} with owner creds -> body (SLA)

def score_player(name, p, tick, board):
    acc = board["players"].setdefault(name, {
        "total": 0, "attack": 0, "uptime": 0, "captured": 0, "stolen_from": 0,
        "declared": {"transports": p["transports"], "http_versions": p["http_versions"]},
        "up": {},
    })
    up = acc["up"]

    # UDP rung (liveness + transport flag surface; carries no note app)
    if "udp" in p["transports"]:
        ok = safe(probe_udp_echo, p["host"], p["udp"])
        up["udp"] = ok
        if ok: acc["uptime"] += UPTIME["udp"]

    # HTTP versions: "up" = correct AND flag round-trip completes
    for ver in p["http_versions"]:
        carrying = ver in {"1.0", "1.1", "2", "3"}     # 0.9 = liveness only
        port = p["udp"] if ver == "3" else p["tcp"]
        ok = safe(probe_http, p["host"], port, ver)
        if ok and carrying:
            flag = new_flag()
            ref = safe(plant_note, p["host"], port, ver, flag)
            ok = ref is not None
            if ok:
                FLAGDB[(name, ver, tick)] = {"flag": flag, "creds": ref}
                old = FLAGDB.get((name, ver, tick - K + 1))     # SLA on a K-old flag
                if old and safe(fetch_note, p["host"], port, ver, old["creds"]) != old["flag"]:
                    ok = False
        up[ver] = ok
        if ok: acc["uptime"] += UPTIME[ver]

    for (pl, _, t) in list(FLAGDB):                             # expire
        if t <= tick - K: FLAGDB.pop((pl, _, t), None)

    acc["total"] = acc["attack"] + acc["uptime"]

def safe(fn, *a):
    try: return fn(*a)
    except OSError: return None

def run():
    board = {"tick": 0, "players": {}}
    tick = 0
    while True:
        tick += 1
        board["tick"] = tick
        board["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for name, p in PLAYERS.items():
            score_player(name, p, tick, board)
        STATE.write_text(json.dumps(board, indent=2))
        time.sleep(TICK)
```

---

## 7. Submission API (referee) — validate fresh + other-player + declared

Bound on the **viewer** edge only. A stolen flag scores iff it is unexpired,
belongs to the *other* player, and was over a declared transport.

```python
# POST /submit  {"by": "morgan", "flag": "FLAG_..."}
def submit(by, flag, board):
    for (owner, transport, tick), rec in FLAGDB.items():
        if rec["flag"] != flag:            continue
        if owner == by:                    return "own-flag"       # no self-submit
        acc  = board["players"][by]
        cls  = tier_for(owner, transport)                          # 50 / 75 / 100 (RULES §7)
        acc["attack"]  += cls
        acc["captured"] += 1
        board["players"][owner]["stolen_from"] += 1
        acc["total"] = acc["attack"] + acc["uptime"]
        return f"+{cls}"
    return "invalid-or-expired"
```

`tier_for` classifies by the flag's protocol/exploit path: app-layer = 50,
transport-layer = 75, RCE-class = 100. (Simplest: attacker self-declares the
class on submit and you spot-check write-ups; or key it to which endpoint the
flag lived behind.)

---

## 8. Live leaderboard (viewer edge)

Stdlib server, no framework. Serves an **auto-refreshing** page plus a `/state`
JSON endpoint that reads the `scoreboard.json` the tick loop writes. Shows
scores and the per-protocol up/down grid — **never flag tokens**. Bind on the
viewer interface; services on `game` have no route to it.

```python
# leaderboard.py  — python3 leaderboard.py  (bind viewer IP only)
import json, pathlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = pathlib.Path("/srv/ctf/scoreboard.json")
VIEWER_BIND = ("10.9.0.1", 8000)   # viewer-plane address ONLY

PAGE = b"""<!doctype html><meta charset=utf-8>
<title>CTF Leaderboard</title>
<style>
 body{background:#0b0e14;color:#c8d3f5;font:14px/1.5 ui-monospace,monospace;margin:2rem}
 h1{font-size:1.1rem;letter-spacing:.06em;color:#82aaff}
 table{border-collapse:collapse;width:100%;margin-top:1rem}
 th,td{padding:.4rem .7rem;border-bottom:1px solid #1c2333;text-align:left}
 th{color:#7a88a8;font-weight:600;text-transform:uppercase;font-size:.72rem}
 .tot{color:#c3e88d;font-weight:700}.atk{color:#ff9e64}.up{color:#82aaff}
 .g span{display:inline-block;width:1.1rem;text-align:center;border-radius:3px}
 .ok{background:#1b3a2b;color:#c3e88d}.no{background:#3a1b1b;color:#ff757f}
 .tick{color:#7a88a8;margin-top:1rem;font-size:.8rem}
</style>
<h1>&#9873; ATTACK / DEFENSE &mdash; LEADERBOARD</h1>
<div id=board>loading&hellip;</div>
<div class=tick id=tick></div>
<script>
const grid = u => Object.entries(u||{}).map(([k,v])=>
  `<span class=${v?'ok':'no'} title="${k}">${v?'\\u2714':'\\u2718'}</span> ${k}`).join(' ');
async function tick(){
 const b = await (await fetch('/state')).json();
 const rows = Object.entries(b.players)
   .sort((a,c)=>c[1].total-a[1].total)
   .map(([n,p],i)=>`<tr><td>${i+1}</td><td>${n}</td>
      <td class=tot>${p.total}</td><td class=atk>${p.attack}</td>
      <td class=up>${p.uptime}</td><td>${p.captured}</td><td>${p.stolen_from}</td>
      <td class=g>${grid(p.up)}</td></tr>`).join('');
 board.innerHTML = `<table><tr><th>#</th><th>player</th><th>total</th>
   <th>attack</th><th>uptime</th><th>caps</th><th>lost</th><th>protocols up</th></tr>${rows}</table>`;
 tickEl.textContent = `tick ${b.tick} \\u00b7 updated ${b.updated}`;
}
const tickEl=document.getElementById('tick'), board=document.getElementById('board');
tick(); setInterval(tick, 2000);
</script>"""

class H(BaseHTTPRequestHandler):
    def _send(self, body, ctype):
        self.send_response(200); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/state":
            self._send(STATE.read_bytes() if STATE.exists()
                       else b'{"tick":0,"players":{}}', "application/json")
        else:
            self._send(PAGE, "text/html; charset=utf-8")
    def log_message(self, *a): pass

if __name__ == "__main__":
    ThreadingHTTPServer(VIEWER_BIND, H).serve_forever()
```

Live view: page polls `/state` every 2 s and re-renders — sortable by total,
with a green/red grid of which declared protocols are up this tick.

---

## 9. Directory layout

```
ctf/
  RULES.md
  SETUP.md
  orchestrator/
    tick.py               # §6  plant / retrieve / expire, writes scoreboard.json
    submit.py             # §7  submission API (viewer edge)
    leaderboard.py        # §8  live page + /state (viewer edge)
    builder/              # §5  sandboxed, offline build environment
    validate.py           # §4  manifest schema check
  topology/
    networks.sh           # control / game / viewer planes + routing
    vm-morgan.sh          # microVM + tap + subnet 10.0.1.0/24
    vm-friend.sh          # microVM + tap + subnet 10.0.2.0/24
  players/
    morgan/  service.toml build.sh run.sh   src/    # their stack
    friend/  service.toml build.sh run.sh   src/
  fixtures/               # flag-carrying files planted into docroot
```

---

## 10. Bring-up order

1. `ls /dev/kvm` — confirm virt; pick Firecracker/QEMU vs. container fallback.
2. `topology/networks.sh` — three planes; verify services have **no** route to
   control/viewer (`ip route` from inside a guest).
3. Boot one microVM, open `tun0`, get `curl 10.0.1.2/health` answering — the
   kernel-interop SLA gate.
4. Start `tick.py` (TCP-only players first), confirm `scoreboard.json` updates.
5. Start `leaderboard.py` on viewer; open the page; watch the up/down grid.
6. Start `submit.py`; test a self-submit (rejected) and a cross-steal (scores).
7. Add UDP, then QUIC/HTTP-3, declaring each in the manifest as it lands.
