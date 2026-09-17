# RULES — Build-Your-Own-Stack Attack/Defense CTF

An attack/defense competition where each player builds their **transport
layer (UDP/TCP, optionally QUIC) and HTTP server from raw sockets**, hosts it
on a shared central host, and steals rotating flags from the opponent by
exploiting bugs in their hand-rolled stack. Everything below the application
is yours to build and yours to break.

---

## 1. Format

- **Attack/Defense.** A neutral **orchestrator (referee)** plants a rotating
  flag into each running service every tick and later retrieves it. A
  **vulnerability** is anything that lets the opponent read a flag they don't
  own. Steal it, submit it, score.
- **Two trust domains, one host.** The referee plane (builder, flag store,
  tick loop, submission API, leaderboard) is **unroutable from the services**.
  The service sandboxes are the only attackable units. Attacking the referee,
  builder, flag store, submission API, or leaderboard is out of scope (§9).
- **You build the stack.** No HTTP/TCP/UDP/QUIC libraries. See §4.

---

## 2. Definitions

| Term | Meaning |
|---|---|
| **Tick** | 60 s scoring round. |
| **Flag** | `FLAG_[A-Za-z0-9]{32}`, bound to `(player, transport, tick)`. |
| **Flag lifetime** | Valid for **K = 5 ticks** after planting, then expired. |
| **SLA** | A declared protocol is *up* this tick iff it answers correctly **and** completes a flag round-trip (§6). |
| **Declared capability** | The transports and HTTP versions a service advertises in its manifest (§3). |
| **Blind attacker** | May send packets toward the peer; may **not** sniff the peer's link (§5). |

---

## 3. Transport capability — the menu

Each service declares any **subset** of `{tcp, udp, quic}` plus the HTTP
versions it speaks. You **score and are attackable ONLY on declared
capabilities.** Declaring is risk/reward: every declared transport raises your
scoring ceiling *and* opens an attack surface against you.

**Declaration rules (validated at deploy; a bad manifest fails deploy):**

- `tcp`, `udp`, `quic` — declare any subset. **`tcp`-only is valid.**
- **`quic` requires `udp`** — QUIC rides UDP; declaring QUIC without UDP is rejected.
- HTTP versions map to transports:
  - `0.9, 1.0, 1.1, 2` require **`tcp`**.
  - `3` requires **`quic`**.
- **`udp` as a standalone transport** is scored as a liveness/conformance rung
  (a hand-built UDP echo fixture) and carries a **transport-level** flag
  surface — but it does **not** carry the note/flag app (no headers, no auth,
  same reason HTTP/0.9 can't).

**Undeclared ⇒ not probed, not scored, and out of scope for attack.** You
cannot earn points on a transport you didn't declare, and a flag "stolen" over
an undeclared transport does not count.

---

## 4. What "from scratch" means

You own **L3 and up**; the kernel/TUN gives you raw IP packets.

**In scope (you build it):**
- IP header handling, TTL, and the **transport checksum + pseudo-header** for
  UDP/TCP. (Validating the peer's checksum is your responsibility — and a
  seedable bug if you skip it.)
- **TCP** state machine: handshake, seq/ack, retransmit, teardown, TIME_WAIT.
- **UDP** datagram handling.
- **QUIC** (if declared): reliable streams, loss detection, congestion
  control, connection IDs, packet-number spaces, flow control — **and TLS 1.3**,
  which is fused into the QUIC handshake with **no cleartext escape hatch**.
  Declaring QUIC means implementing TLS 1.3 from scratch too. There is no
  library exception.
- **HTTP** parsing/serving for every version you declare.

**Out of scope / banned:**
- **No protocol libraries** at any layer: no `http.server`/`net/http`/`hyper`/
  `actix`; no userspace TCP/QUIC/TLS libs (`smoltcp`, `quiche`, `quinn`,
  `ngtcp2`, `openssl`/`rustls` for the QUIC path). Language stdlib for
  **sockets, threads, bytes, and crypto primitives** (hashes, AEAD) is allowed;
  a library that *speaks the protocol for you* is not.
- **L2 is out**: Ethernet/ARP handled by TUN. (TAP + ARP only as an optional
  bonus rung, by mutual agreement.)
- **IP fragmentation/reassembly out by default**: flags/notes must fit one
  MTU-bounded segment. Flip to in-scope only by mutual agreement (then
  overlap-reassembly becomes a legal vuln).

---

## 5. Network & attacker vantage

- **One TUN subnet per service.** Kernel owns `.1`; your stack answers `.2+`.
  Routing between the two hosts crosses the VPN (§ SETUP).
- **Parity, identical on both hosts:** MTU **1500**; NIC/TUN offload **off**
  (unfilled L4 checksums otherwise break interop).
- **Blind/off-path only.** You may inject/spoof packets toward the peer's
  service. You may **not** capture (`tcpdump`/sniff) the peer's TUN read path.
  Enforced by network-namespace topology, not honor system. This is what makes
  **ISN quality** decide TCP hijacks instead of "whoever sniffs wins."

---

## 6. Flags, SLA, and submission

**Each tick, per declared transport, the referee:**
1. Registers a throwaway user and plants a **fresh flag** (a note the user owns,
   or a transport-level fixture for the UDP rung).
2. Retrieves a flag planted **K ticks ago** using that user's own credentials —
   the **SLA check**. Success ⇒ that protocol is *up* this tick.
3. Expires flags older than K ticks.

**"Up" is strict per protocol** — it means *answers correctly for that specific
version/transport* **and** (for flag-carrying protocols) *completes the flag
round-trip*. A liveness ping alone does not count; you cannot farm defense by
serving `/health` while refusing to implement the attackable features.

**Stealing:** exploit a bug to read a flag you don't own, then submit the token
to the referee's submission API (from your workstation / attacker foothold, not
from a service). A submission scores iff the flag is **fresh** (unexpired),
**belongs to the other player**, and was over a **declared** transport. Expired
flags are worthless — no hoarding.

---

## 7. Scoring

**Uptime (per passing tick, per declared protocol) — effort-weighted:**

| Protocol | Points/tick |
|---|---|
| UDP echo rung | 2 |
| HTTP/0.9 | 1 |
| HTTP/1.0 | 1 |
| HTTP/1.1 | 3 |
| HTTP/2 (h2c) | 6 |
| HTTP/3 (QUIC) | 10 |

**Attack (per valid fresh steal) — tiered by exploit class:**

| Flag class | Points |
|---|---|
| App-layer (path traversal, IDOR, auth bypass) | 50 |
| Transport-layer (blind ISN hijack/injection, UDP parser over-read, forged-segment acceptance) | 75 |
| Memory-corruption → RCE in the service process | 100 |

**Attack ≫ SLA by design.** A single steal outweighs many ticks of uptime, so
offense dominates and turtling loses. (Optional defense bonus: +2/tick per
protocol whose flag was **not** stolen that tick.)

---

## 8. Defense & patching

- **A push = redeploy = a patch.** Fix a bug in your repo and push; the
  orchestrator rebuilds and redeploys. That is the entire defense mechanic —
  there is no separate patch channel.
- **Rebuild rate limit:** at most **1 redeploy per 90 s** per service (else a
  player rebuilds continuously to dodge exploitation).
- **SLA grace window:** a redeploy gets **2 ticks** of SLA immunity (else
  patching costs uptime and no one patches).
- **Reproducible builds** required so both artifacts are parity-comparable.
- Editing your own source freely is allowed. Reading the opponent's source is
  not — unless you both agree to open-source at start (turning the game into a
  pure patch war on known bugs).

---

## 9. Isolation & prohibited actions

- **RCE inside your own service process is a first-class, intended flag path.**
  Memory-corruption bugs are *in scope* and worth the most — the microVM
  boundary (see SETUP) exists precisely so that owning a service process still
  cannot reach the referee or the other player.
- **VM escape to the host is BANNED / out of scope.** The hypervisor boundary
  is infrastructure, not a target.
- **Prohibited:** attacking the referee, builder, flag store, submission API,
  or leaderboard; sniffing the peer's TUN link (§5); tampering with parity
  settings (MTU/offload); build-time network egress or supply-chain tricks
  (builders are offline).
- **DoS out of scope by default** (SYN-flood/state-exhaustion, resource
  bombs). SLA already punishes downtime. Enable a DoS category only by mutual
  agreement, with resource limits defined.

---

## 10. Leaderboard

The orchestrator serves a **live leaderboard page** (auto-refreshing) on the
viewer edge — reachable by the human players, **not** by the service
sandboxes. It shows, per player: total score, attack vs. uptime split, the
per-protocol *up/down* grid for the current tick, flags captured, and flags
lost. Scores only — never flag tokens.

---

## 11. Version ladder (suggested build order)

`UDP echo` → `TCP handshake + kernel interop (curl connects)` →
`TCP reliable delivery` → `HTTP/0.9 → 1.0 → 1.1 → 2` →
`QUIC + TLS 1.3 → HTTP/3` (apex).

Declare capabilities as you finish them; the menu (§3) lets you start scoring
on TCP-only and add UDP/QUIC later without rule changes.
