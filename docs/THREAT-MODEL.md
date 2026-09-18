# Threat model — what the referee actually trusts

The network diagram is the easy half. These are the paths that bypass it,
what the code does about each, and what remains honour-system or inherent.

---

## 1. The prober is attack surface (the biggest one)

The forward policy stops a service *dialing* the referee. It cannot stop the
referee **connecting into each service every tick and parsing the reply** —
that channel must stay open, and every byte of it is player-controlled.

What the code does:

* **Memory-safe parsers.** The prober is pure-Python stdlib: no C parsing, no
  `zlib`, no compression negotiated (the referee never sends
  `Accept-Encoding`), so decompression bombs and buffer overflows are not on
  the menu. The realistic worst case is resource exhaustion, not RCE.
* **Declared sizes are capped before a byte is buffered.** `Content-Length`
  and chunk sizes are checked against `MAX_BODY` (1 MiB) *first*. This was a
  real bug: a service claiming `Content-Length: 4294967296` and then
  streaming drove the prober to **8.9 GiB RSS in 9.2 seconds**, which with N
  players probed concurrently OOMs the referee every tick.
* **A wall-clock budget per request** (`Budget`, default 3x the probe
  timeout). A socket timeout alone is useless against a service that dribbles
  one byte just inside it forever: the recv never times out, the probe never
  returns, and its pool thread is consumed for the rest of the game.
* **Bounded everything else**: header section 64 KiB, at most 4096 chunks,
  h2 frames capped, HPACK dynamic table clamped to 64 KiB so the peer cannot
  talk the decoder into a huge allocation.
* **The referee process is sandboxed**, not trusted infra: `MemoryMax=512M`,
  `SystemCallFilter=@system-service` minus `@privileged @resources`, empty
  `CapabilityBoundingSet`, `PrivateDevices`, `ProtectSystem=strict`,
  `UMask=0077`. A parser bug kills one service unit; it does not own the host.

`tests/e2e.py` and the hostile-service cases in this repo's review history
cover the five shapes: lying length, huge chunk, slow drip, endless headers,
chunk flood.

**Residual:** a Python-level logic bug in the prober still runs with read
access to the flag store. Sandboxing reduces the blast radius; it does not
eliminate it. If you want that gone, the prober has to move into its own
process with the store behind an IPC boundary — not built.

## 2. Submission authentication — implemented

`by` is **not** self-asserted. Each player has a `submit_token` in the host
config; `submit()` compares it with `hmac.compare_digest` before anything
else, refuses to start while any token is a placeholder, and rate-limits to
30 submissions/minute/player. Every accepted flag is recorded against the
authenticated identity. See `orchestrator/submit.py` and the `bad token
refused` check in the test suite.

**Residual:** tokens are bearer secrets in a config file. Anyone who can read
`/etc/ctf/ctf.toml` (mode 0640 root:ctf) can submit as anyone.

## 3. The builder runs player code next to the flag store

`build.sh` is arbitrary player code by design. "Offline" only removes the
network — it says nothing about the filesystem.

This was a **real hole**: the flag store was created world-readable (0644,
sqlite's default minus umask) and the sandbox did `--ro-bind / /`, so a
malicious `build.sh` could lift every live flag with `strings state.db` — no
network, no sqlite, before a single packet touched a service.

What the code does now:

* the store is forced to **0600**, including the `-wal`/`-shm` files, which
  inherit the main file's mode and leak identically;
* the sandbox **masks the referee's whole tree** (`--tmpfs` over
  `paths.root`, `state_db`, `fixtures`, `logs`, `run`) *before* re-binding
  the artifact directory, so ordering cannot un-mask it;
* the build runs as a separate `ctf-build` user with a wiped environment, in
  a fresh empty network namespace (`bwrap --unshare-all`), so it cannot scan
  the control plane either;
* if `bwrap` is missing, the weaker `unshare` path **refuses to build at all**
  when the build user can actually read the store.

**Optional relaxation:** `game.offline_builds = false` gives builds internet
access so players need not vendor dependencies. This is a deliberate trade —
you are accepting supply-chain trust in whatever they pull — and it is a
change to RULES §9, so tell your players. It is **not** a hole in the game:
the sandbox still masks the flag store, and a host firewall rule pinned to
the build user's uid rejects any packet from a build to the control plane,
the viewer edge or any player subnet. A build can reach npm; it cannot reach
the referee or its opponent.

**Residual:** the builder shares the host kernel. A kernel LPE from the build
user owns the host. The proper fix is a build microVM with pull-only artifact
handoff — not built; the mitigations above are what stands.

## 4. rp_filter=0 + notrack is blunt — narrowed

Turning both off is what makes blind ISN injection land at all. Unnarrowed it
also lets a foothold claim **any** source: the victim's own address, the
host, another plane. Anything treating a source IP as authorization is then
forged for free, which is a duller game than guessing an ISN.

Both policy files now carry **egress anti-spoof** on the foothold
interfaces: a foothold may claim its own /30 and the referee's address range
(whose session is the legitimate target of a hijack) and nothing else.
Everything else is logged (`ctf-spoof`) and dropped.

**A rule for players, because no firewall can enforce it:** source IP is
never an authorization signal. If your service trusts one, that is a bug, and
it is meant to be.

## 5. In-guest hardening is not a boundary against the guest's owner

True, with one distinction worth keeping straight:

* **Against the owner** — caps, the unprivileged `app` user, the fresh rootfs
  — none of it is a boundary. It is their VM.
* **Against the peer attacker** it still does work: an RCE lands as `app`,
  not root, so it cannot re-add checksum offload to break parity, cannot read
  the rootfs wholesale, and does not survive the next deploy.

**The only real boundary is the VMM**, and in-guest RCE is an intended,
100-point flag path — i.e. the ideal launchpad for a hypervisor escape.
"VM escape is banned" (RULES §9) is honour-system: a QEMU CVE owns the host,
every repo and the flag store.

Reduce the surface: prefer **Firecracker** (far smaller device model than
QEMU) — `vm.sh` runs it without `--no-seccomp`, so its default seccomp
filters are active. Adding the **jailer** (chroot + cgroup + netns per VM) is
the next step and is not yet wired in. Keep the host kernel patched, do not
nest virtualisation, and understand that isolation is exactly as strong as
your VMM.

## 6. One host means shared availability fate and cross-plane side channels

Inherent to centralising, per SETUP. Partly mitigated:

* each guest runs in a **systemd scope** with `MemoryMax`, `MemorySwapMax=0`,
  `CPUQuota` and `TasksMax`, so a resource-bombed guest cannot starve the
  host router or the tick loop into global scoring skew;
* the referee has its own `MemoryMax` and the tick loop schedules on absolute
  boundaries, so probe latency does not shift the grid.

**Residual, not fixable on one box:** the shared host router has global
counters (IP-ID, ICMP rate limits, conntrack occupancy) observable across
planes, which is exactly the lineage of the challenge-ACK side channel. An
off-path attacker gets signals that separate physical hosts would not give
them. If that matters to you, the answer is two hosts, not a rule.

## 7. Repo push authentication and manifest paths

**Push auth is outside this codebase by default** — `repo` points at each
player's own remote, so it is GitHub's (or your forge's) problem, and the
orchestrator only ever *reads*. That changes the moment you take the advice
in `nat_post` and host bare repos locally: then **you** must give each player
their own SSH key and make each bare repo writable only by its owner, or a
player can rewrite their opponent's service to be trivially exploitable.

Commits are deliberately **not** pinned — a push *is* the patch (RULES §8) —
but every deploy records the revision and the artifact's content hash in the
`deploys` ledger, so a rewritten history is auditable after the fact.

Manifest fields that reach a path or a request line are validated: `build`
and `run` must be repo-relative with no traversal, `health` must be a single
short request line with no CR/LF (so a manifest cannot split requests),
`docroot` must be the documented placeholder or a repo-relative path, and the
declared name must match the roster entry. Fixtures are always planted at a
fixed location in the guest regardless of what the manifest asks for.
