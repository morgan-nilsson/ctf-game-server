# Player quickstart

You are writing a transport stack and an HTTP server from raw sockets, and
you are running it on someone else's host. Here is what the host expects.

## 1. Your repo

```
service.toml     the manifest — the only interface to the orchestrator
build.sh         runs offline, in a sandbox, with no flags and no secrets
run.sh           starts your stack inside the guest
src/             your stack
```

## 2. `service.toml`

```toml
[service]
name = "morgan"                       # must match your name in the host config

transports    = ["tcp"]               # declare only what you have finished
http_versions = ["1.0", "1.1"]

build    = "./build.sh"
run      = "./run.sh"
tcp_port = 8080
udp_port = 8080
docroot  = "$DOCROOT"
caps     = ["NET_RAW", "NET_ADMIN"]
health   = "GET /health"
```

Declaring is risk/reward (RULES §3): every transport you declare raises your
ceiling *and* opens a surface. `quic` requires `udp`; `0.9/1.0/1.1/2` require
`tcp`; `3` requires `quic`. A bad manifest fails the deploy — check yours
before pushing:

```bash
ctfctl validate service.toml
```

## 3. The environment inside the guest

* `tun0` already exists, is up, is owned by your user `app`, MTU 1500,
  offload off. The kernel holds `10.0.<n>.1`; **your stack answers
  `10.0.<n>.2`**.
* You open `/dev/net/tun` and attach to `tun0` — no root needed.
* `$DOCROOT` is `/srv/app/docroot`, where the orchestrator plants fixtures.
* You get the caps you declared, ambient, nothing more.
* There is no route off the game plane. No DNS, no package fetch at runtime.
* `run.sh` is supervised: if your process dies it restarts, with backoff.
* **Every deploy gives you a fresh rootfs.** Nothing you write outside
  `/srv/app` survives, which is also why an attacker's persistence does not.

## 4. Building

Builds run **offline**, in a sandbox, as a user that cannot see any flag.
Vendor your dependencies. Set `SOURCE_DATE_EPOCH` if your toolchain needs it;
it is already exported. Reproducible builds are required (RULES §8) — the
orchestrator records the content hash of each build so artifacts stay
parity-comparable.

## 5. Patching

A push **is** the patch (RULES §8). The watcher notices within ~30 s, rebuilds
and redeploys. Limits: 1 redeploy / 90 s, and each redeploy buys 2 ticks of
SLA immunity so patching does not cost you uptime.

## 6. Attacking and submitting

Attack from your foothold namespace (`ctfctl foothold <you>`), never from your
own service. Then:

```bash
curl -s http://10.9.0.1:8001/submit -H 'Content-Type: application/json' \
  -d '{"by":"morgan","token":"<your token>","flag":"FLAG_...",
       "class":"transport","writeup":"blind ISN guess, details..."}'
```

`class` is optional. The floor tier for the endpoint is paid immediately; a
higher claim needs a write-up and is settled by a human spot-check.

A flag scores only if it is fresh (K = 5 ticks), belongs to someone else, and
was planted over a declared transport. No hoarding.

## 7. What you must not do

Attack the referee, builder, flag store, submission API or leaderboard; sniff
a peer's TUN link; tamper with MTU/offload parity; fetch anything at build
time; escape the VM. See RULES §9 — the interesting attacks are all inside
the service.
