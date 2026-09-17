# CTF central host

Hosting scripts for the attack/defense CTF specified in [`RULES.md`](RULES.md)
and [`SETUP.md`](SETUP.md): one Ubuntu host runs the referee, the service
microVMs, the attacker footholds and the leaderboard, split across three
network planes so "referee unattackable, services attackable, leaderboard
human-viewable" is true by construction rather than by agreement.

Built for **N players**, not two. Everything per-player — service subnet, VM
link, tap, foothold namespace, firewall entries — is derived from the player's
position in the config roster, so adding the fifth player is a config block
plus `ctfctl topology apply`.

Two plane modes, same structural property: `netns` (taps in a router
namespace, self-contained) or `host` (one bridge per guest, host as sole
router — use this if libvirt owns your guests).

```
                ┌──────────── control plane (the host) ─────────────┐
                │  tick loop · flag store · builder · deploy         │
                └───────┬───────────────────────────┬───────────────┘
      viewer edge ──────┘                           │ probes / deploys
  leaderboard :8000                                 ▼
  submission  :8001                        ┌──── ctf-gw (router ns) ────┐
        ▲                                  │  tap-p1 ── microVM p1      │
        │                                  │  tap-p2 ── microVM p2      │
   workstations                            │  …                          │
        │                                  │  vf1 ── foothold-p1         │
        └── footholds may submit ──────────│  vf2 ── foothold-p2         │
                                           └────────────────────────────┘
   every link is a point-to-point /30: you can send anywhere, sniff nothing
```

---

## Quick start

**Running it today? Follow [`GO-LIVE.md`](GO-LIVE.md)** — the same steps with
the gates and the "no KVM / no kernel" escape hatches called out.

```bash
sudo ./install.sh                     # packages, users, /opt/ctf, systemd
sudo $EDITOR /etc/ctf/ctf.toml        # roster + submit tokens
ctfctl preflight                      # /dev/kvm, tools, config
sudo /opt/ctf/topology/build-rootfs.sh
systemctl start ctf-topology          # planes + microVMs
/opt/ctf/topology/networks.sh verify  # prove the isolation
ctfctl deploy all
systemctl start ctf-tick ctf-leaderboard ctf-submit ctf-watcher
ctfctl status
```

**Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) before running this.**
The network planes are the easy half; the paths that bypass them — the prober
parsing hostile bytes, player build code next to the flag store, spoofing
latitude on the attack path — are documented there with what the code does
about each and what stays honour-system.

Full runbook: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).
Hand players [`docs/PLAYER-QUICKSTART.md`](docs/PLAYER-QUICKSTART.md) and
[`docs/NOTE-API.md`](docs/NOTE-API.md).

---

## Layout

```
orchestrator/
  config.py        roster + address derivation (index -> every subnet)
  validate.py      SETUP §4 manifest schema; a bad manifest fails deploy
  state.py         sqlite flag store + score ledger (scores are derived, not stored)
  hpack.py         minimal HPACK for the h2c prober
  httpclient.py    strict per-version HTTP clients (0.9 / 1.0 / 1.1 / h2c)
  probes.py        the flag contract: plant, retrieve, expire; HTTP/3 hook
  tick.py          SETUP §6 referee loop, N players probed concurrently
  submit.py        SETUP §7 submission API (viewer edge)
  leaderboard.py   SETUP §8 live page + /state (viewer edge)
  deploy.py        SETUP §5 build pipeline: fetch, sandbox-build, disk, boot, healthcheck
  watcher.py       push = patch (RULES §8)
  topology.py      emits the derived topology to the shell scripts
  builder/         the offline build sandbox
topology/
  networks.sh      control / game / viewer planes, N players, nftables
  vm.sh            microVM lifecycle (Firecracker or QEMU/KVM)
  build-rootfs.sh  base guest image
  guest/           guest init: tun0, caps, supervision, isolation self-test
bin/
  ctfctl           the operator CLI
  preflight.sh     can this host run the game?
systemd/           units for tick, submit, leaderboard, watcher, topology, backup
tests/
  fake_service.py  known-good target service
  e2e.py           drives the real referee against it
docs/              operations, player quickstart, the flag contract
```

---

## Design decisions worth knowing

**The flag store is sqlite, not a dict.** SETUP §6 sketches `FLAGDB = {}`, but
the tick loop runs on control and the submission API on viewer — two
processes. They share `state.db` (WAL). Scores are never stored as running
totals; they are derived from the `uptime` and `submissions` ledgers, so a
recount is always possible and a bad submission can be re-priced without
drift.

**Deploy replaces the VM's disk and reboots it.** There is no deploy agent
inside the guest, because an agent needs a route back to control — exactly the
route RULES §1 says must not exist. A side effect worth having: every deploy
starts from a fresh copy of the base rootfs, so an attacker's persistence dies
with the patch.

**Blind vantage is topological.** Every guest and every foothold is alone on
its own L2 segment, so peer traffic is *routed*, not bridged — nftables'
forward hook filters it natively, with no `br_netfilter`/`ebtables` mess, and
there is no shared broadcast domain to sniff. "You may not sniff the peer's
link" needs no honour system: there is nothing to sniff. ISN quality decides
hijacks, which is the point of RULES §5.

**Two asymmetries carry the security argument.** They are easy to get
backwards, and both failures are silent:

* *Conntrack, on the referee path only.* Referee→service is tracked, so a
  service can answer the referee but can never dial it. That single rule is
  the RCE containment — own the service process and you are boxed into
  replying in-band on a connection someone else opened.
* *Notrack, on the attack path.* Blind ISN hijacking, forged-segment
  acceptance and UDP parser over-reads are *by definition* packets a state
  engine files as invalid. Track them and the 75-point flag class quietly
  stops existing. Same for `rp_filter`, which must be 0 on `all`, `default`
  and each device, on the host and inside each guest.

`networks.sh verify` asserts both, and the negative tests (nothing reaches
the referee) matter more than the positive ones.

**"Up" is judged strictly, per version.** Each HTTP version gets its own
hand-written client: HTTP/1.0 must answer `HTTP/1.0` and close; HTTP/1.1 must
answer `HTTP/1.1` and survive a second request on the same socket; h2c must
frame properly. No `http.client` anywhere in the prober — the referee has to
judge wire bytes, not have a library normalise them away.

**HTTP/3 is not probed in-process.** Writing QUIC + TLS 1.3 is the players'
apex rung; a half-correct referee QUIC client would score it wrongly. Instead
there is a documented external hook (`probe.h3_probe_cmd`). Unconfigured,
HTTP/3 simply shows as down — honest and visible.

**Scores are derived, not accumulated.** Totals come from the `uptime` and
`submissions` ledgers every time they are rendered, so `ctfctl recount`
rebuilds the board from source data and a mis-scored steal can be re-priced
without drift. The ledger is sqlite with `synchronous=FULL`: a process crash
loses nothing, and neither does a power cut. Hourly verified backups, and
`ctfctl restore` puts one back (refusing to run under a live referee, and
keeping what it replaced).

**Exploit class is derived, then spot-checked.** The floor tier comes from
where the flag lived (note app = 50, UDP fixture = 75). A higher claim needs a
write-up, is paid at the floor immediately, and settles via
`ctfctl review <id> approve`.

---

## Tests

```bash
python3 tests/e2e.py
```

Starts a known-good fake service and drives the *real* tick loop and the
*real* submission API against it on loopback — no root, no VMs, no network
planes. It asserts the rules that are easy to get subtly wrong: per-protocol
uptime weights, undeclared protocols never being probed or scored, the K-tick
SLA round-trip, self-submission refusal, cross-steal scoring, replay
detection, expiry, and that the rendered scoreboard contains no flag token.

---

## Requirements

Ubuntu 22.04+ (Python ≥ 3.11 for `tomllib`), `/dev/kvm` for microVMs, and
`nftables`, `iproute2`, `ethtool`, `e2fsprogs`, `git`. `bubblewrap` for the
build sandbox, `debootstrap` for the guest image. `ctfctl preflight` checks
all of it and tells you what to do if KVM is missing.
