# Go live

Ordered. Each step has a gate — if the gate fails, fix it there rather than
pressing on, because everything after it depends on it.

```bash
sudo ./install.sh
sudo $EDITOR /etc/ctf/ctf.toml          # roster + a real submit_token each
ctfctl preflight                        # GATE: tools, /dev/kvm, config, images
```

### If preflight complains about the guest kernel

Firecracker needs an **uncompressed vmlinux**, which nothing here builds. In a
hurry, take the zero-download path — set in `/etc/ctf/ctf.toml`:

```toml
[vm]
hypervisor = "qemu"        # vm.sh then uses /boot/vmlinuz-$(uname -r)
```

No KVM at all (`ls /dev/kvm` empty, e.g. a cloud VM without nested virt)?
`hypervisor = "qemu-tcg"` boots but is slow — raise `probe.timeout` to ~10 s
or the SLA will flake every tick. RCE-class flags still work; only speed
suffers.

```bash
sudo topology/build-rootfs.sh           # guest image, once (a few minutes)
ctfctl selftest                         # GATE: does the referee work at all?
```

`selftest` runs the real prober, the real flag contract and the hostile-input
checks against a bundled reference service on loopback. **If this passes,
anything broken later is a player's stack or the network — not the referee.**

```bash
sudo systemctl start ctf-topology       # planes + microVMs
sudo ctfctl topology verify             # GATE: isolation actually holds
```

Read that output. The **negative** results are the ones that matter: every
`foothold -> control plane blocked` line is the claim the whole game rests on.
If any says FAIL, stop and fix it — a leaky referee plane invalidates the
round.

```bash
ctfctl deploy all                       # first build+deploy of every repo
ctfctl status                           # GATE: services running?
sudo systemctl start ctf-tick ctf-leaderboard ctf-submit ctf-watcher
ctfctl status
```

Open the leaderboard on the viewer address (default `http://10.9.0.1:8000/`).

### Hand each player

* their submit token: `ctfctl token <name>` (send privately — it is their
  scoring identity)
* `docs/PLAYER-QUICKSTART.md` and `docs/NOTE-API.md`
* their foothold: `ssh` to the host, then `ctfctl foothold <name>`

---

## First five minutes: what "wrong" looks like

| Symptom | Almost always |
|---|---|
| Every rung down for everyone | The tick loop can't reach the game plane. `ctfctl logs tick -f`, then `ctfctl topology verify`. |
| One player down, others fine | Their stack. `ctfctl console <name>` shows their service's output and the `[isolation]` self-test. |
| A rung answers but stays down | "Up" is strict: it needs the *exact* version **and** a completed flag round-trip. The log line names which of the two failed. |
| `~` on the grid | SLA grace after a redeploy. Clears in 2 ticks. Working as intended. |
| Deploy says "rate limited" | 1 redeploy / 90 s per service (RULES §8). `--force` if you must. |
| Build fails on a network error | Builders are offline by design. They must vendor dependencies. |
| Transport-layer exploits never land | `rp_filter` back on somewhere, or `notrack` missing. `ctfctl topology verify` checks both. |

## Mid-game controls

```bash
ctfctl freeze / unfreeze         # pause scoring (dinner, an argument, a bug)
ctfctl submissions --pending     # claimed exploit classes awaiting review
ctfctl review <id> approve       # settle one
ctfctl deploy <player> --force   # bypass the redeploy rate limit
ctfctl backup                    # hourly already, but before anything risky
```

If something goes badly wrong: `ctfctl backup` first, then
`ctfctl restore <dir> --confirm` (stop `ctf-tick ctf-submit ctf-watcher`
first — restore refuses while they run). Scores are derived from the ledger,
so `ctfctl recount` fixes a stale board without touching history.

## Two things to accept before you start

* **The prober parses hostile bytes every tick.** It is capped, budgeted and
  sandboxed, but it is the one channel that must stay open into player code.
* **The hypervisor is the only real boundary**, and in-guest RCE is an
  intended flag path. "No VM escape" is a rule, not a control.

Both are in `docs/THREAT-MODEL.md`. Worth five minutes before you hand anyone
a foothold.
