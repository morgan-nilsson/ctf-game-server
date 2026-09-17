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

### Dry run, before anyone depends on it

Prove the scoring loop end to end on your own box, playing both sides. You
are the referee, so you can read a live flag — that is exactly what an
attacker has to steal:

```bash
sudo ctfctl topology verify         # GATE: read the negative results
ctfctl status                       # are the declared rungs green?

ctfctl flags --show-tokens          # take one flag owned by player A
curl -s http://10.9.0.1:8001/submit -H 'Content-Type: application/json' \
  -d '{"by":"B","token":"<B token>","flag":"FLAG_..."}'
# expect: {"verdict":"+50",...}

ctfctl submissions                  # the steal is in the ledger
ctfctl status                       # B's attack column moved
```

Then prove the patch mechanic: push a trivial commit to a player repo and
watch the watcher pick it up within ~30 s —

```bash
ctfctl logs watcher -f              # "deployed <rev>"
ctfctl status                       # new rev, and `~` grace on the grid
```

**Then wipe the practice scores before the real start:**

```bash
ctfctl backup && ctfctl reset --confirm
```

`reset` clears flags, uptime and submissions and puts the tick counter back to
0, keeping the roster and deployed services. Skip it and you start the real
game with your test steal on the board.

### Viewing it from another machine

The leaderboard binds the viewer address on the host, not `0.0.0.0` (RULES §9
— the game plane must never reach the viewer edge). From a laptop on the same
network, tunnel rather than re-binding anything:

```bash
ssh -f -N -L 8000:10.9.0.1:8000 -L 8001:10.9.0.1:8001 <you>@<host>
# then: http://localhost:8000/
```

That is the whole setup for a host + laptop. No router port forwarding, no
config change, nothing extra exposed.

To let several people on a trusted LAN browse it without tunnels, set
`net.viewer_bind` to the host's LAN IP **and** `net.viewer_cidr` to the LAN
subnet (both, or footholds lose their route to the submission API), then
restart `ctf-topology`, `ctf-leaderboard` and `ctf-submit`.

### Players who are not on your network

**Do not port-forward 8000/8001 to the internet.** The leaderboard and the
submission API are plain HTTP with bearer tokens and no TLS: exposing them
publishes submit tokens and, through the API, flags — in cleartext, to
anyone who can watch the path or find the port.

A remote player needs SSH to the host anyway, because their attacker foothold
is a namespace on the host (`ctfctl foothold <name>`). So expose **SSH only**
— ideally via WireGuard/Tailscale rather than a forwarded port 22 — and have
them tunnel the two ports over it exactly as above. One door, keyed, and
everything else rides through it.

Give them a normal user account on the host plus a sudo rule for just their
own foothold:

```
theirname ALL=(root) NOPASSWD: /usr/bin/ip netns exec ctf-foot-theirname *
```

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

## Updating mid-game

```bash
rsync -a --delete --exclude .git ./ <host>:/tmp/ctf-update/
ssh <host> 'sudo /tmp/ctf-update/install.sh --no-packages && ctfctl version'
sudo systemctl restart ctf-tick ctf-submit ctf-leaderboard ctf-watcher   # code
sudo /opt/ctf/topology/networks.sh up                                    # firewall/routes
```

Never `systemctl restart ctf-topology` for a firewall change while people are
playing — it stops every microVM. `networks.sh up` reloads the policy in
place. Full table in `docs/OPERATIONS.md`.

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
