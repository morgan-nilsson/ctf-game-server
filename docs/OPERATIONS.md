# Operations runbook

Everything here assumes `ctfctl` on `$PATH` (install.sh symlinks it) and
`CTF_CONFIG=/etc/ctf/ctf.toml`.

---

## Bring-up (SETUP §10, in order)

```bash
ctfctl preflight                      # 1. /dev/kvm, tools, config sanity
sudo topology/build-rootfs.sh         #    guest image, once
systemctl start ctf-topology          # 2. planes + microVMs
topology/networks.sh verify           #    prove the planes are isolated
ctfctl deploy all                     # 3. first build of every repo
systemctl start ctf-tick              # 4. scoring starts
systemctl start ctf-leaderboard       # 5. viewer page
systemctl start ctf-submit            # 6. submission API
systemctl start ctf-watcher           #    push = patch
ctfctl status
```

Step 2's `verify` is not optional. It is the difference between "the referee
is unattackable" and "we assumed the referee was unattackable".

---

## Adding a person to the game

Two halves: **access to the host**, then **a slot in the game**. A remote
player needs both — their attacker foothold is a namespace *on the host*, so
there is no way to play without a login here.

### 1. Let them reach the host

Tailscale, so nothing is exposed publicly:

* Admin console → **Users → Invite** → send the link. They install Tailscale
  and `tailscale up`; the host is then reachable at its `100.x` address or
  MagicDNS name, from anywhere.
* Prefer inviting them to the tailnet over sharing a single node if they will
  also want to reach the leaderboard.
* Set an ACL if your tailnet has machines they should not touch.

### 2. Give them a login and their own foothold

```bash
sudo adduser --disabled-password --gecos "" friend
sudo install -d -m 700 -o friend -g friend /home/friend/.ssh
# paste THEIR public key:
sudo tee /home/friend/.ssh/authorized_keys <<< 'ssh-ed25519 AAAA... them@laptop'
sudo chown friend:friend /home/friend/.ssh/authorized_keys
sudo chmod 600 /home/friend/.ssh/authorized_keys
```

Then let them into **their own** foothold and nothing else:

```bash
echo 'friend ALL=(root) NOPASSWD: /usr/bin/ip netns exec ctf-foot-friend *' \
  | sudo tee /etc/sudoers.d/ctf-foothold-friend
sudo chmod 440 /etc/sudoers.d/ctf-foothold-friend
sudo visudo -cf /etc/sudoers.d/ctf-foothold-friend
```

Name the namespace after *their* player name. Do not give them blanket sudo:
root on the host is root over the referee, the flag store and their
opponent's VM, which ends the game (RULES §9).

### 3. Give them a slot in the game

1. Add a `[[players]]` block to `/etc/ctf/ctf.toml` (name, repo, branch, a
   fresh `submit_token`). Everything else — service subnet, VM link, foothold
   namespace — is derived from the block's position in the list.
2. `ctfctl topology apply` — creates the new tap, foothold namespace, routes
   and firewall entries. Existing players are untouched.
3. `ctfctl deploy <name>`.
4. If their repo is private, `sudo ctfctl keygen <name>` and have them paste
   the printed public key into their repo as a read-only deploy key.
5. `ctfctl token <name>` and send them the token over a private channel — it
   is their scoring identity, and anyone holding it can submit as them.

### 4. Hand them

* the leaderboard URL (their tunnel, or the `serve` address)
* `docs/PLAYER-QUICKSTART.md` and `docs/NOTE-API.md`
* their submit token and the `curl` line from `ctfctl token`
* how to attack: `ssh <host>` then `sudo ip netns exec ctf-foot-<name> -- bash`

Generate a token with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Removing a player: delete the block and `ctfctl topology apply`. Their history
stays in the ledger; they are marked `disabled` and stop being probed.

**Do not reorder the player list mid-game.** Index position determines
addressing, so reordering renumbers subnets under running VMs. Append only.

---

## Giving players their footholds

Each player attacks from their own network namespace on the game plane
(RULES §5: send freely, sniff nothing).

```bash
ctfctl foothold morgan                 # interactive shell in that namespace
ctfctl foothold morgan -- nmap -sT 10.0.2.2
```

For remote players, give them SSH to the host and a sudo rule for exactly
`ip netns exec ctf-foot-<their-name>`. They can reach every other player's
service subnet, the submission API, and the leaderboard — nothing else.

---

## Day-to-day

| Task | Command |
|---|---|
| Overview | `ctfctl status` |
| Why is a rung down? | `ctfctl logs tick -f` |
| What is the guest doing? | `ctfctl console <player>` |
| Force a redeploy | `ctfctl deploy <player> --force` |
| Steal ledger | `ctfctl submissions` |
| Class spot-checks | `ctfctl submissions --pending` → `ctfctl review <id> approve` |
| Pause for dinner | `ctfctl freeze` / `ctfctl unfreeze` |
| Backup | `ctfctl backup` (hourly timer also installed) |
| New round | `ctfctl backup && ctfctl reset --confirm` |

---

## Updating a running host

The host runs from `/opt/ctf`, not your working copy. Nothing you edit
locally takes effect until you copy it over and re-run the installer.

```bash
# from your working copy
rsync -a --delete --exclude .git ./ <host>:/tmp/ctf-update/
ssh <host>
sudo /tmp/ctf-update/install.sh --no-packages     # idempotent; keeps /etc/ctf/ctf.toml
ctfctl version                                     # confirm the digest changed
```

`install.sh` replaces `/opt/ctf` wholesale (so deleted files actually
disappear), leaves your config alone, reloads systemd and re-enables the
units. `--no-packages` skips apt, which is what you want for a code-only
update.

Then apply the change, picking the lightest option that covers it:

| What changed | Apply with | Cost |
|---|---|---|
| `orchestrator/*.py`, `bin/ctfctl` | `systemctl restart ctf-tick ctf-submit ctf-leaderboard ctf-watcher` | a second; the tick resumes from the stored counter |
| `topology/*.nft`, routes, `networks.sh` | `sudo /opt/ctf/topology/networks.sh up` | a sub-second packet blip while the ruleset reloads |
| `topology/guest/*`, the rootfs | `sudo topology/build-rootfs.sh` then redeploy players | each guest reboots |
| `service.toml` / player code | the player pushes; the watcher redeploys | 2 ticks of SLA grace |
| systemd unit files | `systemctl daemon-reload` (install.sh does it) then restart that unit | as above |

**Do not `systemctl restart ctf-topology` mid-game to pick up a firewall
change.** Its `ExecStop` runs `vm.sh all-stop`, so every microVM goes down and
everyone eats the downtime. `networks.sh up` is idempotent and reloads the
policy, routes and offload settings without touching running VMs.

After any update:

```bash
ctfctl version                 # digest matches, no drift
ctfctl selftest                # the referee still works
sudo ctfctl topology verify    # isolation still holds (after network changes)
ctfctl status                  # services active, grid healthy
```

`ctfctl version` also catches the other direction: files hand-edited on the
host since install show as `DRIFT`, which is what you want to know before
blaming the code for behaving oddly.

---

## Crashes, backups and restore

**What survives what:**

| Event | Effect |
|---|---|
| A referee process crashes or is OOM-killed | Nothing committed is lost. systemd restarts it within 5 s and the tick counter resumes from `meta`. Verified by SIGKILLing a writer mid-flight: 154/154 acknowledged writes survived, integrity `ok`. |
| The host loses power | Nothing committed is lost either: `game.sqlite_synchronous = "FULL"` fsyncs every commit, so a steal is durable the instant the player is told it scored. Set `"NORMAL"` for speed and you accept losing the last few commits. |
| A microVM dies | Only that player's SLA, for as long as it is down. The ledger is untouched. |
| The database is corrupted or wrongly edited | Restore from a backup (below). |
| The host's disk dies | Backups live on the same disk. **Copy them off-host** — see below. |

Scores are never stored as running totals. They are derived from the `uptime`
and `submissions` ledgers, so `ctfctl recount` rebuilds the board from source
data at any time, and a wrong submission can be re-priced without drift.

**Backups.** `ctf-backup.timer` runs hourly (enabled by `install.sh`) and
writes to `/var/backups/ctf`. Each backup is a consistent snapshot taken with
sqlite's online backup API — safe to take while the tick loop is writing — and
is integrity-checked and chmod 0600 on the way out, because a backup contains
live flags.

```bash
ctfctl backup                  # ad-hoc, to /var/backups/ctf
ctfctl backup /mnt/x --keep 7  # elsewhere, keeping the last 7
ctfctl verify                  # is the LIVE database healthy?
ctfctl verify /var/backups/ctf/ctf-backup-20260101-120000
```

Retention defaults to `game.backup_keep` (48 = two days of hourly copies);
older ones are pruned automatically.

**Never copy `state.db` with `cp` while the referee runs** — the `-wal` file
may hold commits the main file does not. Use `ctfctl backup`.

**Restore:**

```bash
systemctl stop ctf-tick ctf-submit ctf-watcher
ctfctl restore /var/backups/ctf/ctf-backup-20260101-120000     # dry run
ctfctl restore /var/backups/ctf/ctf-backup-20260101-120000 --confirm
systemctl start ctf-tick ctf-submit ctf-watcher
```

Restore refuses to run while the referee is live (a running tick loop would
write over what you just restored), refuses a backup that fails its integrity
check, and keeps whatever it replaced as `state.db.replaced-<timestamp>` — so
the restore itself is reversible. It prints the recovered scores when done.

**Get the backups off the host.** Everything here is one box; a disk failure
takes the live database and every backup with it. One line in root's crontab
is enough:

```
17 * * * * rsync -a --delete /var/backups/ctf/ backup-host:/ctf-backups/
```

Treat those copies as secret: they contain unexpired flags.

---

## The optional defense bonus (RULES §7)

`game.defense_bonus` is off by default. When set, it is settled **one tick
late**: the bonus for tick T is awarded at the start of tick T+1. Judging it
at the end of T would pay out before any attacker could possibly have
submitted a flag planted seconds earlier — i.e. unconditionally, which is not
a defense bonus. It is recomputed from the weight table rather than
incremented, so a re-run cannot inflate anyone's score.

One consequence worth knowing: the current tick's uptime figure can still
grow slightly after the tick closes. That is the bonus landing, not a bug.

---

## Exploit-class review (RULES §7)

The floor tier is derived from where the flag lived: note app = `app` (50),
UDP fixture = `transport` (75). An attacker claiming more sends
`"class": "transport"|"rce"` with a `writeup`. They are paid the floor
immediately and the difference is held:

```bash
ctfctl submissions --pending
ctfctl review 14            # prints the write-up
ctfctl review 14 approve    # or: reject
```

Approving re-prices that submission and re-renders the board. This is the
spot-check SETUP §7 asks for, with the honour system removed from the
scoring path.

---

## Common failures

**A rung is down but the service looks fine.** "Up" is strict (RULES §6).
Check, in order: does the status line carry the *exact* version; does HTTP/1.1
keep the connection open for a second request; does `GET /note/{id}` return
the flag to its own token K-1 ticks later. `ctfctl logs tick` names which of
the three failed.

**Transport-layer exploits never land.** The two settings that cause this,
in order of likelihood: (1) `rp_filter` back on somewhere — check
`conf.all`, `conf.default` *and* the specific device, on the host **and**
inside the guest, since the kernel uses the maximum; (2) conntrack eating the
packets — `nft list chain inet ctf raw_prerouting` must show `notrack` on the
foothold interfaces. `networks.sh verify` asserts both. App-layer steals
working while transport-layer ones do not is the signature.

**SLA flaking on long responses.** Almost always offload. Both ends must have
checksum offload off (RULES §5): `ethtool -K tun0 tx off rx off` in the guest
— `ctf-init` does it, but a player's `run.sh` that recreates `tun0` undoes it.

**Deploy says "rate limited".** Working as intended: 1 redeploy / 90 s per
service (RULES §8). `--force` overrides; do not make that a habit, it is the
anti-rebuild-to-dodge-exploitation rule.

**A build fails with a network error.** Working as intended by default:
builders are offline (RULES §9), so dependencies must be vendored. If that is
too much friction for your group, flip it:

```toml
[game]
offline_builds = false
```

then `sudo /opt/ctf/topology/networks.sh up` (reloads the build-egress rules)
and the next deploy fetches normally. The build still cannot reach the
referee, the viewer edge or any player subnet — that restriction is pinned to
the build user's uid and stays on either way. Tell your players, since it
changes RULES §9 for your game.

**Firecracker won't boot.** `ls /dev/kvm`. No KVM means no microVM — switch to
`vm.hypervisor = "qemu-tcg"` and raise `probe.timeout`, or drop RCE from scope
and run services in containers. `ctfctl preflight` says which case you are in.

**The leaderboard shows `~` for a protocol.** SLA grace after a redeploy
(RULES §8). It clears after 2 ticks. The rung is scoring its points; the `~`
only tells you it is being carried rather than genuinely answering.

**The grid looks like it is from the previous tick.** It is. `scoreboard.json`
carries both `tick` (the tick in progress) and `grid_tick` (the most recent
tick that has results), and the page draws the grid from the latter — so a
render triggered mid-tick by an incoming submission cannot paint an empty
grid.

---

## Plane modes, and libvirt

`net.plane_mode` picks how the game plane is built. Both modes give the same
structural property — every guest alone on its own L2 segment, so guest-to-
guest traffic is routed and filtered by the `forward` hook with no
`br_netfilter`/`ebtables` involvement, and no guest can sniff a peer's link.

| | `netns` (default) | `host` |
|---|---|---|
| Segments | a tap per guest in the `ctf-gw` namespace; no bridge at all | one bridge per guest (`br-svc<N>`) in the root namespace |
| Router | the `ctf-gw` namespace | the host itself |
| Policy | `topology/ctf.nft` (referee path is `forward`) | `topology/ctf-host.nft` (referee path is `output`/`input`) |
| Host networking | untouched | `ip_forward=1` and `rp_filter=0` host-wide |
| Hypervisor | `vm.sh` starts it inside the namespace | anything that can attach to a bridge |

Use `host` mode when **libvirt owns the guests**. Then set
`vm.hypervisor = "libvirt"` and, per domain:

```xml
<interface type='bridge'>
  <source bridge='br-svc1'/>          <!-- player index 1 -->
  <model type='virtio'/>
</interface>
<disk type='file' device='disk'>
  <source file='/srv/ctf/artifacts/morgan/data.ext4'/>
  <target dev='vdb' bus='virtio'/>     <!-- ctf-init mounts vdb at /srv/app -->
</disk>
```

Domains are named `ctf-<player>` (override with `CTF_LIBVIRT_PREFIX`).
`ctfctl deploy` still rebuilds the data disk and bounces the domain through
`virsh`, so the patch mechanic is unchanged.

Humans reach footholds by jumping: `ssh host` then `ctfctl foothold <name>`
(or `ip netns exec ctf-foot-<name>`). Footholds have **no LAN leg** by design,
and `ip_forward=0` inside them, so a popped service cannot pivot LAN-ward
through its own attacker's vantage point.

### If the referee needs the internet

It shouldn't. The `nat_post` chain in both policy files is deliberately empty,
with the one-line masquerade commented out. If you do enable it, scope it to
the referee's own egress interface — **never** a service plane, or you have
just handed a popped service a route out. The cleaner arrangement is to have
players push to a bare git remote on the host over the viewer/LAN edge and
point `repo` at that local path, so the referee never dials out at all.

---

## Security posture — what protects what

| Claim | Enforced by |
|---|---|
| Services cannot reach the referee | nftables `forward` policy in `ctf-gw`: only control→service and foothold→service are accepted, and the drop is logged. Verified at boot from inside the guest by `isolation-selftest.sh`. |
| Services cannot reach the leaderboard/submission API | Same rule, plus both services bind the viewer address only and refuse to start on `0.0.0.0`, plus `IPAddressAllow` in their units. |
| Nobody can sniff a peer's TUN link | Topology: every guest is alone on its own L2 segment, so peer traffic is *routed*, never bridged past anyone. There is no shared broadcast domain on the game plane to sniff, in either plane mode. |
| Blind injection actually lands | `rp_filter` is 0 on every game-plane interface (`all`, `default` and per-device — the kernel takes the max) *and* inside each guest, and the attacker path carries `notrack`. Without both, spoofed and off-window segments are dropped before the target stack sees them and the 75-point flag class silently stops existing. `networks.sh verify` checks for both. |
| RCE in a service cannot reach the host or the other player | Hypervisor boundary (microVM), fresh rootfs copy per start, no route out. VM escape is out of scope by rule (RULES §9). |
| Builds cannot exfiltrate or fetch | `bwrap --unshare-all` (or `unshare -n`), separate build user with no read access to the flag store, wiped environment. |
| The leaderboard cannot leak a flag | It only ever reads the rendered `scoreboard.json`, which is built from the ledger and contains no tokens. The e2e test asserts this. |

---

## What is deliberately *not* automated

* **Exploit-class judgement above the floor tier.** A human reads the write-up.
* **HTTP/3 probing.** No QUIC client ships with the referee (docs/NOTE-API.md §5).
* **The guest kernel.** Bring your own `vmlinux`; the image build script does
  not fetch one, since which kernel you run is a parity decision.
