"""SETUP §5 — build pipeline. A push IS the patch mechanic (RULES §8).

  fetch → validate manifest → rate-limit → offline sandboxed build →
  pack a data disk → restart the microVM on it → healthcheck → SLA grace

Deploying by *replacing the VM's data disk and rebooting it* is deliberate:
it means the guest never needs a route back to the control plane. A push-based
deploy channel into a live guest would hand an attacker with RCE exactly the
route RULES §1 says must not exist.
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import sys
import time
from pathlib import Path

from . import probes
from .config import Config, Player, load as load_config
from .state import Store
from .validate import ManifestError, load as load_manifest

log = logging.getLogger("deploy")
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent


class DeployError(Exception):
    pass


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    log.debug("run: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def git_env(player) -> dict:
    """Environment for git operations against one player's repo.

    The key is named explicitly rather than left to ~/.ssh or an agent,
    because these commands run as different users depending on the trigger:
    root from the watcher, you from `ctfctl deploy`. An agent-based setup
    gives you a deploy that works by hand and fails from the service.
    """
    env = dict(os.environ)
    key = getattr(player, "ssh_key", "")
    if key and Path(key).is_file():
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {shlex.quote(str(key))} -o IdentitiesOnly=yes "
            "-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10"
        )
    env.setdefault("GIT_TERMINAL_PROMPT", "0")   # fail fast, never hang on a prompt
    return env


def _sudo(cmd: list[str]) -> list[str]:
    return cmd if os.geteuid() == 0 else ["sudo", "-n", *cmd]


# --------------------------------------------------------------------------
def sync_repo(cfg: Config, player: Player, rev: str | None) -> tuple[Path, str]:
    """Mirror the player's repo and check out a working tree. Read-only use of
    their repo — the orchestrator never pushes."""
    mirror = cfg.path_of("repos") / f"{player.name}.git"
    mirror.parent.mkdir(parents=True, exist_ok=True)
    env = git_env(player)
    if not mirror.exists():
        res = run(["git", "clone", "--mirror", player.repo, str(mirror)], env=env)
        if res.returncode:
            raise DeployError(f"git clone failed: {res.stderr.strip()[:400]}")
    else:
        res = run(["git", "--git-dir", str(mirror), "fetch", "--prune", "origin",
                   f"+refs/heads/{player.branch}:refs/heads/{player.branch}"], env=env)
        if res.returncode:
            raise DeployError(f"git fetch failed: {res.stderr.strip()[:400]}")

    if not rev:
        res = run(["git", "--git-dir", str(mirror), "rev-parse", player.branch])
        if res.returncode:
            raise DeployError(f"unknown branch {player.branch}")
        rev = res.stdout.strip()

    work = cfg.path_of("players") / player.name / "src"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    res = run(["git", "--git-dir", str(mirror), "--work-tree", str(work), "checkout", "-f", rev])
    if res.returncode:
        raise DeployError(f"checkout {rev[:12]} failed: {res.stderr.strip()[:400]}")
    return work, rev


# --------------------------------------------------------------------------
# Build output is PLAYER-CONTROLLED. Everything below runs as root over a tree
# the build user wrote, so none of it may follow a symlink, open a special
# file, or write through a path component the build could have planted.
#
# The concrete attacks this closes: a build leaves `leak -> /srv/ctf/state.db`
# and a following copy puts the live flag store on the player's own disk; a
# build makes `service.env` or `docroot` a symlink and root writes wherever it
# points; a build leaves a FIFO or `-> /dev/zero` and the deploy hangs.
# --------------------------------------------------------------------------

def _ignore_special(directory: str, names: list[str]) -> list[str]:
    """copytree ignore hook: keep only directories, regular files, symlinks."""
    skip = []
    for name in names:
        try:
            mode = os.lstat(os.path.join(directory, name)).st_mode
        except OSError:
            skip.append(name)
            continue
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            skip.append(name)
    return skip


def copy_untrusted(src: Path, dst: Path) -> None:
    """Copy a build-controlled tree without being steered by it: symlinks are
    copied AS symlinks (never followed) and special files are dropped."""
    shutil.copytree(src, dst, symlinks=True, ignore=_ignore_special)


def ensure_real_dir(path: Path, root: Path) -> None:
    """Make `path` a real directory, replacing any symlink or file the build
    left at `root` or at any component between `root` and `path`."""
    cur = root
    for part in (("",) + path.relative_to(root).parts):
        cur = cur / part if part else cur
        if cur.is_symlink() or (cur.exists() and not cur.is_dir()):
            cur.unlink()
        cur.mkdir(exist_ok=True)


def write_owned(path: Path, text: str) -> None:
    """Write a file the orchestrator owns into a build-controlled directory:
    remove whatever is there first (a symlink included — unlink removes the
    link, not its target), then create it exclusively."""
    if path.is_symlink() or path.exists():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


def tree_digest(root: Path) -> str:
    """Content hash of a build output, independent of filesystem metadata —
    what makes two builds parity-comparable (RULES §8). Never follows a
    symlink (hashes the link text instead) and never opens a special file."""
    h = hashlib.sha256()
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            entries.append(Path(dirpath) / name)
    for path in sorted(entries, key=lambda p: str(p.relative_to(root))):
        rel = str(path.relative_to(root)).encode()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            h.update(b"L" + rel + b"\0" + os.readlink(path).encode() + b"\0")
        elif stat.S_ISREG(mode):
            h.update(rel)
            h.update(b"\0")
            h.update(hashlib.sha256(path.read_bytes()).digest())
    return h.hexdigest()


def build(cfg: Config, player: Player, src: Path, manifest: dict) -> tuple[Path, str, str]:
    final = cfg.path_of("artifacts") / player.name / "build"
    if final.exists():
        shutil.rmtree(final)
    final.parent.mkdir(parents=True, exist_ok=True)

    # The build runs as the unprivileged build user, which deliberately
    # cannot traverse /srv/ctf — the flag store lives there. So its output is
    # staged somewhere it CAN write, and handed off pull-only: once the build
    # has exited (and bwrap has killed everything it started), we copy the
    # result out as root without following anything it left behind.
    out = Path(tempfile.mkdtemp(prefix=f"ctf-out-{player.name}.",
                                dir=os.environ.get("CTF_BUILD_TMP", "/var/tmp")))

    script = REPO_ROOT / "orchestrator" / "builder" / "sandbox-build.sh"
    timeout = str(int(cfg.p("game", "build_timeout", default=600)))
    # Everything the referee owns is masked inside the build sandbox.
    masked = [cfg.raw["paths"][k] for k in ("root", "state_db", "fixtures", "logs", "run")
              if k in cfg.raw["paths"]]
    offline = bool(cfg.p("game", "offline_builds", default=True))
    env = dict(os.environ,
               CTF_MASK=" ".join(str(m) for m in masked),
               CTF_STATE_DB=str(cfg.path_of("state_db")),
               CTF_BUILD_NETWORK="0" if offline else "1")
    if not offline:
        log.info("%s: building WITH network access (game.offline_builds = false)", player.name)
    try:
        res = run([str(script), str(src), str(out), manifest["build"], timeout], env=env)
        log_text = (res.stdout or "") + (res.stderr or "")
        if res.returncode:
            raise DeployError(f"build failed (exit {res.returncode})\n{log_text[-2000:]}")
        copy_untrusted(out, final)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return final, tree_digest(final), log_text


def plant_fixtures(cfg: Config, out: Path) -> None:
    """SETUP §4: the orchestrator plants docroot fixtures. These are static
    props, never flags — flags only ever arrive over the wire, per tick."""
    fixtures = cfg.path_of("fixtures")
    docroot = out / "docroot"
    ensure_real_dir(docroot, out)
    if not fixtures.exists():
        return
    for dirpath, _dirnames, filenames in os.walk(fixtures, followlinks=False):
        rel = Path(dirpath).relative_to(fixtures)
        target = docroot / rel
        ensure_real_dir(target, docroot)
        for name in filenames:
            source = Path(dirpath) / name
            if not source.is_file() or source.is_symlink():
                continue
            write_owned(target / name, "")          # clears any planted link
            shutil.copyfile(source, target / name, follow_symlinks=False)


def pack_disk(cfg: Config, player: Player, out: Path, manifest: dict) -> Path:
    """Build the ext4 data disk the microVM boots its service from."""
    artifacts = cfg.path_of("artifacts") / player.name
    stage = artifacts / "stage"
    if stage.exists():
        shutil.rmtree(stage)
    copy_untrusted(out, stage)

    # The guest init reads this to know what to start and with which caps.
    write_owned(stage / "service.env",
        "\n".join([
            f"CTF_PLAYER={player.name}",
            f"CTF_RUN={manifest['run']}",
            f"CTF_TCP_PORT={manifest['tcp_port']}",
            f"CTF_UDP_PORT={manifest['udp_port']}",
            f"CTF_CAPS={','.join(manifest['caps'])}",
            f"CTF_ADDR={player.host}",
            f"CTF_KERNEL_ADDR={player.kernel_addr}",
            f"CTF_SUBNET={player.subnet}",
            f"CTF_LINK_ADDR={player.link_addr}",
            f"CTF_LINK_GW={player.link_gw}",
            # for the boot-time isolation self-test
            f"CTF_PEERS={' '.join(o.host for o in cfg.players if o.name != player.name)}",
            f"CTF_CONTROL_PROBE={cfg.p('net', 'control_bind', default='10.9.1.1')}",
            f"CTF_VIEWER_PROBE={cfg.p('net', 'viewer_bind', default='10.9.0.1')}",
            f"CTF_BOARD_PORT={cfg.p('net', 'leaderboard_port', default=8000)}",
            f"CTF_SUBMIT_PORT={cfg.p('net', 'submit_port', default=8001)}",
            f"CTF_MTU={cfg.p('net', 'alloc', 'mtu', default=1500)}",
            f"DOCROOT=/srv/app/docroot",
            "",
        ])
    )
    image = artifacts / "data.ext4"
    tmp = artifacts / "data.ext4.new"
    size_mib = int(cfg.p("vm", "data_disk_mib", default=512))
    if tmp.exists():
        tmp.unlink()
    res = run(["mkfs.ext4", "-q", "-F", "-L", f"ctf-{player.name}",
               "-d", str(stage), str(tmp), f"{size_mib}M"])
    if res.returncode:
        raise DeployError(f"mkfs.ext4 failed: {res.stderr.strip()[:400]}")
    os.replace(tmp, image)
    return image


def restart_vm(cfg: Config, player: Player) -> None:
    script = REPO_ROOT / "topology" / "vm.sh"
    res = run(_sudo([str(script), "restart", player.name]))
    if res.returncode:
        raise DeployError(f"vm restart failed: {(res.stderr or res.stdout).strip()[:600]}")


def healthcheck(cfg: Config, player: Player, manifest: dict) -> None:
    """SETUP §5 step 4 — the kernel-interop gate. We only require the *simplest*
    declared rung to answer here; the tick loop judges every rung properly."""
    order = [v for v in ("1.1", "1.0", "0.9", "2") if v in manifest["http_versions"]]
    udp_only = not order and "udp" in manifest["transports"]
    if not order and not udp_only:
        # Only reachable for a manifest declaring quic/http3 alone, which the
        # referee cannot probe in-process (docs/NOTE-API.md §5). Don't spin
        # for boot_timeout seconds to conclude that.
        raise DeployError(
            "no rung the healthcheck can probe: declare a tcp HTTP version or udp, "
            "or configure probe.h3_probe_cmd")
    deadline = time.monotonic() + float(cfg.p("vm", "boot_timeout", default=45))
    last = "never answered"
    while time.monotonic() < deadline:
        for version in order:
            try:
                probes.probe_http(player.host, manifest["tcp_port"], version,
                                  manifest["health_path"], cfg.probe_timeout)
                return
            except probes.ProbeFailure as exc:
                last = f"http/{version}: {exc}"
        if udp_only:
            try:
                probes.probe_udp(player.host, manifest["udp_port"], cfg.probe_timeout)
                return
            except probes.ProbeFailure as exc:
                last = f"udp: {exc}"
        time.sleep(2)
    raise DeployError(f"healthcheck never passed: {last}")


# --------------------------------------------------------------------------
def deploy(cfg: Config, store: Store, player: Player, rev: str | None = None,
           force: bool = False) -> str:
    since = time.time() - store.last_deploy_time(player.name)
    limit = cfg.redeploy_interval
    if not force and since < limit:
        raise DeployError(
            f"rate limited: {limit - since:.0f}s until {player.name} may redeploy "
            f"(RULES §8: 1 per {limit}s)")

    store.set_status(player.name, "building")
    store.event("deploy-start", player.name, rev or player.branch)
    log_text = ""
    try:
        src, rev = sync_repo(cfg, player, rev)
        try:
            manifest = load_manifest(src / "service.toml")
        except (ManifestError, OSError) as exc:
            raise DeployError(f"manifest rejected: {exc}")     # RULES §3
        if manifest["name"] != player.name:
            raise DeployError(f"manifest declares name={manifest['name']!r}, expected {player.name!r}")

        out, digest, log_text = build(cfg, player, src, manifest)
        plant_fixtures(cfg, out)
        pack_disk(cfg, player, out, manifest)
        store.set_status(player.name, "deploying")
        restart_vm(cfg, player)
        healthcheck(cfg, player, manifest)
    except DeployError as exc:
        store.record_deploy(player.name, rev or "", None, "", "failed", f"{exc}\n{log_text}", 0)
        store.event("deploy-failed", player.name, str(exc)[:300])
        raise

    grace_until = store.tick + cfg.grace_ticks          # RULES §8
    store.record_deploy(player.name, rev, manifest, digest, "ok", log_text, grace_until)
    store.event("deploy-ok", player.name, f"{rev[:12]} sha256={digest[:12]} grace→tick {grace_until}")
    log.info("%s deployed %s (artifact %s), SLA grace through tick %d",
             player.name, rev[:12], digest[:12], grace_until)
    return rev


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build and deploy a player's service")
    ap.add_argument("player")
    ap.add_argument("-c", "--config", default=None)
    ap.add_argument("--rev", default=None, help="deploy a specific revision")
    ap.add_argument("--force", action="store_true", help="ignore the redeploy rate limit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config(args.config)
    player = cfg.player(args.player)
    if player is None:
        print(f"no such player: {args.player} (have: {', '.join(cfg.names)})", file=sys.stderr)
        return 2
    store = Store(cfg.path_of("state_db"),
                  cfg.p("game", "sqlite_synchronous", default="FULL"))
    store.sync_roster(cfg.players)
    try:
        deploy(cfg, store, player, args.rev, args.force)
    except DeployError as exc:
        print(f"DEPLOY FAILED: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
