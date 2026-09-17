"""SETUP §5 step 1 — watch each player's repo and redeploy on push.

Polling, not webhooks: the control plane accepts no inbound connections from
anywhere, which is the whole point of RULES §1. `git ls-remote` is cheap and a
push takes effect within one poll interval.

The RULES §8 rate limit (1 redeploy / 90 s per service) is enforced in
deploy.py, so a player hammering pushes just coalesces into one deploy.
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time

from .config import load as load_config
from .deploy import DeployError, deploy, run
from .state import Store

log = logging.getLogger("watcher")
_stop = threading.Event()


def remote_head(player) -> str | None:
    res = run(["git", "ls-remote", "--heads", player.repo, player.branch])
    if res.returncode:
        log.warning("%s: ls-remote failed: %s", player.name, res.stderr.strip()[:200])
        return None
    line = res.stdout.strip().split("\n")[0] if res.stdout.strip() else ""
    return line.split("\t")[0] if line else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redeploy players on push")
    ap.add_argument("-c", "--config", default=None)
    ap.add_argument("--interval", type=int, default=30, help="poll seconds")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cfg = load_config(args.config)
    store = Store(cfg.path_of("state_db"),
                  cfg.p("game", "sqlite_synchronous", default="FULL"))
    store.sync_roster(cfg.players)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: _stop.set())

    log.info("watching %d repos every %ds", len(cfg.players), args.interval)
    while not _stop.is_set():
        for player in cfg.players:
            if not player.repo:
                continue
            head = remote_head(player)
            if not head:
                continue
            row = store.db.execute("SELECT rev FROM players WHERE name=?", (player.name,)).fetchone()
            current = (row["rev"] if row else None) or ""
            if head == current:
                continue
            try:
                deploy(cfg, store, player, head)
            except DeployError as exc:
                # Rate limit or a broken push: keep it pending and retry next poll.
                log.warning("%s: %s", player.name, str(exc).split("\n")[0])
        if args.once:
            break
        _stop.wait(args.interval)

    store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
