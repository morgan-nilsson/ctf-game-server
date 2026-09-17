"""SETUP §6 — the referee tick loop. Runs on the control plane only.

Each tick, for every declared protocol of every player: probe, plant a fresh
flag, re-fetch the flag planted K-1 ticks ago (the SLA check), expire anything
older than K, then render scoreboard.json.

Differences from the SETUP §6 sketch, all deliberate:
  * players are probed concurrently — with N players a serial sweep can
    overrun a 60 s tick once anyone times out;
  * FLAGDB is sqlite (orchestrator/state.py), because submit.py is a separate
    process on a different plane;
  * a redeploy's SLA grace (RULES §8) is applied here, not at deploy time;
  * the loop is scheduled on absolute tick boundaries, so probe latency never
    makes ticks drift.
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import probes
from .config import load as load_config
from .state import Store
from .validate import carries_flags, protocols

log = logging.getLogger("tick")
_stop = threading.Event()


def score_player(store: Store, cfg, player_row, tick: int) -> None:
    """Probe every declared protocol for one player and record the result."""
    name = player_row["name"]
    manifest = json.loads(player_row["manifest"]) if player_row["manifest"] else None
    if not manifest:
        log.info("%s: no deployed manifest yet, nothing to score", name)
        return

    host = player_row["host"]
    timeout = cfg.probe_timeout
    udp_fixture = bool(cfg.p("game", "udp_flag_fixture", default=False))
    points_table = cfg.uptime_points
    in_grace = tick <= int(player_row["grace_until_tick"] or 0)
    K = cfg.K

    for proto in protocols(manifest):
        port = manifest["udp_port"] if proto in ("udp", "3") else manifest["tcp_port"]
        ok, reason = True, ""

        # 1. version-correct liveness
        try:
            if proto == "udp":
                probes.probe_udp(host, port, timeout)
            elif proto == "3":
                probes.probe_h3(host, port, manifest["health_path"])
            else:
                probes.probe_http(host, port, proto, manifest["health_path"], timeout)
        except probes.ProbeFailure as exc:
            ok, reason = False, f"health: {exc}"

        # 2. plant a fresh flag, and 3. retrieve the K-old one (the SLA check)
        if ok and carries_flags(proto, udp_fixture):
            flag = store.new_flag()
            try:
                if proto == "udp":
                    ref = probes.udp_plant(host, port, flag, timeout)
                else:
                    ref = probes.plant_note(host, port, proto, flag, timeout)
                store.plant(name, proto, tick, flag, ref, K)
            except probes.ProbeFailure as exc:
                ok, reason = False, f"plant: {exc}"

            if ok:
                old = store.flag_for_sla(name, proto, tick - K + 1)
                if old is not None:
                    try:
                        old_ref = json.loads(old["ref"])
                        got = (probes.udp_fetch(host, port, old_ref, timeout) if proto == "udp"
                               else probes.fetch_note(host, port, proto, old_ref, timeout))
                        if got != old["flag"]:
                            ok, reason = False, "sla: retrieved value did not match the planted flag"
                    except probes.ProbeFailure as exc:
                        ok, reason = False, f"sla: {exc}"

        # RULES §8: a redeploy buys 2 ticks of SLA immunity, else patching
        # costs uptime and nobody patches.
        graced = bool(in_grace and not ok)
        awarded = points_table.get(proto, 0) if (ok or graced) else 0
        store.record_uptime(tick, name, proto, ok or graced, graced, awarded)

        if not ok:
            log.info("tick %d %s/%s DOWN%s: %s", tick, name, proto,
                     " (grace)" if graced else "", reason)



def apply_defense_bonus(store: Store, cfg, tick: int) -> None:
    """RULES §7 optional bonus: +N per tick per protocol whose flag was NOT
    stolen that tick.

    Applied one tick late, on purpose. Judging tick T's bonus at the end of
    tick T would award it before any attacker could possibly have submitted
    a flag planted seconds earlier — i.e. unconditionally. So when tick T
    starts we settle T-1, by which point its steals have landed.

    Recomputed from the weight table rather than incremented, so running it
    twice cannot inflate a score.
    """
    bonus = int(cfg.p("game", "defense_bonus", default=0))
    target = tick - 1
    if not bonus or target < 1:
        return
    weights = cfg.uptime_points
    for row in store.active_players():
        name = row["name"]
        stolen = store.stolen_this_tick(name, target)
        for u in store.db.execute(
            "SELECT protocol, ok, grace FROM uptime WHERE tick=? AND player=?", (target, name)
        ).fetchall():
            if not u["ok"]:
                continue
            base = weights.get(u["protocol"], 0)
            points = base if u["protocol"] in stolen else base + bonus
            store.record_uptime(target, name, u["protocol"], True, u["grace"], points)


def run_tick(store: Store, cfg, tick: int, pool: ThreadPoolExecutor | None = None) -> None:
    rows = [r for r in store.active_players() if r["status"] != "disabled"]
    if not rows:
        return
    owned = pool is None
    pool = pool or ThreadPoolExecutor(max_workers=min(16, max(1, len(rows))))
    try:
        futures = {pool.submit(score_player, store, cfg, row, tick): row["name"] for row in rows}
        for future, name in futures.items():
            try:
                # A probe budget of one tick: a player whose stack hangs costs
                # themselves the round, never everyone else's.
                future.result(timeout=max(cfg.tick_seconds, 30))
            except Exception as exc:                    # one bad player never stalls the round
                log.exception("scoring %s raised: %s", name, exc)
    finally:
        if owned:
            pool.shutdown(wait=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CTF referee tick loop")
    ap.add_argument("-c", "--config", default=None)
    ap.add_argument("--once", action="store_true", help="run a single tick and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    cfg = load_config(args.config)
    probes.H3_CMD = cfg.p("probe", "h3_probe_cmd", default="") or ""

    store = Store(cfg.path_of("state_db"),
                  cfg.p("game", "sqlite_synchronous", default="FULL"))
    store.sync_roster(cfg.players)
    scoreboard = cfg.path_of("scoreboard")

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: _stop.set())

    log.info("referee up: %d players, tick=%ds, K=%d, grace=%d ticks",
             len(cfg.players), cfg.tick_seconds, cfg.K, cfg.grace_ticks)

    # One pool for the whole run: threads (and their sqlite connections) are
    # reused tick after tick instead of being rebuilt every 60 seconds.
    pool = ThreadPoolExecutor(max_workers=min(16, max(1, len(cfg.players))),
                              thread_name_prefix="probe")
    while not _stop.is_set():
        started = time.monotonic()
        if store.frozen:
            log.info("scoring frozen; skipping tick %d", store.tick)
            store.render_board(store.tick, scoreboard)
        else:
            tick = store.tick + 1
            store.set_meta("tick", tick)
            store.set_meta("tick_started", time.time())
            apply_defense_bonus(store, cfg, tick)   # settles tick-1
            run_tick(store, cfg, tick, pool)
            removed = store.expire(tick)                # RULES §6: no hoarding
            store.render_board(tick, scoreboard)
            log.info("tick %d complete in %.1fs (%d flags expired)",
                     tick, time.monotonic() - started, removed)

        if args.once:
            break
        # Absolute-boundary scheduling: probe latency must not shift the grid.
        remaining = cfg.tick_seconds - (time.monotonic() - started)
        if remaining <= 0:
            log.warning("tick overran by %.1fs; starting the next one immediately", -remaining)
        _stop.wait(max(0.0, remaining))

    pool.shutdown(wait=False)
    store.close()
    log.info("referee stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
