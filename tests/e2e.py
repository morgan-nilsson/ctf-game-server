"""End-to-end referee test: no VMs, no root, no network planes.

Runs the *real* tick loop and the *real* submission API against a known-good
fake service on loopback, and asserts the RULES behaviours that matter:

  * every declared protocol scores its RULES §7 weight when it is up
  * an undeclared protocol is never probed and never scores
  * a flag planted this tick is retrievable K-1 ticks later (the SLA)
  * self-submission is refused; a cross-steal scores; a replay is a duplicate
  * an expired flag is worthless
  * a broken version is marked down while the others stay up

  python3 tests/e2e.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    mark = "\033[32mok  \033[0m" if condition else "\033[31mFAIL\033[0m"
    print(f"  {mark} {label}" + (f"  — {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


CONFIG = """
[paths]
root = "{d}"
players = "{d}/players"
artifacts = "{d}/artifacts"
repos = "{d}/repos"
state_db = "{d}/state.db"
scoreboard = "{d}/scoreboard.json"
fixtures = "{d}/fixtures"
run = "{d}/run"
logs = "{d}/logs"

[game]
tick_seconds = 1
flag_lifetime_ticks = 3
sla_grace_ticks = 2
redeploy_min_interval = 90
udp_flag_fixture = true

[scoring.uptime]
udp = 2
"0.9" = 1
"1.0" = 1
"1.1" = 3
"2" = 6
"3" = 10

[scoring.attack]
app = 50
transport = 75
rce = 100

[net]
viewer_bind = "127.0.0.1"
control_bind = "127.0.0.1"
submit_port = {submit_port}
leaderboard_port = {board_port}

[probe]
timeout = 3.0

[vm]
hypervisor = "none"

[[players]]
name = "alpha"
host = "127.0.0.1"
repo = ""
submit_token = "tok-alpha"

[[players]]
name = "beta"
host = "127.0.0.1"
repo = ""
submit_token = "tok-beta"
"""

MANIFEST_FULL = {
    "name": "alpha", "transports": ["tcp", "udp"],
    "http_versions": ["0.9", "1.0", "1.1", "2"],
    "build": "./build.sh", "run": "./run.sh",
    "tcp_port": 0, "udp_port": 0, "docroot": "$DOCROOT", "caps": [],
    "health": "GET /health", "health_path": "/health",
}
MANIFEST_TCPONLY = dict(MANIFEST_FULL, name="beta", transports=["tcp"],
                        http_versions=["1.0", "1.1"])


def free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ctf-e2e-"))
    alpha_tcp, alpha_udp = free_port(), free_port()
    beta_tcp = free_port()
    submit_port, board_port = free_port(), free_port()

    cfg_path = tmp / "ctf.toml"
    cfg_path.write_text(CONFIG.format(d=tmp, submit_port=submit_port, board_port=board_port))
    os.environ["CTF_CONFIG"] = str(cfg_path)

    from orchestrator.config import load as load_config
    from orchestrator.state import Store
    from orchestrator import tick as tickmod

    services = [
        subprocess.Popen([sys.executable, str(ROOT / "tests/fake_service.py"),
                          "--tcp", str(alpha_tcp), "--udp", str(alpha_udp)],
                         stdout=subprocess.DEVNULL),
        subprocess.Popen([sys.executable, str(ROOT / "tests/fake_service.py"),
                          "--tcp", str(beta_tcp), "--udp", str(free_port()),
                          "--break", "1.0"],
                         stdout=subprocess.DEVNULL),
    ]
    submit_proc = None
    try:
        time.sleep(1.2)
        cfg = load_config(cfg_path)
        store = Store(cfg.path_of("state_db"))
        store.sync_roster(cfg.players)

        alpha = dict(MANIFEST_FULL, tcp_port=alpha_tcp, udp_port=alpha_udp)
        beta = dict(MANIFEST_TCPONLY, tcp_port=beta_tcp, udp_port=0)
        for name, manifest in (("alpha", alpha), ("beta", beta)):
            store.db.execute("UPDATE players SET manifest=?, status='running' WHERE name=?",
                             (json.dumps(manifest), name))

        print("\n== tick 1: probe every declared protocol ==")
        store.set_meta("tick", 1)
        tickmod.run_tick(store, cfg, 1)
        rows = {r["protocol"]: r for r in store.db.execute(
            "SELECT * FROM uptime WHERE player='alpha' AND tick=1")}
        for proto, points in (("udp", 2), ("0.9", 1), ("1.0", 1), ("1.1", 3), ("2", 6)):
            r = rows.get(proto)
            check(f"alpha {proto} up, {points} pts",
                  r is not None and r["ok"] == 1 and r["points"] == points,
                  f"got {dict(r) if r else None}")
        check("alpha is not probed on HTTP/3 (undeclared)", "3" not in rows)

        beta_rows = {r["protocol"]: r for r in store.db.execute(
            "SELECT * FROM uptime WHERE player='beta' AND tick=1")}
        check("beta 1.0 down (it answers HTTP/9.9)", beta_rows["1.0"]["ok"] == 0)
        check("beta 1.1 still up", beta_rows["1.1"]["ok"] == 1)
        check("beta has no udp rung (undeclared)", "udp" not in beta_rows)

        planted = store.db.execute(
            "SELECT protocol FROM flags WHERE player='alpha' AND tick=1").fetchall()
        got = {r["protocol"] for r in planted}
        check("flags planted on carrying protocols only",
              got == {"udp", "1.0", "1.1", "2"}, f"got {sorted(got)}")

        print("\n== ticks 2-3: SLA re-fetch of the K-old flag ==")
        for t in (2, 3):
            store.set_meta("tick", t)
            tickmod.run_tick(store, cfg, t)
        sla = store.db.execute(
            "SELECT * FROM uptime WHERE player='alpha' AND tick=3 AND protocol='1.1'").fetchone()
        check("alpha 1.1 still up after an SLA round-trip", sla["ok"] == 1)

        print("\n== submission API ==")
        env = dict(os.environ, CTF_CONFIG=str(cfg_path), PYTHONPATH=str(ROOT))
        submit_proc = subprocess.Popen(
            [sys.executable, "-m", "orchestrator.submit"],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.2)

        def post(payload: dict) -> dict:
            req = urllib.request.Request(
                f"http://127.0.0.1:{submit_port}/submit",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return json.loads(exc.read())

        flag_row = store.db.execute(
            "SELECT * FROM flags WHERE player='alpha' AND protocol='1.1' ORDER BY tick DESC"
        ).fetchone()
        flag = flag_row["flag"]

        check("bad token refused",
              post({"by": "beta", "token": "wrong", "flag": flag})["verdict"] == "bad-token")
        check("self-submission refused (RULES §6)",
              post({"by": "alpha", "token": "tok-alpha", "flag": flag})["verdict"] == "own-flag")
        res = post({"by": "beta", "token": "tok-beta", "flag": flag})
        check("cross-steal scores app tier (+50)", res.get("verdict") == "+50", str(res))
        check("replay is a duplicate",
              post({"by": "beta", "token": "tok-beta", "flag": flag})["verdict"] == "duplicate")
        check("garbage flag rejected",
              post({"by": "beta", "token": "tok-beta", "flag": "FLAG_" + "x" * 32})["verdict"]
              == "invalid-or-expired")

        udp_flag = store.db.execute(
            "SELECT * FROM flags WHERE player='alpha' AND protocol='udp' ORDER BY tick DESC"
        ).fetchone()
        res = post({"by": "beta", "token": "tok-beta", "flag": udp_flag["flag"]})
        check("udp-rung steal scores the transport tier (+75)", res.get("verdict") == "+75", str(res))

        res = post({"by": "beta", "token": "tok-beta", "flag": flag, "class": "rce"})
        check("claiming a higher class without a write-up is refused",
              res.get("verdict") in ("writeup-required", "duplicate"), str(res))

        print("\n== expiry (K ticks) ==")
        old = store.db.execute("SELECT * FROM flags WHERE tick=1 LIMIT 1").fetchone()
        old_flag = old["flag"] if old else None
        store.set_meta("tick", 9)
        removed = store.expire(9)
        check("old flags expire", removed > 0, f"removed {removed}")
        if old_flag:
            check("an expired flag is worthless (RULES §6: no hoarding)",
                  post({"by": "beta", "token": "tok-beta", "flag": old_flag})["verdict"]
                  == "invalid-or-expired")

        print("\n== SLA grace after a redeploy (RULES §8) ==")
        # Point beta at a dead port and give it grace: the rung must stay
        # "up" for scoring but be visibly marked as grace, not as healthy.
        dead = dict(MANIFEST_TCPONLY, tcp_port=free_port(), udp_port=0)
        store.db.execute("UPDATE players SET manifest=?, grace_until_tick=? WHERE name='beta'",
                         (json.dumps(dead), 21))
        store.set_meta("tick", 20)
        tickmod.run_tick(store, cfg, 20)
        g = {r["protocol"]: r for r in store.db.execute(
            "SELECT * FROM uptime WHERE player='beta' AND tick=20")}
        check("a graced rung still scores its points",
              g["1.1"]["ok"] == 1 and g["1.1"]["points"] == 3, str(dict(g["1.1"])))
        check("a graced rung is flagged as grace, not as healthy",
              g["1.1"]["grace"] == 1)
        store.set_meta("tick", 22)
        tickmod.run_tick(store, cfg, 22)
        g2 = store.db.execute(
            "SELECT * FROM uptime WHERE player='beta' AND tick=22 AND protocol='1.1'").fetchone()
        check("once grace expires the rung goes down",
              g2["ok"] == 0 and g2["points"] == 0, str(dict(g2)))
        store.db.execute("UPDATE players SET manifest=?, grace_until_tick=0 WHERE name='beta'",
                         (json.dumps(beta),))

        print("\n== defense bonus is settled one tick late, and is idempotent ==")
        cfg.raw["game"]["defense_bonus"] = 2
        store.db.execute("DELETE FROM uptime WHERE tick IN (30, 31)")
        store.record_uptime(30, "alpha", "1.1", True, 0, 3)
        store.record_uptime(30, "alpha", "2", True, 0, 6)
        # a flag of alpha's, planted at tick 30 on 1.1, gets stolen during 30
        stolen_flag = store.new_flag()
        store.plant("alpha", "1.1", 30, stolen_flag, {"id": "x"}, 5)
        store.mark_stolen(stolen_flag, "beta", 30)
        tickmod.apply_defense_bonus(store, cfg, 31)          # settling tick 30
        after = {r["protocol"]: r["points"] for r in store.db.execute(
            "SELECT protocol, points FROM uptime WHERE player='alpha' AND tick=30")}
        check("no bonus on a protocol whose flag was stolen", after["1.1"] == 3, str(after))
        check("bonus on a protocol that held", after["2"] == 6 + 2, str(after))
        tickmod.apply_defense_bonus(store, cfg, 31)
        tickmod.apply_defense_bonus(store, cfg, 31)
        again = {r["protocol"]: r["points"] for r in store.db.execute(
            "SELECT protocol, points FROM uptime WHERE player='alpha' AND tick=30")}
        check("re-running the bonus cannot inflate a score", again == after, str(again))
        cfg.raw["game"]["defense_bonus"] = 0
        store.db.execute("DELETE FROM uptime WHERE tick IN (30, 31)")
        store.db.execute("DELETE FROM flags WHERE flag=?", (stolen_flag,))
        store.db.execute("DELETE FROM submissions WHERE flag=?", (stolen_flag,))

        print("\n== the grid never blanks out mid-tick ==")
        store.set_meta("tick", 40)                  # a tick with no rows yet
        mid = store.render_board(40, cfg.path_of("scoreboard"))
        check("a render during a tick in progress keeps the last grid",
              bool(mid["players"]["alpha"]["up"]),
              f"grid_tick={mid.get('grid_tick')} up={mid['players']['alpha']['up']}")
        check("the board still reports the current tick", mid["tick"] == 40)

        print("\n== the prober against hostile services (THREAT-MODEL §1) ==")
        # Each of these is a legal-looking response from a player's own stack.
        # None may exhaust the referee's memory or hold a probe thread open.
        import resource
        for mode, bound in (("clen", 3.0), ("chunked", 3.0), ("headers", 3.0),
                            ("manychunks", 3.0), ("drip", 20.0)):
            hp = subprocess.Popen([sys.executable, str(ROOT / "tests/hostile_service.py"), mode],
                                  stdout=subprocess.PIPE, text=True)
            hport = int(hp.stdout.readline())
            before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            t0 = time.time()
            try:
                from orchestrator.probes import ProbeFailure, probe_http
                try:
                    probe_http("127.0.0.1", hport, "1.1", "/health", 4.0)
                    verdict, contained = "probe PASSED", False
                except ProbeFailure as exc:
                    verdict, contained = str(exc)[:40], True
                except Exception as exc:
                    verdict, contained = f"uncaught {type(exc).__name__}", False
            finally:
                hp.kill()
            elapsed = time.time() - t0
            grew = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) // 1024 // 1024
            check(f"hostile/{mode} contained in {elapsed:.1f}s (+{grew}MiB)",
                  contained and elapsed < bound and grew < 128, verdict)

        print("\n== manifest validation (RULES §3) ==")
        from orchestrator.validate import ManifestError, validate as vmanifest
        base = {"service": {"name": "x"}, "build": "./b.sh", "run": "./r.sh", "tcp_port": 8080}
        cases = [
            ("quic without udp", {"transports": ["tcp", "quic"], "http_versions": ["1.1"]}),
            ("http/2 without tcp", {"transports": ["udp"], "http_versions": ["2"], "udp_port": 1}),
            ("http/3 without quic", {"transports": ["tcp"], "http_versions": ["3"]}),
            ("unknown transport", {"transports": ["sctp"], "http_versions": []}),
            ("absolute run path", {"transports": ["tcp"], "http_versions": ["1.1"], "run": "/bin/sh"}),
            ("path escape in build", {"transports": ["tcp"], "http_versions": ["1.1"], "build": "../x"}),
        ]
        for label, patch in cases:
            m = {**base, **patch}
            try:
                vmanifest(m)
                check(f"rejects {label}", False, "accepted it")
            except ManifestError:
                check(f"rejects {label}", True)

        print("\n== crash safety and disaster recovery ==")
        import shutil as _sh
        store.set_meta("tick", 3)
        before = {n: p["total"] for n, p in
                  store.render_board(3, cfg.path_of("scoreboard"))["players"].items()}
        bdir = tmp / "backup"; bdir.mkdir(exist_ok=True)
        store.backup_to(bdir / "state.db")
        ok, detail = store.verify(bdir / "state.db")
        check("backup verifies", ok, detail)
        check("backup is not world-readable",
              not (os.stat(bdir / "state.db").st_mode & 0o077))

        bad = tmp / "bad.db"; bad.write_bytes(os.urandom(512))
        bad_ok, _ = store.verify(bad)
        check("a corrupt database fails verification", not bad_ok)

        # Replace the live db with the backup, as `ctfctl restore` does.
        db_path = cfg.path_of("state_db")
        store.close()
        for suffix in ("-wal", "-shm"):
            (db_path.parent / (db_path.name + suffix)).unlink(missing_ok=True)
        _sh.copy2(bdir / "state.db", db_path)
        store = Store(db_path)
        after = {n: p["total"] for n, p in
                 store.render_board(3, cfg.path_of("scoreboard"))["players"].items()}
        check("scores survive a restore intact", before == after, f"{before} != {after}")
        check("the ledger still recounts from source",
              store.totals()["beta"]["attack"] == before["beta"] - store.totals()["beta"]["uptime"])

        print("\n== scoreboard ==")
        store.set_meta("tick", 3)
        board = store.render_board(3, cfg.path_of("scoreboard"))
        beta_acc = board["players"]["beta"]
        check("attack points land on the thief", beta_acc["attack"] == 125, str(beta_acc["attack"]))
        check("losses land on the owner", board["players"]["alpha"]["stolen_from"] == 2)
        check("total = attack + uptime",
              beta_acc["total"] == beta_acc["attack"] + beta_acc["uptime"])
        dumped = json.dumps(board)
        check("the rendered board contains no flag token (RULES §10)", "FLAG_" not in dumped)
        store.close()
    finally:
        for proc in services + ([submit_proc] if submit_proc else []):
            proc.terminate()

    print()
    if FAILURES:
        print(f"\033[31m{len(FAILURES)} failed:\033[0m " + ", ".join(FAILURES))
        return 1
    print("\033[32mall checks passed\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
