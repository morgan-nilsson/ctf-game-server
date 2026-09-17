"""The flag store and score ledger.

SETUP §6/§7 sketch FLAGDB as an in-process dict. That cannot work here: the
tick loop runs on the *control* plane and the submission API on the *viewer*
edge, as two processes (RULES §1). They share this sqlite database instead —
WAL mode, one writer at a time, durable across restarts.

Scores are never stored as running totals; they are derived from the ledger
(`uptime`, `submissions`) so a recount is always possible and a bad
submission can be reversed without drift.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);

CREATE TABLE IF NOT EXISTS players(
  name TEXT PRIMARY KEY,
  idx INTEGER,
  host TEXT,
  manifest TEXT,                 -- JSON, last validated manifest
  rev TEXT,
  deployed_at REAL,
  grace_until_tick INTEGER DEFAULT 0,
  status TEXT DEFAULT 'unknown'  -- unknown|building|deploying|running|failed|disabled
);

CREATE TABLE IF NOT EXISTS flags(
  flag TEXT PRIMARY KEY,
  player TEXT NOT NULL,          -- owner: the service it was planted into
  protocol TEXT NOT NULL,        -- udp | 0.9 | 1.0 | 1.1 | 2 | 3
  tick INTEGER NOT NULL,
  ref TEXT,                      -- JSON {id, user, token} for the SLA re-fetch
  planted_at REAL,
  expires_tick INTEGER NOT NULL,
  stolen_by TEXT,
  stolen_tick INTEGER
);
CREATE INDEX IF NOT EXISTS flags_by_owner ON flags(player, protocol, tick);

CREATE TABLE IF NOT EXISTS uptime(
  tick INTEGER, player TEXT, protocol TEXT,
  ok INTEGER, grace INTEGER DEFAULT 0, points INTEGER,
  PRIMARY KEY(tick, player, protocol)
);

CREATE TABLE IF NOT EXISTS submissions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, by TEXT, flag TEXT, owner TEXT, protocol TEXT,
  verdict TEXT,                  -- accepted | own-flag | invalid-or-expired | duplicate | bad-token
  klass TEXT,                    -- app | transport | rce
  claimed TEXT,                  -- class the attacker claimed
  points INTEGER DEFAULT 0,
  pending INTEGER DEFAULT 0,     -- claimed tier above auto tier, awaiting spot-check
  writeup TEXT, src TEXT
);

CREATE TABLE IF NOT EXISTS deploys(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, player TEXT, rev TEXT, status TEXT, sha256 TEXT, log TEXT
);

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, kind TEXT, player TEXT, detail TEXT
);
"""


class Store:
    """Thread-safe by giving every thread its own connection.

    The tick loop probes N players in parallel, so a single shared connection
    is not an option (sqlite objects are bound to their creating thread). WAL
    plus a generous busy_timeout makes concurrent readers free and serialises
    the writers, which is exactly the shape of this workload: many small
    writes, no long transactions.
    """

    def __init__(self, path: str | os.PathLike, synchronous: str = "FULL"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if synchronous.upper() not in ("OFF", "NORMAL", "FULL", "EXTRA"):
            raise ValueError(f"bad synchronous mode {synchronous!r}")
        self.synchronous = synchronous.upper()
        self._local = threading.local()
        # Every connection ever handed out, so close() can actually close
        # them all. Without this, a probe-pool thread's connection outlives
        # close() and keeps the old database file open — which matters when
        # the file is about to be replaced by a restore.
        self._conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        self.db.executescript(SCHEMA)
        self._restrict()

    def _restrict(self) -> None:
        """Flags are the one secret in the system: 0600, owner only.

        sqlite creates the database with 0644 minus umask, and the -wal/-shm
        files inherit the main file's mode. Left at the default, anything that
        can read the filesystem can lift every live flag straight out of the
        file with `strings` — no sqlite, no query, no network. Player build
        code runs on this host, so this is not hypothetical.
        """
        for suffix in ("", "-wal", "-shm"):
            target = Path(str(self.path) + suffix)
            try:
                if target.exists():
                    os.chmod(target, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        # check_same_thread=False so close() may close connections belonging
        # to other threads. Each connection is still used only by the thread
        # that created it — see the `db` property.
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        # FULL, not NORMAL. NORMAL survives a process crash (systemd restarts
        # us and nothing committed is lost) but a host power cut can drop the
        # last few commits — i.e. a steal someone already saw accepted. This
        # ledger takes a few dozen tiny writes per tick; paying an fsync for
        # each one is free at that rate and makes an accepted submission
        # durable the moment the player is told it scored.
        conn.execute(f"PRAGMA synchronous={self.synchronous}")
        # A new thread's first write can recreate -wal/-shm; re-assert the mode.
        try:
            self._restrict()
        except AttributeError:
            pass          # during __init__, before _restrict is reachable
        with self._conns_lock:
            self._conns.append(conn)
        return conn

    @property
    def db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    # --- meta -------------------------------------------------------------
    def get_meta(self, k: str, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row["v"] if row else default

    def set_meta(self, k: str, v) -> None:
        self.db.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (k, str(v)),
        )

    @property
    def tick(self) -> int:
        return int(self.get_meta("tick", 0))

    @property
    def frozen(self) -> bool:
        return self.get_meta("frozen", "0") == "1"

    def event(self, kind: str, player: str = "", detail: str = "") -> None:
        self.db.execute(
            "INSERT INTO events(ts,kind,player,detail) VALUES(?,?,?,?)",
            (time.time(), kind, player, detail),
        )

    # --- roster -----------------------------------------------------------
    def sync_roster(self, players) -> None:
        """Insert new players, mark removed ones disabled. Never deletes history."""
        names = {p.name for p in players}
        for p in players:
            self.db.execute(
                """INSERT INTO players(name, idx, host, status) VALUES(?,?,?, 'unknown')
                   ON CONFLICT(name) DO UPDATE SET idx=excluded.idx, host=excluded.host""",
                (p.name, p.index, p.host),
            )
        for row in self.db.execute("SELECT name FROM players").fetchall():
            if row["name"] not in names:
                self.db.execute("UPDATE players SET status='disabled' WHERE name=?", (row["name"],))

    def manifest(self, player: str) -> dict | None:
        row = self.db.execute("SELECT manifest FROM players WHERE name=?", (player,)).fetchone()
        return json.loads(row["manifest"]) if row and row["manifest"] else None

    def active_players(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM players WHERE status NOT IN ('disabled') ORDER BY idx"
        ).fetchall()

    def set_status(self, player: str, status: str) -> None:
        self.db.execute("UPDATE players SET status=? WHERE name=?", (status, player))

    def record_deploy(self, player, rev, manifest, sha256, status, log, grace_until) -> None:
        self.db.execute(
            "INSERT INTO deploys(ts,player,rev,status,sha256,log) VALUES(?,?,?,?,?,?)",
            (time.time(), player, rev, status, sha256, log[-8000:]),
        )
        if status == "ok":
            self.db.execute(
                """UPDATE players SET manifest=?, rev=?, deployed_at=?, grace_until_tick=?,
                          status='running' WHERE name=?""",
                (json.dumps(manifest), rev, time.time(), grace_until, player),
            )
        else:
            self.db.execute("UPDATE players SET status='failed' WHERE name=?", (player,))

    def last_deploy_time(self, player: str) -> float:
        row = self.db.execute(
            "SELECT MAX(ts) t FROM deploys WHERE player=? AND status IN ('ok','building')",
            (player,),
        ).fetchone()
        return float(row["t"] or 0.0)

    def grace_until(self, player: str) -> int:
        row = self.db.execute("SELECT grace_until_tick g FROM players WHERE name=?", (player,)).fetchone()
        return int(row["g"] or 0) if row else 0

    # --- flags ------------------------------------------------------------
    @staticmethod
    def new_flag() -> str:
        """FLAG_[A-Za-z0-9]{32} — RULES §2."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return "FLAG_" + "".join(secrets.choice(alphabet) for _ in range(32))

    def plant(self, player, protocol, tick, flag, ref, lifetime) -> None:
        self.db.execute(
            """INSERT INTO flags(flag,player,protocol,tick,ref,planted_at,expires_tick)
               VALUES(?,?,?,?,?,?,?)""",
            (flag, player, protocol, tick, json.dumps(ref), time.time(), tick + lifetime),
        )

    def flag_for_sla(self, player, protocol, tick) -> sqlite3.Row | None:
        """The K-old flag whose retrieval is this tick's SLA check (SETUP §6)."""
        return self.db.execute(
            "SELECT * FROM flags WHERE player=? AND protocol=? AND tick=?",
            (player, protocol, tick),
        ).fetchone()

    def expire(self, tick: int) -> int:
        cur = self.db.execute("DELETE FROM flags WHERE expires_tick <= ?", (tick,))
        return cur.rowcount

    def find_live_flag(self, flag: str, tick: int) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM flags WHERE flag=? AND expires_tick > ?", (flag, tick)
        ).fetchone()

    def mark_stolen(self, flag: str, by: str, tick: int) -> None:
        self.db.execute(
            "UPDATE flags SET stolen_by=?, stolen_tick=? WHERE flag=? AND stolen_by IS NULL",
            (by, tick, flag),
        )

    def stolen_this_tick(self, player: str, tick: int) -> set[str]:
        rows = self.db.execute(
            "SELECT DISTINCT protocol FROM flags WHERE player=? AND stolen_tick=?", (player, tick)
        ).fetchall()
        return {r["protocol"] for r in rows}

    # --- scoring ----------------------------------------------------------
    def record_uptime(self, tick, player, protocol, ok, grace, points) -> None:
        self.db.execute(
            """INSERT INTO uptime(tick,player,protocol,ok,grace,points) VALUES(?,?,?,?,?,?)
               ON CONFLICT(tick,player,protocol) DO UPDATE SET
                 ok=excluded.ok, grace=excluded.grace, points=excluded.points""",
            (tick, player, protocol, int(ok), int(grace), int(points)),
        )

    def totals(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for row in self.db.execute("SELECT name FROM players ORDER BY idx").fetchall():
            out[row["name"]] = {
                "total": 0, "attack": 0, "uptime": 0, "captured": 0,
                "stolen_from": 0, "pending": 0,
            }
        for row in self.db.execute(
            "SELECT player, COALESCE(SUM(points),0) s FROM uptime GROUP BY player"
        ):
            out.setdefault(row["player"], {}).setdefault("uptime", 0)
            out[row["player"]]["uptime"] = int(row["s"])
        for row in self.db.execute(
            """SELECT by, COALESCE(SUM(points),0) s, COUNT(DISTINCT flag) n,
                      COALESCE(SUM(pending),0) p
                 FROM submissions WHERE verdict='accepted' GROUP BY by"""
        ):
            acc = out.setdefault(row["by"], {})
            acc["attack"] = int(row["s"])
            acc["captured"] = int(row["n"])
            acc["pending"] = int(row["p"])
        for row in self.db.execute(
            """SELECT owner, COUNT(DISTINCT flag) n FROM submissions
                 WHERE verdict='accepted' GROUP BY owner"""
        ):
            if row["owner"]:
                out.setdefault(row["owner"], {})["stolen_from"] = int(row["n"])
        for name, acc in out.items():
            for k in ("total", "attack", "uptime", "captured", "stolen_from", "pending"):
                acc.setdefault(k, 0)
            acc["total"] = acc["attack"] + acc["uptime"]
        return out

    # --- rendered view ----------------------------------------------------
    def render_board(self, tick: int, out_path: str | os.PathLike) -> dict:
        """Write scoreboard.json atomically. Scores only — never flag tokens
        (RULES §10)."""
        totals = self.totals()
        # The grid is drawn from the most recent tick that actually has
        # results. Without this, any render during a tick in progress — a
        # steal arriving on the submission API, say — would paint an empty
        # grid until the tick loop finished writing its rows.
        row = self.db.execute(
            "SELECT MAX(tick) t FROM uptime WHERE tick <= ?", (tick,)
        ).fetchone()
        grid_tick = int(row["t"]) if row and row["t"] is not None else tick
        board = {
            "tick": tick,
            "grid_tick": grid_tick,
            "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "frozen": self.frozen,
            "players": {},
        }
        for row in self.db.execute("SELECT * FROM players ORDER BY idx").fetchall():
            name = row["name"]
            if row["status"] == "disabled":
                continue
            manifest = json.loads(row["manifest"]) if row["manifest"] else {}
            up = {}
            for u in self.db.execute(
                "SELECT protocol, ok, grace FROM uptime WHERE player=? AND tick=?",
                (name, grid_tick),
            ):
                up[u["protocol"]] = "grace" if u["grace"] else bool(u["ok"])
            acc = dict(totals.get(name, {}))
            acc.update({
                "declared": {
                    "transports": manifest.get("transports", []),
                    "http_versions": manifest.get("http_versions", []),
                },
                "up": up,
                "status": row["status"],
                "rev": (row["rev"] or "")[:12],
                "grace": tick <= int(row["grace_until_tick"] or 0),
            })
            board["players"][name] = acc

        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(out_path.suffix + ".tmp")
        tmp.write_text(json.dumps(board, indent=2))
        os.replace(tmp, out_path)          # atomic: readers never see a partial board
        return board

    # --- backup / restore -------------------------------------------------
    def backup_to(self, dest: str | os.PathLike) -> Path:
        """Consistent copy via sqlite's online backup API — safe to run while
        the tick loop is writing. Never copy state.db with cp: the -wal may
        hold commits the main file does not."""
        dest = Path(dest)
        target = sqlite3.connect(dest)
        try:
            with target:
                self.db.backup(target)
            ok = target.execute("PRAGMA integrity_check").fetchone()[0]
            if ok != "ok":
                raise RuntimeError(f"backup failed its integrity check: {ok}")
        finally:
            target.close()
        os.chmod(dest, 0o600)          # a backup holds live flags too
        return dest

    @staticmethod
    def verify(path: str | os.PathLike) -> tuple[bool, str]:
        """Check a database file before trusting it in a restore."""
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as exc:
            return False, str(exc)
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                return False, result
            for table in ("players", "flags", "uptime", "submissions", "meta"):
                conn.execute(f"SELECT COUNT(*) FROM {table}")
            tick = conn.execute("SELECT v FROM meta WHERE k='tick'").fetchone()
            subs = conn.execute(
                "SELECT COUNT(*) FROM submissions WHERE verdict='accepted'").fetchone()[0]
            return True, f"tick {tick[0] if tick else 0}, {subs} accepted steals"
        except sqlite3.Error as exc:
            return False, f"schema mismatch: {exc}"
        finally:
            conn.close()

    def close(self) -> None:
        """Close every connection this store opened, in any thread."""
        with self._conns_lock:
            conns, self._conns = self._conns, []
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        self._local.conn = None
