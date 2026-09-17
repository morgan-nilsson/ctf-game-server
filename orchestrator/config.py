"""Configuration loading and per-player address derivation.

One config file describes the host; each player's *capabilities* come from
their own service.toml (SETUP §4), never from here.
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = os.environ.get("CTF_CONFIG", "/etc/ctf/ctf.toml")


@dataclass
class Player:
    index: int                 # 1-based; drives every derived address
    name: str
    repo: str
    branch: str
    submit_token: str
    subnet: str                # service subnet, e.g. 10.0.3.0/24
    host: str                  # address the player's stack answers on (.2)
    kernel_addr: str           # tun0 kernel side (.1)
    link_gw: str               # host/router side of the VM link subnet
    link_addr: str             # guest eth0 address, CIDR form
    foot_gw: str               # router side of the foothold link
    foot_addr: str             # foothold netns address, CIDR form

    @property
    def tap(self) -> str:
        return f"tap-{self.name}"[:15]

    @property
    def netns(self) -> str:
        return f"ctf-foot-{self.name}"[:63]

    @property
    def veth_host(self) -> str:
        return f"vf{self.index}h"

    @property
    def veth_ns(self) -> str:
        return f"vf{self.index}p"

    @property
    def vm_veth(self) -> str:
        return f"vs{self.index}h"

    @property
    def link_net(self) -> str:
        return self.link_addr.split("/")[0].rsplit(".", 1)[0] + ".0/30"

    @property
    def foot_net(self) -> str:
        return self.foot_addr.split("/")[0].rsplit(".", 1)[0] + ".0/30"

    @property
    def bridge(self) -> str:
        """Per-guest L2 segment, for hypervisors that attach to a bridge
        (libvirt) rather than opening a tap directly."""
        return f"br-svc{self.index}"


@dataclass
class Config:
    path: Path
    raw: dict
    players: list[Player] = field(default_factory=list)

    # --- convenience accessors -------------------------------------------
    def p(self, *keys, default=None):
        node = self.raw
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def path_of(self, key: str) -> Path:
        return Path(self.raw["paths"][key])

    @property
    def tick_seconds(self) -> int:
        return int(self.p("game", "tick_seconds", default=60))

    @property
    def K(self) -> int:
        return int(self.p("game", "flag_lifetime_ticks", default=5))

    @property
    def grace_ticks(self) -> int:
        return int(self.p("game", "sla_grace_ticks", default=2))

    @property
    def redeploy_interval(self) -> int:
        return int(self.p("game", "redeploy_min_interval", default=90))

    @property
    def uptime_points(self) -> dict:
        return {str(k): int(v) for k, v in self.p("scoring", "uptime", default={}).items()}

    @property
    def attack_points(self) -> dict:
        return {str(k): int(v) for k, v in self.p("scoring", "attack", default={}).items()}

    @property
    def probe_timeout(self) -> float:
        return float(self.p("probe", "timeout", default=4.0))

    def player(self, name: str) -> Player | None:
        for pl in self.players:
            if pl.name == name:
                return pl
        return None

    @property
    def names(self) -> list[str]:
        return [p.name for p in self.players]


def _derive(idx: int, raw: dict, entry: dict) -> Player:
    alloc = raw.get("net", {}).get("alloc", {})
    svc = int(alloc.get("svc_octet", 0))
    link = int(alloc.get("link_octet", 10))
    foot = int(alloc.get("foot_octet", 20))

    subnet = entry.get("subnet", f"10.{svc}.{idx}.0/24")
    base = subnet.split("/")[0].rsplit(".", 1)[0]          # 10.0.3
    link_net = entry.get("link_net", f"10.{link}.{idx}.0/30")
    lbase = link_net.split("/")[0].rsplit(".", 1)[0]
    foot_net = entry.get("foot_net", f"10.{foot}.{idx}.0/30")
    fbase = foot_net.split("/")[0].rsplit(".", 1)[0]

    return Player(
        index=idx,
        name=entry["name"],
        repo=entry.get("repo", ""),
        branch=entry.get("branch", "main"),
        submit_token=entry.get("submit_token", ""),
        subnet=subnet,
        host=entry.get("host", f"{base}.2"),
        kernel_addr=entry.get("kernel_addr", f"{base}.1"),
        link_gw=entry.get("link_gw", f"{lbase}.1"),
        link_addr=entry.get("link", f"{lbase}.2/30"),
        foot_gw=entry.get("foot_gw", f"{fbase}.1"),
        foot_addr=entry.get("foot", f"{fbase}.2/30"),
    )


def load(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or DEFAULT_CONFIG)
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)

    entries = raw.get("players", [])
    if not entries:
        raise SystemExit(f"{path}: no [[players]] blocks")
    limit = int(raw.get("game", {}).get("max_players", 64))
    if len(entries) > limit:
        raise SystemExit(f"{path}: {len(entries)} players exceeds max_players={limit}")

    seen: set[str] = set()
    players: list[Player] = []
    for i, entry in enumerate(entries, start=1):
        name = entry.get("name")
        if not name or not name.replace("-", "").replace("_", "").isalnum():
            raise SystemExit(f"{path}: player #{i} has a missing or unsafe name")
        if name in seen:
            raise SystemExit(f"{path}: duplicate player name {name!r}")
        seen.add(name)
        players.append(_derive(i, raw, entry))

    cfg = Config(path=path, raw=raw, players=players)
    # Loopback addresses are exempt: that only ever happens in the referee's
    # own test harness, where services are distinguished by port.
    hosts = [p.host for p in players if not p.host.startswith("127.")]
    if len(set(hosts)) != len(hosts):
        raise SystemExit(f"{path}: two players resolve to the same service address")
    return cfg
