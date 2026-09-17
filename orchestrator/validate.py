"""SETUP §4 — manifest schema check. A bad manifest fails deploy (RULES §3).

Usage: python3 -m orchestrator.validate players/morgan/service.toml
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

TRANSPORTS = {"tcp", "udp", "quic"}
HTTP_VERSIONS = {"0.9", "1.0", "1.1", "2", "3"}
TCP_VERSIONS = {"0.9", "1.0", "1.1", "2"}
CARRYING = {"1.0", "1.1", "2", "3"}          # RULES §3: 0.9 and raw udp carry no note app
KNOWN_CAPS = {"NET_RAW", "NET_ADMIN", "SYS_ADMIN"}


class ManifestError(ValueError):
    pass


def validate(raw: dict) -> dict:
    """Return a normalised manifest, or raise ManifestError.

    Accepts both layouts: keys at the top level, and keys nested under
    [service]. The SETUP §4 example reads as the former but parses as the
    latter (everything after a table header belongs to that table), and
    players will copy it verbatim — so take either.
    """
    service = raw.get("service") or {}
    if "name" not in service and "name" not in raw:
        raise ManifestError("missing [service].name")
    m = {**service, **{k: v for k, v in raw.items() if k != "service"}}
    m["service"] = {"name": service.get("name") or raw.get("name")}

    t = set(m.get("transports") or [])
    v = {str(x) for x in (m.get("http_versions") or [])}

    if not t:
        raise ManifestError("declare at least one transport")
    if not t <= TRANSPORTS:
        raise ManifestError(f"unknown transport: {sorted(t - TRANSPORTS)}")
    if not v <= HTTP_VERSIONS:
        raise ManifestError(f"unknown http version: {sorted(v - HTTP_VERSIONS)}")
    if "quic" in t and "udp" not in t:
        raise ManifestError("quic requires udp")
    if v & TCP_VERSIONS and "tcp" not in t:
        raise ManifestError("http <= 2 requires tcp")
    if "3" in v and "quic" not in t:
        raise ManifestError("http/3 requires quic")

    if "tcp" in t and not m.get("tcp_port"):
        raise ManifestError("tcp declared but tcp_port missing")
    if ("udp" in t or "quic" in t) and not m.get("udp_port"):
        raise ManifestError("udp/quic declared but udp_port missing")
    for key in ("tcp_port", "udp_port"):
        port = m.get(key)
        if port is not None and not (1 <= int(port) <= 65535):
            raise ManifestError(f"{key} out of range")

    for key in ("build", "run"):
        if not m.get(key):
            raise ManifestError(f"missing {key}")
        if str(m[key]).startswith("/") or ".." in str(m[key]):
            raise ManifestError(f"{key} must be a relative path inside the repo")

    caps = set(m.get("caps") or [])
    if not caps <= KNOWN_CAPS:
        raise ManifestError(f"unknown caps: {sorted(caps - KNOWN_CAPS)}")

    health = m.get("health", "GET /health")
    if not health.startswith("GET /"):
        raise ManifestError("health must be a GET request line, e.g. 'GET /health'")
    # This string is written into a request line by the prober. A newline in
    # it would let a manifest inject extra headers or a second request —
    # only ever against the player's own service, but the referee should not
    # be the one splitting requests.
    if any(c in health for c in "\r\n\0") or len(health) > 256:
        raise ManifestError("health must be a single short request line")
    if " " in health.split(None, 1)[1]:
        raise ManifestError("health path must not contain spaces")

    # docroot is planted into a fixed location in the guest; accept the
    # documented placeholder or a repo-relative path, never an absolute path
    # or a traversal, which would aim the fixture planter at the host tree.
    docroot = str(m.get("docroot", "$DOCROOT"))
    if docroot != "$DOCROOT":
        if docroot.startswith("/") or ".." in docroot or "\0" in docroot:
            raise ManifestError(
                "docroot must be \"$DOCROOT\" or a repo-relative path; "
                "fixtures are always planted at $DOCROOT in the guest")

    if len(m["service"]["name"]) > 64:
        raise ManifestError("service name is too long")

    return {
        "name": m["service"]["name"],
        "transports": sorted(t),
        "http_versions": sorted(v, key=lambda s: HTTP_ORDER.index(s)),
        "build": m["build"],
        "run": m["run"],
        "tcp_port": int(m.get("tcp_port") or 0),
        "udp_port": int(m.get("udp_port") or 0),
        "docroot": docroot,
        "caps": sorted(caps),
        "health": health,
        "health_path": health.split(None, 1)[1] if " " in health else "/health",
    }


HTTP_ORDER = ["0.9", "1.0", "1.1", "2", "3"]


def protocols(manifest: dict) -> list[str]:
    """Scored protocol rungs for a validated manifest, in ladder order."""
    out = []
    if "udp" in manifest["transports"]:
        out.append("udp")
    out += list(manifest["http_versions"])
    return out


def carries_flags(protocol: str, cfg_udp_fixture: bool = False) -> bool:
    if protocol == "udp":
        return bool(cfg_udp_fixture)
    return protocol in CARRYING


def load(path: str | Path) -> dict:
    with open(path, "rb") as fh:
        return validate(tomllib.load(fh))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        m = load(argv[1])
    except (ManifestError, tomllib.TOMLDecodeError, OSError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {m['name']} transports={m['transports']} http={m['http_versions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
