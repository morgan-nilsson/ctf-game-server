"""Per-protocol probes and the flag contract (RULES §6, SETUP §6).

Every probe answers one question: is this declared protocol *up* this tick?
For a flag-carrying protocol that means all of:

  1. the version-correct health request succeeds (httpclient does the judging),
  2. a fresh flag plants (register a throwaway user, PUT /note),
  3. the flag planted K-1 ticks ago still retrieves with that user's own
     credentials — the SLA check.

The wire contract players implement is docs/NOTE-API.md. It is deliberately
line-oriented: a hand-rolled stack should not have to parse JSON to play.
"""
from __future__ import annotations

import json
import secrets
import shlex
import subprocess

from .httpclient import ProtocolError, client_for, udp_echo


class ProbeFailure(Exception):
    """Any reason this protocol is down this tick. Carries a short reason."""


def _text(resp) -> str:
    return resp.body.decode("utf-8", "replace").strip()


def _creds() -> tuple[str, str]:
    return "ref_" + secrets.token_hex(6), secrets.token_urlsafe(18)


# --------------------------------------------------------------------------
# HTTP rungs
# --------------------------------------------------------------------------
def probe_http(host: str, port: int, version: str, path: str, timeout: float) -> None:
    """Version-correct liveness. Raises ProbeFailure if not up."""
    client = client_for(version, host, port, timeout)
    try:
        resp = client.request("GET", path)
        if not resp.ok:
            raise ProbeFailure(f"health returned {resp.status}")
        if version == "0.9" and not resp.body.strip():
            raise ProbeFailure("empty HTTP/0.9 body")
        if version == "1.1":
            # RULES §6 strictness: HTTP/1.1 is persistent by default. A server
            # that hangs up after one response is not speaking 1.1.
            if resp.closed:
                raise ProbeFailure("HTTP/1.1 connection did not persist")
            second = client.request("GET", path)
            if not second.ok:
                raise ProbeFailure(f"second request on persistent connection returned {second.status}")
    except (ProtocolError, OSError) as exc:
        raise ProbeFailure(str(exc)) from exc
    finally:
        client.close()


def plant_note(host: str, port: int, version: str, flag: str, timeout: float) -> dict:
    """Register a throwaway user and PUT the flag as a note they own.
    Returns the ref used for the later SLA fetch."""
    if version == "3":
        return _h3("plant", host, port, version, flag=flag)
    client = client_for(version, host, port, timeout)
    user, password = _creds()
    try:
        resp = client.request("POST", "/register", body=f"{user}\n{password}\n".encode())
        if not resp.ok:
            raise ProbeFailure(f"/register returned {resp.status}")
        token = _text(resp)
        if not token or len(token) > 512 or "\n" in token:
            raise ProbeFailure("/register did not return a single-line token")

        resp = client.request(
            "PUT", "/note",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
            body=flag.encode(),
        )
        if not resp.ok:
            raise ProbeFailure(f"PUT /note returned {resp.status}")
        note_id = _text(resp)
        if not note_id or len(note_id) > 256 or "/" in note_id or "\n" in note_id:
            raise ProbeFailure("PUT /note did not return a usable note id")
        return {"user": user, "token": token, "id": note_id}
    except (ProtocolError, OSError) as exc:
        raise ProbeFailure(str(exc)) from exc
    finally:
        client.close()


def fetch_note(host: str, port: int, version: str, ref: dict, timeout: float) -> str:
    """Retrieve a previously planted flag with its owner's own credentials."""
    if version == "3":
        return _h3("fetch", host, port, version, ref=ref).get("body", "")
    client = client_for(version, host, port, timeout)
    try:
        resp = client.request(
            "GET", f"/note/{ref['id']}",
            headers={"Authorization": f"Bearer {ref['token']}"},
        )
        if not resp.ok:
            raise ProbeFailure(f"GET /note/{{id}} returned {resp.status}")
        return _text(resp)
    except (ProtocolError, OSError) as exc:
        raise ProbeFailure(str(exc)) from exc
    finally:
        client.close()


# --------------------------------------------------------------------------
# UDP rung (RULES §3: liveness/conformance, no note app)
# --------------------------------------------------------------------------
def probe_udp(host: str, port: int, timeout: float) -> None:
    nonce = secrets.token_hex(8)
    payload = f"ECHO {nonce}".encode()
    try:
        reply = udp_echo(host, port, payload, timeout)
    except OSError as exc:
        raise ProbeFailure(f"udp: {exc}") from exc
    if reply != payload:
        raise ProbeFailure(f"udp echo mismatch: {reply[:48]!r}")


def udp_plant(host: str, port: int, flag: str, timeout: float) -> dict:
    """Optional transport-level flag surface (config game.udp_flag_fixture)."""
    key = secrets.token_hex(8)
    try:
        reply = udp_echo(host, port, f"SET {key} {flag}".encode(), timeout)
    except OSError as exc:
        raise ProbeFailure(f"udp set: {exc}") from exc
    if reply.strip() != b"OK":
        raise ProbeFailure(f"udp SET refused: {reply[:48]!r}")
    return {"id": key, "token": "", "user": ""}


def udp_fetch(host: str, port: int, ref: dict, timeout: float) -> str:
    try:
        reply = udp_echo(host, port, f"GET {ref['id']}".encode(), timeout)
    except OSError as exc:
        raise ProbeFailure(f"udp get: {exc}") from exc
    return reply.decode("utf-8", "replace").strip()


# --------------------------------------------------------------------------
# HTTP/3 — external prober hook
# --------------------------------------------------------------------------
H3_CMD = ""          # set from config by tick.py
H3_TIMEOUT = 20.0


def _h3(op: str, host: str, port: int, version: str, **kw) -> dict:
    """Delegate to probe.h3_probe_cmd.

    The referee ships no QUIC client: writing QUIC + TLS 1.3 is the players'
    apex rung (RULES §4), not the host's job, and a half-correct one would
    score HTTP/3 wrongly. With no command configured, HTTP/3 simply never
    comes up — which is honest, and visible on the leaderboard grid.

    Contract: the command reads one JSON object on stdin and writes one JSON
    object on stdout. See docs/NOTE-API.md §5.
    """
    if not H3_CMD:
        raise ProbeFailure("no h3_probe_cmd configured; HTTP/3 is not scored")
    request = {"op": op, "host": host, "port": port, "version": version, **kw}
    try:
        proc = subprocess.run(
            shlex.split(H3_CMD),
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=H3_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise ProbeFailure("h3 prober timed out") from exc
    except OSError as exc:
        raise ProbeFailure(f"h3 prober failed to start: {exc}") from exc
    if proc.returncode != 0:
        raise ProbeFailure(f"h3 prober exit {proc.returncode}: {proc.stderr[:200].decode('utf-8','replace')}")
    try:
        out = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError as exc:
        raise ProbeFailure(f"h3 prober emitted non-JSON: {exc}") from exc
    if not out.get("ok"):
        raise ProbeFailure(f"h3 {op}: {out.get('error', 'refused')}")
    return out


def probe_h3(host: str, port: int, path: str) -> None:
    _h3("health", host, port, "3", path=path)
