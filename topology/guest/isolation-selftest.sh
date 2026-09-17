#!/bin/sh
# Runs inside the guest at boot. Proves RULES §1 from the side that matters:
# from a *service*, everything except its own attacker's response path is
# unreachable. The negative results are the point — a passing positive test
# tells you far less than a failing negative one.
#
# Output goes to the VM console: `ctfctl console <player>`.
set -u
. /srv/app/service.env 2>/dev/null || true

CONTROL=${CTF_CONTROL_PROBE:-10.9.1.1}
VIEWER=${CTF_VIEWER_PROBE:-10.9.0.1}
BOARD=${CTF_BOARD_PORT:-8000}
SUBMIT=${CTF_SUBMIT_PORT:-8001}
PEERS=${CTF_PEERS:-}
rc=0

say() { echo "[isolation] $*" > /dev/console; }

# A TCP connect that must NOT succeed.
must_fail_tcp() {
  if timeout 3 python3 -c '
import socket, sys
s = socket.socket(); s.settimeout(2.5)
sys.exit(0 if s.connect_ex((sys.argv[1], int(sys.argv[2]))) == 0 else 1)
' "$1" "$2" 2>/dev/null; then
    say "FAIL service reached $3 ($1:$2) — the forward policy is wrong"
    rc=1
  else
    say "ok   $3 unreachable ($1:$2)"
  fi
}

must_fail_ping() {
  if ping -c1 -W1 "$1" >/dev/null 2>&1; then
    say "FAIL service reached $2 ($1)"
    rc=1
  else
    say "ok   $2 unreachable ($1)"
  fi
}

say "checking what this service can reach..."
must_fail_tcp "$VIEWER"  "$BOARD"  "leaderboard"
must_fail_tcp "$VIEWER"  "$SUBMIT" "submission API"
must_fail_tcp "$CONTROL" 22        "control plane"
must_fail_ping "$CONTROL" "control plane (icmp)"

# Peer services: a compromised service must not become a pivot into anyone
# else's guest. Attacks come from footholds, never from a service.
for peer in $PEERS; do
  must_fail_tcp "$peer" "${CTF_TCP_PORT:-8080}" "peer service $peer"
done

# The internet. Builders are offline and so is the game plane; a service that
# can reach out is an exfil path for flags it holds.
must_fail_ping "1.1.1.1" "the internet"

if [ "$rc" = 0 ]; then
  say "PASS this service is correctly boxed: it can only answer in-band"
else
  say "ISOLATION IS BROKEN — do not start the round"
fi
exit 0
