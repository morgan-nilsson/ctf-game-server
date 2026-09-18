#!/usr/bin/env bash
# SETUP §1 — the three network planes, for N players.
#
#   control : the host itself (orchestrator, builder, flag store, tick loop)
#   game    : one L2 segment PER GUEST, routed; plus one foothold per player
#   viewer  : humans — leaderboard and submission API
#
# The layout trick that makes the policy tractable: every guest sits alone on
# its own segment, so guest-to-guest traffic is *routed*, not bridged. That
# means nftables' forward hook filters it natively — no br_netfilter, no
# ebtables — and no guest can sniff a peer's link. RULES §5's blind-vantage
# rule stops being a rule you enforce and becomes a property of the wiring.
#
# Two modes, same property (net.plane_mode):
#   netns : taps live in the `ctf-gw` router namespace; vm.sh starts the
#           hypervisor inside it. Self-contained, leaves the host's own
#           networking completely untouched.
#   host  : one bridge per guest in the root namespace, host is the sole
#           router. Use this when libvirt owns the guests — point each domain
#           at <source bridge='br-svc<N>'/>.
#
# usage: networks.sh {up|down|status|verify}
set -euo pipefail

PY=${PY:-python3}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GW=ctf-gw
CTRL_IF=ctf-ctrl
VIEW_IF=ctf-view
VM_USER=${CTF_VM_USER:-ctf-vm}

cd "$ROOT"
eval "$("$PY" -m orchestrator.topology env)"
MODE=${CTF_PLANE_MODE:-netns}

require_root() { [ "$(id -u)" = 0 ] || { echo "networks.sh: must run as root" >&2; exit 1; }; }
have() { command -v "$1" >/dev/null 2>&1; }

load_players() {
  PLAYER_ROWS=()
  while read -r row; do [ -n "$row" ] && PLAYER_ROWS+=("$row"); done \
    < <("$PY" -m orchestrator.topology players)
}

# Run a command on the game plane: inside the router namespace, or right here
# if the host itself is the router.
if [ "$MODE" = host ]; then
  ns() { "$@"; }
else
  ns() { ip netns exec "$GW" "$@"; }
fi

offload_off() {   # RULES §5 parity: unfilled L4 checksums break interop
  have ethtool || return 0
  ns ethtool -K "$1" tx off rx off tso off gso off gro off 2>/dev/null || true
}

norp() {          # the kernel takes MAX(conf.all, conf.<dev>) — zero both
  ns sysctl -qw "net.ipv4.conf.$1.rp_filter=0" 2>/dev/null || true
}

# --------------------------------------------------------------------------
up() {
  require_root
  load_players

  # --- control plane (host side) ---------------------------------------
  ip link show "$CTRL_IF" >/dev/null 2>&1 || ip link add "$CTRL_IF" type bridge
  ip addr replace "${CTF_CONTROL_BIND}/${CTF_CONTROL_CIDR#*/}" dev "$CTRL_IF"
  ip link set "$CTRL_IF" mtu "$CTF_MTU" up

  # --- viewer plane (host side) ----------------------------------------
  # Humans arrive over your VPN/LAN: set CTF_VIEWER_IFACE=wg0 (or eth1) to
  # enslave that interface; otherwise this is a local-only bridge.
  ip link show "$VIEW_IF" >/dev/null 2>&1 || ip link add "$VIEW_IF" type bridge
  ip addr replace "${CTF_VIEWER_BIND}/${CTF_VIEWER_CIDR#*/}" dev "$VIEW_IF"
  ip link set "$VIEW_IF" mtu "$CTF_MTU" up
  if [ -n "${CTF_VIEWER_IFACE:-}" ]; then
    # Enslaving a NIC into a bridge makes that NIC's own IP unusable. Do it to
    # the interface carrying your default route and you lose SSH to this box
    # on the spot, with no way back except a physical/serial console. Refuse,
    # unless the operator insists and has console access.
    default_if=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    has_addr=$(ip -4 addr show dev "$CTF_VIEWER_IFACE" scope global 2>/dev/null | grep -c 'inet ' || true)
    if [ "$CTF_VIEWER_IFACE" = "$default_if" ] && [ "${CTF_VIEWER_IFACE_FORCE:-0}" != 1 ]; then
      echo "networks.sh: REFUSING to enslave $CTF_VIEWER_IFACE — it carries this host's" >&2
      echo "             default route. Bridging it would drop your SSH session." >&2
      echo "             Either use a spare NIC/VPN interface, or just set" >&2
      echo "             net.viewer_bind to this host's LAN IP (no bridging needed)." >&2
      echo "             Override only from a console: CTF_VIEWER_IFACE_FORCE=1" >&2
      exit 1
    fi
    if [ "$has_addr" -gt 0 ] && [ "${CTF_VIEWER_IFACE_FORCE:-0}" != 1 ]; then
      echo "networks.sh: WARNING $CTF_VIEWER_IFACE has a global IPv4 address;" >&2
      echo "             bridging it will make that address unusable." >&2
    fi
    ip link set "$CTF_VIEWER_IFACE" master "$VIEW_IF" up
  fi

  # --- the router ------------------------------------------------------
  if [ "$MODE" = netns ]; then
    ip netns list | grep -qx "$GW" || ip netns add "$GW"
    ns ip link set lo up
    if ! ip link show gwc0 >/dev/null 2>&1; then
      ip link add gwc0 type veth peer name gwc1
      ip link set gwc0 master "$CTRL_IF" up
      ip link set gwc1 netns "$GW"
    fi
    ip link set gwc0 mtu "$CTF_MTU" up
    ns ip addr replace "${CTF_GW_CONTROL_ADDR}/${CTF_CONTROL_CIDR#*/}" dev gwc1
    ns ip link set gwc1 mtu "$CTF_MTU" up
    norp gwc1
    # Footholds submit flags and read the board, so the router needs a route
    # to the viewer edge — gwc1 only covers the control CIDR. Without this,
    # foothold -> submission API fails as "network unreachable" before the
    # policy ever gets a say.
    ns ip route replace "$CTF_VIEWER_CIDR" via "$CTF_CONTROL_BIND" dev gwc1
    # Deliberately NO default route in this namespace: a service with no
    # route off the game plane cannot reach the internet even if the policy
    # were wrong.
  fi

  ns sysctl -qw net.ipv4.ip_forward=1
  # RULES §5/§7: reverse-path filtering drops packets whose source does not
  # route back out the interface they arrived on — which is exactly what a
  # blind spoofed injection looks like. Leave it on and the transport-layer
  # flag class (ISN hijack, forged segments) mysteriously never lands.
  ns sysctl -qw net.ipv4.conf.all.rp_filter=0
  ns sysctl -qw net.ipv4.conf.default.rp_filter=0
  if [ "$MODE" = host ]; then
    echo "networks.sh: note — host mode enables ip_forward and clears rp_filter"
    echo "             host-wide. Run this on a dedicated CTF host."
  fi

  id -u "$VM_USER" >/dev/null 2>&1 || echo "networks.sh: note: user $VM_USER does not exist yet" >&2

  SVC_NETS=()
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    local name=$2 tap=$3 fns=$4 subnet=$5 lgw=$8 laddr=$9
    SVC_NETS+=("$subnet")
    local fgw=${10} faddr=${11} vh=${12} vn=${13} br=${14} footnet=${15}

    # --- the guest's own segment ---------------------------------------
    if [ "$MODE" = host ]; then
      # One bridge per guest. libvirt attaches the domain's NIC here; vm.sh
      # enslaves its own tap. Either way the guest is alone on this segment.
      ip link show "$br" >/dev/null 2>&1 || ip link add "$br" type bridge
      ip addr replace "${lgw}/30" dev "$br"
      ip link set "$br" mtu "$CTF_MTU" up
      if ! ip link show "$tap" >/dev/null 2>&1; then
        if id -u "$VM_USER" >/dev/null 2>&1; then
          ip tuntap add dev "$tap" mode tap user "$VM_USER"
        else
          ip tuntap add dev "$tap" mode tap
        fi
      fi
      ip link set "$tap" master "$br"
      ip link set "$tap" mtu "$CTF_MTU" up
      offload_off "$tap"; offload_off "$br"
      norp "$br"; norp "$tap"
      ip route replace "$subnet" via "${laddr%/*}" dev "$br"
    else
      # A tap in the router namespace: no bridge needed at all, the /30 is
      # the segment.
      if ! ns ip link show "$tap" >/dev/null 2>&1; then
        if id -u "$VM_USER" >/dev/null 2>&1; then
          ns ip tuntap add dev "$tap" mode tap user "$VM_USER"
        else
          ns ip tuntap add dev "$tap" mode tap
        fi
      fi
      ns ip addr replace "${lgw}/30" dev "$tap"
      ns ip link set "$tap" mtu "$CTF_MTU" up
      offload_off "$tap"
      norp "$tap"
      ns ip route replace "$subnet" via "${laddr%/*}" dev "$tap"
    fi

    # --- the attacker foothold ------------------------------------------
    ip netns list | grep -qx "$fns" || ip netns add "$fns"
    if ! ns ip link show "$vh" >/dev/null 2>&1; then
      ns ip link add "$vh" type veth peer name "$vn"
      ns ip link set "$vn" netns "$fns"
    fi
    ns ip addr replace "${fgw}/30" dev "$vh"
    ns ip link set "$vh" mtu "$CTF_MTU" up
    norp "$vh"
    ip netns exec "$fns" ip link set lo up
    ip netns exec "$fns" ip addr replace "$faddr" dev "$vn"
    ip netns exec "$fns" ip link set "$vn" mtu "$CTF_MTU" up
    ip netns exec "$fns" ip route replace default via "$fgw"
    ip netns exec "$fns" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$fns" sysctl -qw net.ipv4.conf.default.rp_filter=0
    # A foothold must never forward: a popped service must not be able to
    # pivot LAN-ward through its attacker's vantage point.
    ip netns exec "$fns" sysctl -qw net.ipv4.ip_forward=0
    ip netns exec "$fns" ethtool -K "$vn" tx off rx off 2>/dev/null || true

    # In netns mode the host reaches the game plane through the router. Both
    # routes are needed: the service subnet so the referee can probe, and the
    # foothold subnet so the submission API's replies can get home (and so
    # the host's own rp_filter accepts them on the way in).
    if [ "$MODE" = netns ]; then
      ip route replace "$subnet" via "$CTF_GW_CONTROL_ADDR" dev "$CTRL_IF"
      ip route replace "$footnet" via "$CTF_GW_CONTROL_ADDR" dev "$CTRL_IF"
    fi
  done

  firewall
  [ "$MODE" = netns ] && host_firewall
  echo "networks.sh: up — ${#PLAYER_ROWS[@]} players, mode=$MODE, control=$CTF_CONTROL_BIND viewer=$CTF_VIEWER_BIND"
}

firewall() {
  # The policy lives in topology/ctf.nft (netns mode) or ctf-host.nft (host
  # mode); only the definitions they consume are generated, from the roster.
  mkdir -p "$CTF_RUN"
  local defines="$CTF_RUN/ctf-defines.nft"
  local policy="$ROOT/topology/ctf.nft"
  [ "$MODE" = host ] && policy="$ROOT/topology/ctf-host.nft"
  "$PY" -m orchestrator.topology nft > "$defines"

  if [ "$MODE" = netns ]; then
    ns nft flush ruleset          # the namespace is ours alone
  else
    ns nft list table inet ctf >/dev/null 2>&1 && ns nft delete table inet ctf
  fi
  cat "$defines" "$policy" | ns nft -f -
  echo "networks.sh: policy loaded from $(basename "$policy")"
}

host_firewall() {
  # Build-user egress restrictions, applied whether or not builds are online.
  BUILD_RULES=""
  if id -u "${CTF_BUILD_USER:-ctf-build}" >/dev/null 2>&1; then
    BUILD_USER_NAME=${CTF_BUILD_USER:-ctf-build}
    BUILD_RULES=$(printf '    meta skuid "%s" ip daddr { %s, %s, %s } counter reject\n' \
      "$BUILD_USER_NAME" "$CTF_CONTROL_CIDR" "$CTF_VIEWER_CIDR" "$(IFS=,; echo "${SVC_NETS[*]}")")
  else
    BUILD_USER_NAME=${CTF_BUILD_USER:-ctf-build}
    echo "networks.sh: note: user $BUILD_USER_NAME does not exist; skipping build egress rules" >&2
  fi
  # Defense in depth in the root namespace: a service may never *initiate*
  # anything that terminates on the host, but replies to referee probes must
  # still come back. Scoped to service subnets only — foothold traffic to the
  # submission API is a normal, tracked connection and must pass.
  local set_list
  set_list=$(IFS=,; echo "${SVC_NETS[*]}")
  nft list table inet ctf_host >/dev/null 2>&1 && nft delete table inet ctf_host
  nft -f - <<NFT
table inet ctf_host {
  set game { type ipv4_addr; flags interval; elements = { ${set_list} } }
  chain input {
    type filter hook input priority -10;
    ct state established,related accept
    ip saddr @game ct state new counter drop
    ip saddr @game ct state untracked counter drop
  }
  chain forward {
    type filter hook forward priority -10;
    # the host is not a transit router between planes
    iifname "${CTRL_IF}" oifname "${VIEW_IF}" counter drop
    iifname "${VIEW_IF}" oifname "${CTRL_IF}" counter drop
  }

  chain output {
    type filter hook output priority -10;
    # Player build code runs as ${BUILD_USER} on this host. With
    # game.offline_builds = false it gets the internet so dependencies can be
    # fetched — but it must still never reach the referee, the viewer edge or
    # anyone's service. Pinning by uid keeps that true whether builds are
    # online or not.
${BUILD_RULES}  }
}
NFT
}

down() {
  require_root
  load_players
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    ip netns del "$4" 2>/dev/null || true
    ip route del "$5" 2>/dev/null || true
    ip route del "${15}" 2>/dev/null || true
    if [ "$MODE" = host ]; then
      ip link del "${14}" 2>/dev/null || true
      ip link del "$3" 2>/dev/null || true
    fi
  done
  if [ "$MODE" = netns ]; then
    ip netns del "$GW" 2>/dev/null || true
    ip link del gwc0 2>/dev/null || true
    nft list table inet ctf_host >/dev/null 2>&1 && nft delete table inet ctf_host || true
  else
    nft list table inet ctf >/dev/null 2>&1 && nft delete table inet ctf || true
  fi
  ip link del "$CTRL_IF" 2>/dev/null || true
  ip link del "$VIEW_IF" 2>/dev/null || true
  echo "networks.sh: down"
}

status() {
  load_players
  echo "== mode: $MODE =="
  echo "== host =="
  ip -br addr show "$CTRL_IF" 2>/dev/null || echo "  $CTRL_IF missing"
  ip -br addr show "$VIEW_IF" 2>/dev/null || echo "  $VIEW_IF missing"
  echo "== game plane =="
  if [ "$MODE" = netns ] && ! ip netns list | grep -qx "$GW"; then
    echo "  router namespace missing — run: networks.sh up"
  else
    ns ip -br addr
    echo "-- routes --"
    ns ip route
  fi
  echo "== footholds =="
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    printf '  %-12s ns=%-18s %s\n' "$2" "$4" "${11}"
  done
}

verify() {
  # SETUP §10 step 2. The negative tests matter more than the positive ones:
  # "the attacker can reach the victim" is easy; "nothing reaches the referee"
  # is the claim the whole game rests on.
  require_root
  load_players
  local rc=0

  tcp_from() {   # netns host port -> 0 if connectable
    ip netns exec "$1" timeout 3 "$PY" -c '
import socket, sys
s = socket.socket(); s.settimeout(2.5)
sys.exit(0 if s.connect_ex((sys.argv[1], int(sys.argv[2]))) == 0 else 1)
' "$2" "$3" 2>/dev/null
  }

  echo "== positive: each foothold reaches every other player's service =="
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    local name=$2 fns=$4
    for other in "${PLAYER_ROWS[@]}"; do
      # shellcheck disable=SC2086
      set -- $other
      [ "$2" = "$name" ] && continue
      if ip netns exec "$fns" ping -c1 -W1 "$6" >/dev/null 2>&1; then
        echo "  ok   foothold($name) -> service($2) at $6"
      else
        echo "  WARN foothold($name) -> service($2) unreachable (is that VM up?)"
      fi
    done
  done

  echo "== positive: footholds can submit and read the board =="
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    for port in "$CTF_SUBMIT_PORT" "$CTF_BOARD_PORT"; do
      if tcp_from "$4" "$CTF_VIEWER_BIND" "$port"; then
        echo "  ok   foothold($2) -> viewer edge :$port"
      else
        echo "  WARN foothold($2) -> viewer edge :$port refused (service running?)"
      fi
    done
  done

  echo "== negative: the referee is unreachable from the game plane =="
  for row in "${PLAYER_ROWS[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    local name=$2 fns=$4
    if ip netns exec "$fns" ping -c1 -W1 "$CTF_CONTROL_BIND" >/dev/null 2>&1; then
      echo "  FAIL foothold($name) reaches the control plane"; rc=1
    else
      echo "  ok   foothold($name) -> control plane blocked"
    fi
    if tcp_from "$fns" "$CTF_CONTROL_BIND" 22; then
      echo "  FAIL foothold($name) opens tcp/22 on control"; rc=1
    else
      echo "  ok   foothold($name) -> control tcp/22 blocked"
    fi
    if tcp_from "$fns" "$CTF_VIEWER_BIND" 22; then
      echo "  FAIL foothold($name) opens tcp/22 on the viewer edge"; rc=1
    else
      echo "  ok   foothold($name) -> viewer tcp/22 blocked (only the game ports)"
    fi
  done

  echo "== the two asymmetries =="
  if ns nft list table inet ctf 2>/dev/null | grep -q notrack; then
    echo "  ok   attack path bypasses conntrack (blind injection can land)"
  else
    echo "  FAIL no notrack rules — the state engine will eat injected segments"; rc=1
  fi
  if ns nft list table inet ctf 2>/dev/null | grep -q 'ct state established,related accept'; then
    echo "  ok   referee path stays tracked (a popped service can only reply)"
  else
    echo "  FAIL referee path is not stateful — RCE containment is missing"; rc=1
  fi

  echo
  echo "drop counters (watch ctf_drop climb while you test):"
  ns nft list counter inet ctf ctf_drop 2>/dev/null | sed 's/^/  /'
  ns nft list counter inet ctf ctf_attack 2>/dev/null | sed 's/^/  /'
  echo
  echo "The service side is verified from inside each guest at boot:"
  echo "  ctfctl console <player>    # look for the [isolation] lines"
  [ "$rc" = 0 ] && echo "verify: host-side isolation holds" || echo "verify: FAILURES ABOVE"
  return $rc
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  verify) verify ;;
  *) echo "usage: $0 {up|down|status|verify}" >&2; exit 2 ;;
esac
