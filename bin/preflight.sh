#!/usr/bin/env bash
# SETUP §10 step 1 — check this host can actually run the game before you
# spend an evening finding out it cannot.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY=${PY:-python3}
rc=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; rc=1; }

echo "== virtualisation =="
if [ -e /dev/kvm ]; then
  ok "/dev/kvm present"
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || warn "/dev/kvm not accessible to $(id -un) — add them to the kvm group"
else
  bad "/dev/kvm missing: no nested virt. Firecracker will not boot."
  echo "       Fall back to vm.hypervisor=\"qemu-tcg\" (slow: raise probe.timeout),"
  echo "       or drop RCE to logical-only bugs and run services in containers."
fi
grep -qE 'vmx|svm' /proc/cpuinfo 2>/dev/null && ok "CPU virtualisation flags present" \
  || warn "no vmx/svm in /proc/cpuinfo"

echo "== kernel features =="
[ -c /dev/net/tun ] && ok "/dev/net/tun present" || bad "/dev/net/tun missing (modprobe tun)"
[ -d /proc/sys/net/ipv4 ] && ok "ipv4 stack" || bad "no ipv4?"
lsmod 2>/dev/null | grep -q '^nf_tables' && ok "nf_tables loaded" \
  || warn "nf_tables not loaded yet (nft will load it)"

echo "== tools =="
for tool in ip nft python3 git mkfs.ext4 ethtool; do
  command -v "$tool" >/dev/null && ok "$tool" || bad "$tool missing"
done
for tool in firecracker qemu-system-x86_64; do
  command -v "$tool" >/dev/null && ok "$tool" || warn "$tool not installed"
done
command -v bwrap >/dev/null && ok "bwrap (build sandbox)" \
  || warn "bwrap missing — builds fall back to 'unshare -n' (weaker fs isolation)"
command -v debootstrap >/dev/null && ok "debootstrap (for build-rootfs.sh)" \
  || warn "debootstrap missing"

echo "== python =="
"$PY" -c 'import sys; assert sys.version_info >= (3,11)' 2>/dev/null \
  && ok "python3 $("$PY" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))') (tomllib available)" \
  || bad "python3 >= 3.11 required (tomllib)"

echo "== config =="
CFG=${CTF_CONFIG:-/etc/ctf/ctf.toml}
CFG_OK=1
if [ -f "$CFG" ] && [ ! -r "$CFG" ]; then
  # 0640 root:ctf on purpose — it holds every player's submit token.
  bad "cannot read $CFG as $(id -un) — run: sudo ctfctl preflight"
  CFG_OK=0
elif [ -f "$CFG" ]; then
  if (cd "$ROOT" && CTF_CONFIG="$CFG" "$PY" -m orchestrator.topology env >/dev/null 2>&1); then
    players=$(cd "$ROOT" && CTF_CONFIG="$CFG" "$PY" -m orchestrator.topology env \
              | sed -n "s/^CTF_PLAYERS=//p" | tr -d "'\"")
    ok "$CFG parses; players: $players"
  else
    bad "$CFG failed to parse"
    (cd "$ROOT" && CTF_CONFIG="$CFG" "$PY" -m orchestrator.topology env 2>&1 | sed 's/^/       /')
  fi
  if grep -q 'CHANGE-ME' "$CFG"; then
    bad "$CFG still contains placeholder submit tokens"
  else
    ok "submit tokens set"
  fi
else
  warn "$CFG not found (copy config/ctf.example.toml)"
fi

echo "== guest image =="
if [ "$CFG_OK" = 0 ]; then
  warn "skipped — needs the config (sudo ctfctl preflight)"
elif [ -f "$CFG" ]; then
  eval "$(cd "$ROOT" && CTF_CONFIG="$CFG" "$PY" -m orchestrator.topology env 2>/dev/null | grep -E '^CTF_(KERNEL|ROOTFS|HYPERVISOR)=')" 2>/dev/null || true
  [ -f "${CTF_ROOTFS:-}" ] && ok "guest rootfs ${CTF_ROOTFS}" \
    || bad "no guest rootfs at '${CTF_ROOTFS:-unset}' — run: sudo topology/build-rootfs.sh"
  if [ -f "${CTF_KERNEL:-}" ]; then
    ok "guest kernel ${CTF_KERNEL}"
  elif [ "${CTF_HYPERVISOR:-}" = qemu ] || [ "${CTF_HYPERVISOR:-}" = qemu-tcg ]; then
    if [ -r "/boot/vmlinuz-$(uname -r)" ]; then
      ok "no vm.kernel set, but qemu will use /boot/vmlinuz-$(uname -r)"
    else
      bad "no guest kernel and no /boot/vmlinuz to fall back on"
    fi
  else
    bad "no guest kernel at '${CTF_KERNEL:-unset}' (firecracker needs an uncompressed vmlinux;"
    echo "       in a hurry? set vm.hypervisor=\"qemu\" to use the host kernel)"
  fi
fi

echo
[ "$rc" = 0 ] && echo "preflight: ready" || echo "preflight: blocking problems above"
exit "$rc"
