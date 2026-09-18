#!/usr/bin/env bash
# SETUP §2 — service microVMs, one per player, N players.
#
# Each service runs in a Firecracker (or QEMU/KVM) microVM: a real guest
# kernel, a real TUN inside, isolation at the hypervisor. Containers are not
# enough once memory-corruption flags are in scope (RULES §9), and gVisor is
# specifically wrong here — it replaces the netstack the players are supposed
# to be writing.
#
# Every start gives the guest a *fresh copy* of the base rootfs plus the data
# disk deploy.py just built. So a redeploy wipes any persistence an attacker
# established inside the guest, and two players' guests never share a byte.
#
# usage: vm.sh {start|stop|restart|status|console|all-start|all-stop} [player]
set -euo pipefail

PY=${PY:-python3}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GW=ctf-gw
VM_USER=${CTF_VM_USER:-ctf-vm}

cd "$ROOT"
eval "$("$PY" -m orchestrator.topology env)"
MODE=${CTF_PLANE_MODE:-netns}

# In netns mode the hypervisor must run inside the router namespace, because
# that is where its tap lives. In host mode the tap is already enslaved to the
# guest's bridge in the root namespace, so no netns wrapper is needed.
if [ "$MODE" = host ]; then
  in_plane() { "$@"; }
else
  in_plane() { ip netns exec "$GW" "$@"; }
fi

require_root() { [ "$(id -u)" = 0 ] || { echo "vm.sh: must run as root" >&2; exit 1; }; }
# Named namespaces live at /run/netns/<name>. Don't parse `ip netns list`:
# once a namespace holds a link it prints as "name (id: N)", so an exact-line
# match silently stops working after the first `up`.
ns_exists() { [ -e "/run/netns/$1" ]; }
have() { command -v "$1" >/dev/null 2>&1; }

# Run the hypervisor inside a systemd scope with hard memory and CPU caps.
# Everything shares one host: DoS is out of scope by rule (RULES §9), but a
# runaway or resource-bombed guest would starve the host router and the
# referee's tick loop, skewing scoring for everyone rather than costing one
# player their SLA. A cgroup makes that structural instead of honour-system.
capped() {
  if have systemd-run; then
    systemd-run --quiet --collect --unit="ctf-vm-$P_NAME" --scope \
      -p MemoryMax="${CTF_VM_MEM_MAX:-$(( CTF_MEM_MIB + 256 ))M}" \
      -p MemorySwapMax=0 \
      -p CPUQuota="${CTF_VM_CPU_QUOTA:-$(( CTF_VCPUS * 100 ))%}" \
      -p TasksMax=256 \
      -- "$@"
  else
    echo "vm.sh: systemd-run unavailable — $P_NAME runs uncapped" >&2
    "$@"
  fi
}

# Firecracker needs an uncompressed vmlinux; QEMU is happy with the host's
# own compressed kernel. So if no kernel is configured (or the configured one
# is missing) and we are on QEMU, fall back to the running kernel — that
# removes the one build step that otherwise blocks a first run.
resolve_kernel() {
  if [ -n "${CTF_KERNEL:-}" ] && [ -f "$CTF_KERNEL" ]; then
    return 0
  fi
  case "$CTF_HYPERVISOR" in
    qemu|qemu-tcg)
      for candidate in "/boot/vmlinuz-$(uname -r)" /boot/vmlinuz; do
        if [ -r "$candidate" ]; then
          CTF_KERNEL="$candidate"
          echo "vm.sh: using the host kernel $CTF_KERNEL (vm.kernel not set)" >&2
          return 0
        fi
      done
      ;;
  esac
  return 0        # let the hypervisor report it; start_* checks again
}

load_player() {
  eval "$("$PY" -m orchestrator.topology player "$1")"
  PIDFILE="$CTF_RUN/vm-$P_NAME.pid"
  LOGFILE="$CTF_LOGS/vm-$P_NAME.log"
  VMDIR="$CTF_ARTIFACTS/$P_NAME"
  ROOTFS_COPY="$VMDIR/rootfs.ext4"
  DATA="$VMDIR/data.ext4"
  API_SOCK="$CTF_RUN/fc-$P_NAME.sock"
  mkdir -p "$CTF_RUN" "$CTF_LOGS" "$VMDIR"
}

is_running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

mac_for() {  # stable, locally administered, derived from the player index
  printf '02:00:00:00:%02x:%02x' $(( P_INDEX / 256 )) $(( P_INDEX % 256 ))
}

prepare_disks() {
  [ -f "$DATA" ] || { echo "vm.sh: no data disk for $P_NAME yet — deploy first" >&2; return 1; }
  if [ "$CTF_HYPERVISOR" = libvirt ]; then
    # The domain's root disk belongs to libvirt. We only ever hand it the
    # freshly built data disk, which its XML must reference as vdb.
    chown "$VM_USER":"$VM_USER" "$DATA" 2>/dev/null || true
    return 0
  fi
  [ -f "$CTF_ROOTFS" ] || { echo "vm.sh: base rootfs missing: $CTF_ROOTFS (run topology/build-rootfs.sh)" >&2; return 1; }
  # A fresh copy of the base rootfs on every start: a redeploy therefore
  # wipes any persistence an attacker established inside the guest.
  rm -f "$ROOTFS_COPY"
  cp --reflink=auto "$CTF_ROOTFS" "$ROOTFS_COPY"
  chown "$VM_USER":"$VM_USER" "$ROOTFS_COPY" "$DATA" 2>/dev/null || true
}

# Kernel cmdline: static link address, no DHCP, serial console.
# ip=<client>::<gw>:<mask>:<host>:<dev>:off
cmdline() {
  local addr=${P_LINK_ADDR%/*}
  echo "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux" \
       "ip=${addr}::${P_LINK_GW}:255.255.255.252:${P_NAME}:eth0:off" \
       "ctf.player=${P_NAME} root=/dev/vda rw init=/sbin/ctf-init"
}

start_firecracker() {
  have firecracker || { echo "vm.sh: firecracker not installed" >&2; return 1; }
  if [ -z "${CTF_KERNEL:-}" ] || [ ! -f "$CTF_KERNEL" ]; then
    echo "vm.sh: no guest kernel at '${CTF_KERNEL:-}' — firecracker needs an" >&2
    echo "       UNCOMPRESSED vmlinux. Quickest path if you are in a hurry:" >&2
    echo "       set vm.hypervisor = \"qemu\" and vm.sh will use the host kernel." >&2
    return 1
  fi
  [ -e /dev/kvm ] || { echo "vm.sh: /dev/kvm missing — see bin/preflight.sh" >&2; return 1; }
  rm -f "$API_SOCK"
  local cfg="$VMDIR/firecracker.json"
  cat > "$cfg" <<JSON
{
  "boot-source": {
    "kernel_image_path": "$CTF_KERNEL",
    "boot_args": "$(cmdline)"
  },
  "drives": [
    { "drive_id": "rootfs", "path_on_host": "$ROOTFS_COPY",
      "is_root_device": true, "is_read_only": false },
    { "drive_id": "data", "path_on_host": "$DATA",
      "is_root_device": false, "is_read_only": false }
  ],
  "network-interfaces": [
    { "iface_id": "eth0", "host_dev_name": "$P_TAP", "guest_mac": "$(mac_for)" }
  ],
  "machine-config": { "vcpu_count": $CTF_VCPUS, "mem_size_mib": $CTF_MEM_MIB, "smt": false }
}
JSON
  chown "$VM_USER":"$VM_USER" "$cfg" 2>/dev/null || true
  in_plane capped setsid setpriv --reuid "$VM_USER" --regid "$VM_USER" --init-groups \
    firecracker --api-sock "$API_SOCK" --config-file "$cfg" \
    >>"$LOGFILE" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
}

start_qemu() {
  have qemu-system-x86_64 || { echo "vm.sh: qemu-system-x86_64 not installed" >&2; return 1; }
  if [ -z "${CTF_KERNEL:-}" ] || [ ! -f "$CTF_KERNEL" ]; then
    echo "vm.sh: no guest kernel found (vm.kernel unset and no /boot/vmlinuz)" >&2
    return 1
  fi
  local accel=tcg cpu=max
  if [ "$CTF_HYPERVISOR" = qemu ] && [ -e /dev/kvm ]; then accel=kvm; cpu=host; fi
  if [ "$accel" = tcg ]; then
    # `-cpu host` is a KVM-only model: qemu refuses to start with it under TCG.
    echo "vm.sh: WARNING running $P_NAME under TCG — slow. Raise probe.timeout" >&2
    echo "       in the config or the SLA will flake on every tick." >&2
  fi
  in_plane capped setsid setpriv --reuid "$VM_USER" --regid "$VM_USER" --init-groups \
    qemu-system-x86_64 \
      -machine microvm,accel="$accel" -cpu "$cpu" -smp "$CTF_VCPUS" -m "$CTF_MEM_MIB" \
      -nodefaults -no-user-config -nographic -serial mon:stdio \
      -kernel "$CTF_KERNEL" -append "$(cmdline)" \
      -drive id=root,file="$ROOTFS_COPY",format=raw,if=none \
      -device virtio-blk-device,drive=root \
      -drive id=data,file="$DATA",format=raw,if=none \
      -device virtio-blk-device,drive=data \
      -netdev tap,id=n0,ifname="$P_TAP",script=no,downscript=no \
      -device virtio-net-device,netdev=n0,mac="$(mac_for)" \
    >>"$LOGFILE" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
}

# Libvirt owns the domain: we only rebuild the disks and bounce it. The
# domain XML must attach its NIC to the guest's bridge and reference this
# player's data disk as vdb — see docs/OPERATIONS.md.
libvirt_domain() { echo "${CTF_LIBVIRT_PREFIX:-ctf-}$P_NAME"; }

start_libvirt() {
  have virsh || { echo "vm.sh: virsh not installed" >&2; return 1; }
  virsh start "$(libvirt_domain)" >>"$LOGFILE" 2>&1 \
    || { echo "vm.sh: virsh start $(libvirt_domain) failed; tail $LOGFILE" >&2; return 1; }
  echo "vm.sh: $P_NAME started via libvirt ($(libvirt_domain), $P_HOST)"
}

stop_libvirt() {
  have virsh || return 0
  virsh shutdown "$(libvirt_domain)" >>"$LOGFILE" 2>&1 || true
  for _ in $(seq 1 30); do
    [ "$(virsh domstate "$(libvirt_domain)" 2>/dev/null)" = "shut off" ] && break
    sleep 1
  done
  [ "$(virsh domstate "$(libvirt_domain)" 2>/dev/null)" = "shut off" ] \
    || virsh destroy "$(libvirt_domain)" >>"$LOGFILE" 2>&1 || true
  echo "vm.sh: $P_NAME stopped via libvirt"
}

start() {
  require_root
  load_player "$1"
  if [ "$CTF_HYPERVISOR" = libvirt ]; then
    prepare_disks || return 1
    start_libvirt || return 1
    return 0
  fi
  if is_running; then echo "vm.sh: $P_NAME already running (pid $(cat "$PIDFILE"))"; return 0; fi
  if [ "$MODE" = netns ]; then
    ns_exists "$GW" || { echo "vm.sh: run topology/networks.sh up first" >&2; return 1; }
  fi
  resolve_kernel
  prepare_disks || return 1
  echo "--- $(date -Is) starting $P_NAME ---" >> "$LOGFILE"
  case "$CTF_HYPERVISOR" in
    firecracker) start_firecracker ;;
    qemu|qemu-tcg) start_qemu ;;
    libvirt) start_libvirt ;;
    none) echo "vm.sh: hypervisor=none, nothing to start"; return 0 ;;
    *) echo "vm.sh: unknown hypervisor $CTF_HYPERVISOR" >&2; return 1 ;;
  esac
  sleep 1
  is_running && echo "vm.sh: $P_NAME started (pid $(cat "$PIDFILE"), $P_HOST)" \
             || { echo "vm.sh: $P_NAME failed to start; tail $LOGFILE" >&2; tail -20 "$LOGFILE" >&2; return 1; }
}

stop() {
  require_root
  load_player "$1"
  if [ "$CTF_HYPERVISOR" = libvirt ]; then stop_libvirt; return 0; fi
  if ! is_running; then rm -f "$PIDFILE"; echo "vm.sh: $P_NAME not running"; return 0; fi
  local pid; pid=$(cat "$PIDFILE")
  kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
  rm -f "$PIDFILE" "$API_SOCK"
  echo "vm.sh: $P_NAME stopped"
}

status() {
  load_player "$1"
  if [ "$CTF_HYPERVISOR" = libvirt ]; then
    echo "$P_NAME: $(virsh domstate "$(libvirt_domain)" 2>/dev/null || echo unknown) (libvirt) addr=$P_HOST"
    return 0
  fi
  if is_running; then
    echo "$P_NAME: running pid=$(cat "$PIDFILE") addr=$P_HOST tap=$P_TAP"
  else
    echo "$P_NAME: stopped"
  fi
}

console() {
  load_player "$1"
  if [ "$CTF_HYPERVISOR" = libvirt ]; then
    echo "vm.sh: libvirt owns this domain's console — use:"
    echo "  virsh console $(libvirt_domain)      # live (escape: ctrl-])"
    echo "  virsh dumpxml $(libvirt_domain) | grep -A2 serial"
    echo "--- vm.sh's own log ---"
    tail -n "${2:-60}" "$LOGFILE" 2>/dev/null || echo "(none)"
    return 0
  fi
  echo "--- tail of $LOGFILE (guest serial console) ---"
  tail -n "${2:-60}" "$LOGFILE"
}

case "${1:-}" in
  start)   start "${2:?player}" ;;
  stop)    stop "${2:?player}" ;;
  restart) stop "${2:?player}"; start "$2" ;;
  status)  if [ $# -ge 2 ]; then status "$2"; else for p in $CTF_PLAYERS; do status "$p"; done; fi ;;
  console) console "${2:?player}" "${3:-60}" ;;
  all-start)
    # Best effort by design: on a fresh host nobody has been deployed yet, so
    # "no data disk" is the expected state, not a failure of the unit.
    started=0; skipped=0
    for p in $CTF_PLAYERS; do
      if start "$p"; then started=$((started + 1)); else skipped=$((skipped + 1)); fi
    done
    echo "vm.sh: $started started, $skipped not ready (deploy them, then: ctfctl vm all-start)"
    exit 0 ;;
  all-stop)
    for p in $CTF_PLAYERS; do stop "$p" || true; done
    exit 0 ;;
  *) echo "usage: $0 {start|stop|restart|status|console|all-start|all-stop} [player]" >&2; exit 2 ;;
esac
