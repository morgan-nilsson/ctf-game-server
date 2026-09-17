#!/usr/bin/env bash
# Build the base guest rootfs every service microVM boots from.
#
# Runs on the host, where network access is fine — it is the *builder* that
# must be offline (RULES §9), not this. The image is deliberately small: a
# kernel, a shell, python3, iproute2/ethtool, and nothing that listens.
#
# usage: sudo topology/build-rootfs.sh [output.ext4] [size-mib]
set -euo pipefail

OUT=${1:-/srv/ctf/vm/rootfs.ext4}
SIZE=${2:-1024}
SUITE=${SUITE:-noble}
MIRROR=${MIRROR:-http://archive.ubuntu.com/ubuntu}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

[ "$(id -u)" = 0 ] || { echo "build-rootfs.sh: run as root" >&2; exit 1; }
command -v debootstrap >/dev/null || { echo "install debootstrap first" >&2; exit 1; }

WORK=$(mktemp -d /tmp/ctf-rootfs.XXXXXX)
cleanup() { umount -R "$WORK/mnt" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK/fs" "$WORK/mnt" "$(dirname "$OUT")"

echo "== debootstrap $SUITE =="
debootstrap --variant=minbase \
  --include=iproute2,ethtool,iputils-ping,python3-minimal,libcap2-bin,util-linux,procps,coreutils \
  "$SUITE" "$WORK/fs" "$MIRROR"

echo "== stripping =="
chroot "$WORK/fs" /bin/sh -c '
  apt-get clean
  rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man /var/cache/*
  # nothing in the guest should listen: the only server here is the players
  rm -f /etc/systemd/system/*.wants/* 2>/dev/null || true
'

# Sanity-check the guest has what ctf-init and the self-test need. A missing
# binary here shows up as a service that never comes up, which is a miserable
# thing to debug through a serial console.
echo "== checking guest tooling =="
for tool in ip ethtool setpriv mount timeout python3 ping; do
  chroot "$WORK/fs" /bin/sh -c "command -v $tool >/dev/null" \
    || echo "  WARNING guest is missing $tool"
done

echo "== guest identity =="
# An unprivileged service user. The players stack runs as this; caps are
# granted per manifest by ctf-init, never by setuid.
chroot "$WORK/fs" useradd --system --create-home --home-dir /home/app --shell /bin/sh app
echo "ctf-service" > "$WORK/fs/etc/hostname"
cat > "$WORK/fs/etc/resolv.conf" <<'EOF'
# Deliberately empty: a service has no route off the game plane (RULES §1),
# so name resolution would only ever be a confusing timeout.
EOF

install -m 0755 "$ROOT/topology/guest/ctf-init" "$WORK/fs/sbin/ctf-init"
install -m 0755 "$ROOT/topology/guest/isolation-selftest.sh" \
                "$WORK/fs/usr/local/bin/isolation-selftest.sh"
mkdir -p "$WORK/fs/srv/app"

echo "== packing $OUT (${SIZE}MiB) =="
rm -f "$OUT"
if command -v mkfs.ext4 >/dev/null && mkfs.ext4 -V 2>&1 | grep -qE '1\.4[3-9]|1\.[5-9]'; then
  mkfs.ext4 -q -F -L ctf-root -d "$WORK/fs" "$OUT" "${SIZE}M"
else
  truncate -s "${SIZE}M" "$OUT"
  mkfs.ext4 -q -F -L ctf-root "$OUT"
  mount -o loop "$OUT" "$WORK/mnt"
  cp -a "$WORK/fs/." "$WORK/mnt/"
  umount "$WORK/mnt"
fi

echo "done: $OUT"
echo
echo "You still need a guest kernel (vm.kernel in the config). Either:"
echo "  * an uncompressed vmlinux for Firecracker, e.g. from the Firecracker"
echo "    CI images, or built from source with a microVM config; or"
echo "  * the host's own /boot/vmlinuz-\$(uname -r) if you run vm.hypervisor=qemu."
