#!/usr/bin/env bash
# Install the CTF host onto an Ubuntu server. Idempotent.
#
#   sudo ./install.sh [--no-packages]
#
# Afterwards: edit /etc/ctf/ctf.toml (roster + submit tokens), then follow
# SETUP §10 bring-up order — or just `ctfctl preflight`.
set -euo pipefail

PREFIX=${PREFIX:-/opt/ctf}
SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NO_PACKAGES=0
[ "${1:-}" = "--no-packages" ] && NO_PACKAGES=1

[ "$(id -u)" = 0 ] || { echo "install.sh: run as root" >&2; exit 1; }

if [ "$NO_PACKAGES" = 0 ] && command -v apt-get >/dev/null; then
  echo "== packages =="
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-minimal git iproute2 nftables ethtool e2fsprogs \
    bubblewrap debootstrap qemu-system-x86 util-linux ca-certificates curl
fi

echo "== users =="
# ctf     : runs the referee. Owns the flag store.
# ctf-build: runs player builds. Deliberately has no access to the flag store.
# ctf-vm  : runs the hypervisors.
id -u ctf       >/dev/null 2>&1 || useradd --system --home-dir /srv/ctf --shell /usr/sbin/nologin ctf
id -u ctf-build >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin ctf-build
id -u ctf-vm    >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin ctf-vm
getent group kvm >/dev/null && usermod -aG kvm ctf-vm || true

echo "== files =="
mkdir -p "$PREFIX"
# `tests` ships too: ctfctl selftest drives the bundled reference and
# hostile services from there, and it is the pre-launch gate.
for item in orchestrator topology bin config docs fixtures players tests \
            RULES.md SETUP.md README.md GO-LIVE.md; do
  [ -e "$SRC/$item" ] || continue
  # Replace, don't merge: `cp -a dir dest/` where dest/dir exists would nest
  # it (dest/dir/dir) and leave the previous copy shadowing the new code.
  rm -rf "$PREFIX/$item"
  cp -a "$SRC/$item" "$PREFIX/"
done
# Stale bytecode from a previous version would otherwise win over new source.
find "$PREFIX" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
chmod +x "$PREFIX"/bin/* "$PREFIX"/topology/*.sh "$PREFIX"/topology/guest/* \
         "$PREFIX"/orchestrator/builder/*.sh 2>/dev/null || true
ln -sf "$PREFIX/bin/ctfctl" /usr/local/bin/ctfctl

echo "== directories =="
install -d -o ctf -g ctf -m 0750 /srv/ctf /srv/ctf/players /srv/ctf/repos /srv/ctf/fixtures
install -d -o ctf -g ctf -m 0750 /srv/ctf/artifacts /srv/ctf/vm /var/log/ctf
install -d -o ctf -g ctf -m 0750 /run/ctf
# The backup timer runs as `ctf`, and /var/backups itself is root-owned.
install -d -o ctf -g ctf -m 0750 /var/backups/ctf
install -d -m 0755 /etc/ctf
# The flag store is readable only by the referee: the build user must never
# see a flag (SETUP §5), and neither should a curious player with shell.
if [ -f /srv/ctf/state.db ]; then chown ctf:ctf /srv/ctf/state.db; chmod 0600 /srv/ctf/state.db; fi

if [ ! -f /etc/ctf/ctf.toml ]; then
  cp "$SRC/config/ctf.example.toml" /etc/ctf/ctf.toml
  chmod 0640 /etc/ctf/ctf.toml; chown root:ctf /etc/ctf/ctf.toml
  echo "   wrote /etc/ctf/ctf.toml — EDIT IT: roster and submit tokens"
else
  echo "   keeping existing /etc/ctf/ctf.toml"
fi

echo "== sudo rules =="
# The referee needs exactly two privileged verbs, nothing else.
cat > /etc/sudoers.d/ctf <<EOF
ctf ALL=(root) NOPASSWD: $PREFIX/topology/vm.sh, $PREFIX/topology/networks.sh
EOF
chmod 0440 /etc/sudoers.d/ctf
visudo -cf /etc/sudoers.d/ctf >/dev/null

echo "== systemd =="
cp "$SRC"/systemd/*.service "$SRC"/systemd/*.timer /etc/systemd/system/
systemd-tmpfiles --create 2>/dev/null || true
cat > /etc/tmpfiles.d/ctf.conf <<'EOF'
d /run/ctf 0750 ctf ctf -
EOF
systemctl daemon-reload
systemctl enable ctf-backup.timer >/dev/null

echo
echo "installed to $PREFIX"
echo
echo "next:"
echo "  1. \$EDITOR /etc/ctf/ctf.toml           # roster, submit tokens"
echo "  2. ctfctl preflight                     # /dev/kvm, tools, config"
echo "  3. sudo $PREFIX/topology/build-rootfs.sh   # guest image (once)"
echo "  4. systemctl start ctf-topology         # planes + VMs"
echo "  5. ctfctl deploy all                    # first build of every repo"
echo "  6. systemctl start ctf-tick ctf-leaderboard ctf-submit ctf-watcher"
echo "  7. ctfctl status"
