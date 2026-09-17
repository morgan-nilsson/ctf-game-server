#!/usr/bin/env bash
# SETUP §5 — build a player's repo in a throwaway sandbox.
#
#   no flags     : runs as the unprivileged build user, which has no read
#                  access to the state db or the fixtures tree
#   no secrets   : the environment is wiped; only SOURCE_DATE_EPOCH et al survive
#   no egress    : the build runs in a fresh, empty network namespace, so a
#                  build-time fetch cannot reach a mirror, let alone the
#                  internet (RULES §9 — builders are offline). Vendor your deps.
#   reproducible : fixed TZ/locale/umask + SOURCE_DATE_EPOCH (RULES §8)
#
# usage: sandbox-build.sh <srcdir> <outdir> <build-cmd> [timeout-seconds]
set -euo pipefail

SRC=${1:?srcdir}
OUT=${2:?outdir}
CMD=${3:?build command}
TIMEOUT=${4:-600}
BUILD_USER=${CTF_BUILD_USER:-ctf-build}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1700000000}

[ -d "$SRC" ] || { echo "sandbox-build: no such srcdir: $SRC" >&2; exit 2; }

# --- the flag store must be invisible to player build code ---------------
# build.sh is arbitrary player code by design. "Offline" only removes the
# network; it does nothing about the filesystem. A build that can read
# /srv/ctf/state.db lifts every live flag with `strings` — no network, no
# sqlite, before a single packet touches a service. So: mask the referee's
# directories inside the sandbox, and refuse to run the weaker fallback at
# all if the build user can actually read the store.
if [ -n "${CTF_STATE_DB:-}" ] && [ -f "$CTF_STATE_DB" ] \
   && [ "$(id -u)" = 0 ] && id -u "$BUILD_USER" >/dev/null 2>&1; then
  if setpriv --reuid "$BUILD_USER" --regid "$BUILD_USER" --init-groups \
       test -r "$CTF_STATE_DB" 2>/dev/null; then
    echo "sandbox-build: REFUSING TO BUILD — $BUILD_USER can read the flag store" >&2
    echo "               ($CTF_STATE_DB). Fix its ownership/mode first:" >&2
    echo "               chown ctf:ctf '$CTF_STATE_DB' && chmod 0600 '$CTF_STATE_DB'" >&2
    exit 3
  fi
fi

MASK_ARGS=()
for masked in ${CTF_MASK:-}; do
  [ -e "$masked" ] && MASK_ARGS+=(--tmpfs "$masked")
done
mkdir -p "$OUT"

# The sandbox sees the source read-only and the output tree read-write, so a
# build cannot rewrite the checkout under the orchestrator's feet.
WORK=$(mktemp -d "${CTF_BUILD_TMP:-/var/tmp}/ctf-build.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
cp -a "$SRC/." "$WORK/"
chmod -R u+rwX "$WORK"

if id "$BUILD_USER" >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  chown -R "$BUILD_USER":"$BUILD_USER" "$WORK" "$OUT"
  AS_USER=(setpriv --reuid "$BUILD_USER" --regid "$BUILD_USER" --init-groups --inh-caps=-all)
else
  echo "sandbox-build: WARNING running as $(id -un); create $BUILD_USER for a real split" >&2
  AS_USER=()
fi

ENVIRON=(
  env -i
  PATH=/usr/local/bin:/usr/bin:/bin
  HOME="$WORK"
  TMPDIR="$WORK/tmp"
  LC_ALL=C.UTF-8
  TZ=UTC
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
  DOCROOT="$OUT/docroot"
  OUTDIR="$OUT"
)
mkdir -p "$WORK/tmp" "$OUT/docroot"

run_sandboxed() {
  if command -v bwrap >/dev/null 2>&1; then
    # Preferred: full filesystem + network + IPC isolation.
    bwrap \
      --unshare-all --die-with-parent --new-session \
      --ro-bind / / \
      --dev /dev --proc /proc \
      --tmpfs /run --tmpfs /tmp \
      ${MASK_ARGS[@]+"${MASK_ARGS[@]}"} \
      --bind "$WORK" "$WORK" --bind "$OUT" "$OUT" \
      --chdir "$WORK" \
      -- "${ENVIRON[@]}" /bin/sh -c "umask 022; exec $CMD"
  else
    # Fallback: at minimum, no network namespace.
    echo "sandbox-build: bwrap not found, falling back to unshare -n" >&2
    # Pass the paths and the build command as positional arguments rather
    # than interpolating them into a quoted string, so a quote in either
    # cannot break out of the sandbox invocation.
    unshare --net --mount --pid --fork -- \
      "${ENVIRON[@]}" /bin/sh -c \
        'cd "$1" || exit 1; umask 022; exec /bin/sh -c "$2"' _ "$WORK" "$CMD"
  fi
}

echo "sandbox-build: building in $WORK (offline, as ${BUILD_USER}, timeout ${TIMEOUT}s)"

# One command string, run either directly or after dropping privileges.
INNER=(bash -c "$(declare -f run_sandboxed); $(declare -p ENVIRON WORK OUT CMD MASK_ARGS); run_sandboxed")

set +e
timeout --signal=TERM --kill-after=10 "$TIMEOUT" \
  ${AS_USER[@]+"${AS_USER[@]}"} "${INNER[@]}"
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
  echo "sandbox-build: TIMEOUT after ${TIMEOUT}s" >&2
elif [ "$rc" -ne 0 ]; then
  echo "sandbox-build: build command failed with exit $rc" >&2
else
  echo "sandbox-build: ok"
fi
exit "$rc"
