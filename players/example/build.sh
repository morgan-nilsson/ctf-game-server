#!/bin/sh
# Runs in the sandboxed builder: NO network, NO flags, NO secrets.
# Vendor your dependencies — a fetch here will fail, by design (RULES §9).
#
# Available: $OUTDIR (what gets shipped to the guest), $DOCROOT ($OUTDIR/docroot),
#            $SOURCE_DATE_EPOCH (set it into your toolchain for reproducibility).
set -eu

echo "building example stack"
mkdir -p "$OUTDIR/src"
cp -a src/. "$OUTDIR/src/"
cp run.sh "$OUTDIR/run.sh"
chmod +x "$OUTDIR/run.sh"

# Fixtures the referee plants live in $DOCROOT and ship with the artifact.
mkdir -p "$DOCROOT"

echo "build complete"
