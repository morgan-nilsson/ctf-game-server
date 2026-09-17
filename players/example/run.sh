#!/bin/sh
# Runs inside the guest as the unprivileged user `app`, with the caps you
# declared. tun0 already exists, is up, and is yours to open.
#
#   kernel side : $CTF_KERNEL_ADDR   (10.0.<n>.1)
#   your stack  : $CTF_ADDR          (10.0.<n>.2)  <- answer here
#   ports       : $CTF_TCP_PORT / $CTF_UDP_PORT
#   docroot     : $DOCROOT
set -eu
exec python3 src/main.py
