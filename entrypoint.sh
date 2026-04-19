#!/bin/sh
set -e

# The gateway.py module handles `ip link add ... wireguard`, `wg set`, and
# iptables rules itself. Here we only ensure the kernel knobs it depends on
# are actually on. Docker containers inherit net.ipv4.ip_forward from the
# host unless sysctls are declared in compose; we set it here too so that
# the same image works with just --cap-add=NET_ADMIN.
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
  echo 1 > /proc/sys/net/ipv4/ip_forward || true
fi

exec python -u /app/app.py
