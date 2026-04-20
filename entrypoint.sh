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

# Single worker is mandatory: the gateway holds in-memory grant state and
# owns the WG interface / iptables rules. Multiple workers would race. Use
# threads for concurrency within that one worker.
exec gunicorn \
  --config /app/gunicorn.conf.py \
  --bind 0.0.0.0:8080 \
  --workers 1 \
  --threads 8 \
  --timeout 60 \
  --access-logfile - \
  --error-logfile - \
  wsgi:app
