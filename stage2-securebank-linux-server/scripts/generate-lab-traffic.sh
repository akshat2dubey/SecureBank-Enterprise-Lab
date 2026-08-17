#!/usr/bin/env bash
#
# SecureBank Linux Server — Generate lab traffic for Stage 1
# -----------------------------------------------------------
# Groundwork for Module 6 (Stage 1 integration); usable right now.
# Run this on the SecureBank server as the admin user (NOT root) while the
# Stage 1 analyzer captures the host-only segment (10.10.10.0/24):
#
#   sudo python3 network_traffic_analyzer.py --interface <iface> --timeout 60
#
# It produces exactly the traffic categories the Stage 1 analyzer reports:
#   TCP   -> SSH handshake, HTTP connection attempt to the lab address
#   UDP   -> DNS lookups
#   ICMP  -> ping
#   ARP   -> neighbor discovery (automatic)
#   TCP flags -> SYN/SYN-ACK/ACK, and RST when a service is absent
#
# Visibility rule: Stage 1 sees what crosses the segment it captures.
# Lab-segment traffic (10.10.10.0/24) is visible to a host-only capture;
# traffic leaving via NAT (package updates, external DNS) is not.
#
# Usage:  ./scripts/generate-lab-traffic.sh [repeat-count]
# (repeat-count defaults to 3; raise it for more volume)

set -euo pipefail

COUNT="${1:-3}"

log() { printf '\n\033[1;34m[traffic]\033[0m %s\n' "$*"; }

if ! command -v dig >/dev/null 2>&1; then
  log "dig not found — install it by re-running:  sudo ./scripts/setup.sh  (adds dnsutils)"
fi

log "=== 1/5 TCP — SSH handshake to the lab address ==="
# BatchMode prevents password prompts. Even a failed login produces a full
# TCP handshake (SYN -> SYN-ACK -> ACK) on the segment plus an entry in
# /var/log/auth.log — exactly the telemetry Stages 7/8 want.
ssh -o BatchMode=yes -o ConnectTimeout=3 10.10.10.10 true || true

log "=== 2/5 UDP — DNS lookups ==="
# dig queries DNS servers directly (it does NOT use /etc/hosts), so these are
# real UDP 53 queries. They leave via the NAT resolver by default — to make
# them visible on the host-only segment, Module 2/3 adds dnsmasq on the server
# and you switch to:  dig @10.10.10.10 ...
for _ in $(seq 1 "${COUNT}"); do
  dig +short +time=2 +tries=1 securebank-srv.securebank.lab >/dev/null 2>&1 || true
  dig +short +time=2 +tries=1 deb.debian.org >/dev/null 2>&1 || true
done

log "=== 3/5 ICMP — ping ==="
ping -c "${COUNT}" -i 1 10.10.10.10 >/dev/null 2>&1 || true

log "=== 4/5 TCP — HTTP request to the lab address ==="
# No web service yet (that is Module 3), so curl gets a connection reset.
# That is still real traffic: SYN -> RST, visible in the analyzer's tcp_flags.
# Once nginx exists, this becomes a real HTTP exchange on 80/443.
curl -sS --max-time 5 -o /dev/null http://10.10.10.10/ || true

log "=== 5/5 ARP — neighbor discovery ==="
# Each ping to a host on the segment triggers an ARP request for it.
for host in 10.10.10.10 10.10.10.20 10.10.10.30; do
  ping -c 1 -W 1 "${host}" >/dev/null 2>&1 || true
done

log "Done. In the Stage 1 report, look for:"
log "  - protocols:     TCP / UDP / ICMP / ARP rows"
log "  - top flows:     TCP 10.10.10.10:<port> -> 10.10.10.10:22 (SSH) and :80 (curl)"
log "  - tcp_flags:     handshake flags (S, SA, A) and RST for the closed HTTP port"
