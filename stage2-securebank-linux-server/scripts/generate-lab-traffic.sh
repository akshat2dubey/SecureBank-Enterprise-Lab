#!/usr/bin/env bash
#
# SecureBank Linux Server — Generate lab traffic for Stage 1
# -----------------------------------------------------------
# Groundwork for Module 6 (Stage 1 integration); usable right now.
#
# WHERE to run it — this is the important part:
#   The Stage 1 analyzer captures the host-only segment (lab.env -> SB_LAB_SUBNET).
#   Traffic only crosses that segment when it travels BETWEEN two hosts. A
#   server talking to ITSELF (or to the NAT resolver) is invisible to the
#   analyzer VM. So:
#
#     DEFAULT (recommended): run on KALI (or the analyzer VM) -> client mode.
#       SSH/HTTP/ping from Kali to the server physically crosses the segment
#       and the analyzer sees it. The script auto-detects this: if the local
#       hostname is not SB_HOSTNAME, it runs in client mode.
#
#     Run on the SERVER itself -> self mode (loopback telemetry only; mostly
#       visible to the server's own logs, NOT to the analyzer). Force it with
#       SB_TRAFFIC_MODE=self.
#
#   While the analyzer captures:
#     sudo python3 network_traffic_analyzer.py --interface <iface> --timeout 60
#
# It produces exactly the traffic categories the Stage 1 analyzer reports:
#   TCP   -> SSH handshake, HTTP connection attempt to the lab address
#   UDP   -> DNS lookups
#   ICMP  -> ping
#   ARP   -> neighbor discovery (automatic)
#   TCP flags -> SYN/SYN-ACK/ACK, and RST when a service is absent
#
# Usage:
#   ./scripts/generate-lab-traffic.sh [repeat-count]         # auto mode
#   SB_TRAFFIC_MODE=client ./scripts/generate-lab-traffic.sh # explicit
#   SB_TRAFFIC_MODE=self  ./scripts/generate-lab-traffic.sh  # server only
# (repeat-count defaults to 3, must be an integer 1-100; raise it for volume)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${REPO_DIR}/../lab.env"
if [ ! -f "${LAB_ENV}" ]; then
  echo "[traffic][ERROR] Missing ${LAB_ENV} - lab.env lives at the SecureBank-Enterprise-Lab repo root; clone the whole repo." >&2
  exit 1
fi
# shellcheck disable=SC1091
. "${LAB_ENV}"

SB_FQDN="${SB_HOSTNAME}.${SB_DOMAIN}"

# --- Mode: auto-detect client vs self, allow explicit override -----------------
SB_TRAFFIC_MODE="${SB_TRAFFIC_MODE:-}"
if [ -z "${SB_TRAFFIC_MODE}" ]; then
  if [ "$(hostname)" = "${SB_HOSTNAME}" ]; then
    SB_TRAFFIC_MODE="self"
  else
    SB_TRAFFIC_MODE="client"
  fi
fi
case "${SB_TRAFFIC_MODE}" in
  self|client) ;;
  *) echo "SB_TRAFFIC_MODE must be 'self' or 'client' (got '${SB_TRAFFIC_MODE}')" >&2; exit 1 ;;
esac
echo "[traffic] mode=${SB_TRAFFIC_MODE}  (client = run from Kali/analyzer so the analyzer sees the traffic)"

COUNT="${1:-3}"
if ! [[ "${COUNT}" =~ ^[0-9]+$ ]] || [ "${COUNT}" -lt 1 ]; then
  echo "Usage: $0 [repeat-count]  (integer 1-100)" >&2
  exit 1
fi
if [ "${COUNT}" -gt 100 ]; then
  echo "[traffic] clamping repeat-count to 100" >&2
  COUNT=100
fi

log() { printf '\n\033[1;34m[traffic]\033[0m %s\n' "$*"; }

if ! command -v dig >/dev/null 2>&1; then
  log "dig not found — install it by re-running:  sudo ./scripts/setup.sh  (adds dnsutils)"
fi

if [ "${SB_TRAFFIC_MODE}" = "client" ]; then
  SSH_TARGET="${SB_ADMIN_USER}@${SB_SRV_IP}"
else
  SSH_TARGET="${SB_SRV_IP}"
fi

log "=== 1/5 TCP — SSH handshake to the lab address (${SSH_TARGET}) ==="
# BatchMode prevents password prompts. Even a failed login produces a full
# TCP handshake (SYN -> SYN-ACK -> ACK) on the segment plus an entry in
# /var/log/auth.log — exactly the telemetry Stages 7/8 want. In client mode
# this is a real cross-segment login: provision Kali's key first with
#   ssh-keygen -t ed25519  &&  ssh-copy-id ${SB_ADMIN_USER}@${SB_SRV_IP}
ssh -o BatchMode=yes -o ConnectTimeout=3 "${SSH_TARGET}" true || true

log "=== 2/5 UDP — DNS lookups ==="
# dig queries DNS servers directly (it does NOT use /etc/hosts), so these are
# real UDP 53 queries. They leave via the NAT resolver by default — to make
# them visible on the host-only segment, Module 2/3 adds dnsmasq on the server
# and you switch to:  dig @${SB_SRV_IP} ...
for _ in $(seq 1 "${COUNT}"); do
  dig +short +time=2 +tries=1 "${SB_FQDN}" >/dev/null 2>&1 || true
  dig +short +time=2 +tries=1 deb.debian.org >/dev/null 2>&1 || true
done
if [ "${SB_TRAFFIC_MODE}" = "client" ]; then
  # Client -> server UDP 53 crosses the segment even before dnsmasq exists
  # (the server refuses, which is still visible traffic: ICMP port unreachable).
  dig +short +time=2 +tries=1 "@${SB_SRV_IP}" "${SB_FQDN}" >/dev/null 2>&1 || true
fi

log "=== 3/5 ICMP — ping ${SB_SRV_IP} ==="
ping -c "${COUNT}" -i 1 "${SB_SRV_IP}" >/dev/null 2>&1 || true

log "=== 4/5 TCP — HTTP request to the lab address ==="
# No web service yet (that is Module 3), so curl gets a connection reset.
# That is still real traffic: SYN -> RST, visible in the analyzer's tcp_flags.
# Once nginx exists, this becomes a real HTTP exchange on 80/443.
curl -sS --max-time 5 -o /dev/null "http://${SB_SRV_IP}/" || true

log "=== 5/5 ARP — neighbor discovery ==="
# Each ping to a host on the segment triggers an ARP request for it.
for host in "${SB_SRV_IP}" "${SB_KALI_IP}" "${SB_ANALYZER_IP}"; do
  ping -c 1 -W 1 "${host}" >/dev/null 2>&1 || true
done

log "Done. In the Stage 1 report, look for:"
log "  - protocols:     TCP / UDP / ICMP / ARP rows"
if [ "${SB_TRAFFIC_MODE}" = "client" ]; then
  log "  - top flows:     TCP ${SB_SRV_IP}:<port> <- ${SB_KALI_IP}:<port> (SSH) and :80 (curl)"
else
  log "  - top flows:     TCP ${SB_SRV_IP}:<port> -> ${SB_SRV_IP}:22 (SSH) and :80 (curl)"
fi
log "  - tcp_flags:     handshake flags (S, SA, A) and RST for the closed HTTP port"
log
log "NOTE: in self mode the analyzer usually sees ONLY the ARP step — run this"
log "      script from Kali (client mode) for the full Stage 1 integration test."
