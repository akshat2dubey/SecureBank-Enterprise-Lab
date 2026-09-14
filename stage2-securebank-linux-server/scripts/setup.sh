#!/usr/bin/env bash
#
# SecureBank Linux Server — Modules 1+2: Server Foundation, baseline hardening,
# static lab addressing
# ------------------------------------------------------------------------------
# Run on the SecureBank lab VM (Debian 12 / Ubuntu 24.04), as root:
#     sudo -i
#     ./scripts/setup.sh
#
# What this module does:
#   1. Verifies OS + root
#   2. Updates the base OS (one-time full-upgrade) and installs the minimal
#      base package set (--no-install-recommends)                    (T-02)
#   3. Sets hostname + manages the lab /etc/hosts block, generated from
#      lab.env at the repo root (single source of truth)             (T-05)
#   3b. Detects the lab NIC and applies the static lab address plan from
#       lab.env: IPv4 + IPv6 ULA, via netplan or systemd-networkd    (C-16)
#   4. Creates the SecureBank admin user (least privilege via sudo)
#   5. Ensures the admin's ~/.ssh exists and is correctly permissioned;
#      NO server-side key generation — admin keys are generated ON KALI
#      and installed with ssh-copy-id (Kali is the sole key origin)  (T-10)
#   6. Applies the Module 1 SSH baseline (root login off; password auth
#      TEMPORARY; access limited to the admin account)               (T-01/T-11)
#   7. Installs the authorized-use banner                            (T-12)
#   8. Applies the default-deny nftables firewall (IPv4 + IPv6)      (T-06/T-07)
#   9. Applies the sysctl network-hardening baseline                 (T-09)
#  10. Sets timezone to UTC and enables NTP                          (T-08)
#  11. Enables security-only automatic updates (unattended-upgrades) (C-13)
#  12. Makes the journal persistent for host auditing                (C-15)
#  13. Records an audit trail + applied-config hashes                (T-03)
#
# Deliberately NOT done here (later modules):
#   - key-only SSH, fail2ban, AppArmor profiles -> Module 4 (auditing
#     strategy documented in docs/host-auditing.md; auditd deferred)
#   - logging/telemetry policy           -> Module 5
#
# The script is idempotent: safe to run more than once.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Single source of truth: lab.env at the repo root ----------------------
LAB_ENV="${REPO_DIR}/../lab.env"
if [ ! -f "${LAB_ENV}" ]; then
  echo "[setup][ERROR] Missing ${LAB_ENV} - lab.env lives at the SecureBank-Enterprise-Lab repo root; clone the whole repo." >&2
  exit 1
fi
# shellcheck disable=SC1091
. "${LAB_ENV}"

SB_FQDN="${SB_HOSTNAME}.${SB_DOMAIN}"

BASE_PACKAGES=(
  openssh-server   # remote admin access
  nftables         # default-deny firewall (T-06)
  sudo             # least-privilege elevation for the admin user
  curl wget        # HTTP clients (Stage 1 traffic, later health checks)
  dnsutils         # dig/nslookup — DNS lookups (UDP traffic Stage 1 can see)
  git              # version control (future automation / stages)
  ca-certificates  # TLS trust store
  gnupg            # signature verification (apt keys)
  htop             # interactive process/top view (learning + ops)
  nano             # beginner-friendly editor
  tree             # visualize the filesystem tree
  rsync            # file transfer / backups (later modules)
  unattended-upgrades  # security-only automatic updates (C-13)
)

SSHD_CONF_SRC="${REPO_DIR}/configs/etc/ssh/sshd_config.d/99-securebank.conf"
SSHD_CONF_DST="/etc/ssh/sshd_config.d/99-securebank.conf"
NFT_SRC="${REPO_DIR}/configs/etc/nftables.conf"
NFT_DST="/etc/nftables.conf"
SYSCTL_SRC="${REPO_DIR}/configs/etc/sysctl.d/99-securebank.conf"
SYSCTL_DST="/etc/sysctl.d/99-securebank.conf"
ISSUE_SRC="${REPO_DIR}/configs/etc/issue.net"
APT_AUTO_SRC="${REPO_DIR}/configs/etc/apt/apt.conf.d/50securebank-unattended"
APT_AUTO_DST="/etc/apt/apt.conf.d/50securebank-unattended"
JOURNALD_SRC="${REPO_DIR}/configs/etc/systemd/journald.conf.d/99-securebank.conf"
JOURNALD_DST="/etc/systemd/journald.conf.d/99-securebank.conf"
NETPLAN_SRC="${REPO_DIR}/configs/etc/netplan/99-securebank.yaml"
NETPLAN_DST="/etc/netplan/99-securebank.yaml"
NETWORKD_SRC="${REPO_DIR}/configs/etc/systemd/network/10-securebank-lab.network"
NETWORKD_DST="/etc/systemd/network/10-securebank-lab.network"
CLOUD_NET_DST="/etc/cloud/cloud.cfg.d/99-securebank-network.cfg"
HOSTS_BEGIN="# BEGIN securebank.lab (managed by scripts/setup.sh - do not edit)"
HOSTS_END="# END securebank.lab"
LOG_DIR="${REPO_DIR}/logs"

log() { printf '\n\033[1;34m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup][ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Firewall self-lockout guard helpers --------------------------------------
ipv4_to_int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

ip_in_subnet() {
  # ip_in_subnet <ipv4> <cidr> — exit 0 if the IP is inside the network
  local ip="$1" cidr="$2" net prefix mask
  net="${cidr%/*}"
  prefix="${cidr#*/}"
  [ "${prefix}" -ge 0 ] && [ "${prefix}" -le 32 ] || return 1
  mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
  [ $(( $(ipv4_to_int "${ip}") & mask )) -eq $(( $(ipv4_to_int "${net}") & mask )) ]
}

# --- SSH-session address helpers (fail-closed self-lockout guards) -------------
# Each guard needs a DIFFERENT end of the SSH connection:
#   * the firewall guard asks "which CLIENT address would be cut?" -> the
#     REMOTE peer;
#   * the Module 2 static-address guard asks "which LOCAL address does this
#     session ride?" -> this host's own side (the address being replaced).
# ss -tnpe prints 'peer:PORT' / 'local:PORT' explicitly, so nothing depends
# on fragile column positions. IPv6 endpoints print as [addr]:PORT.
# The one socket layout ss has kept for decades: Local comes before Peer,
# and the local endpoint is the field ENDING in ":22" (the sport = :22
# filter guarantees it). A leading "Netid" column may or may not be present
# and extended columns are appended after Peer — so no fixed field numbers
# and no dependence on "local:"/"peer:" prefixes: find the ":22" field and
# take the requested side. iproute2 on the target platforms (Debian 12 /
# Ubuntu 24.04) prints IPv6 endpoints as [addr]:port; brackets and %-zone
# suffixes are stripped so the result is always a plain address (or empty,
# which every caller must treat as "cannot determine" = fail closed).
_ss_ssh_field() {
  # _ss_ssh_field <local|peer> — plain address of that side of the first
  # established sshd connection (ss -H -n: no header line, no name lookups).
  ss -H -n -t state established '( sport = :22 )' 2>/dev/null \
    | awk -v side="$1" '{
        for (i = 1; i <= NF; i++) {
          if ($i ~ /:22$/) {
            if (side == "local") print $i
            else if (side == "peer" && i < NF) print $(i + 1)
            exit
          }
        }
      }' \
    | sed -E 's/^(local|peer)://; s/:[0-9]+$//; s/^\[(.*)\]$/\1/; s/%[a-zA-Z0-9._-]+$//' \
    || true
}
parse_peer() {
  # parse_peer — the REMOTE peer address of the first established
  # SSH-session connection (empty if none / undeterminable).
  _ss_ssh_field peer
}
parse_local() {
  # parse_local — the LOCAL address of the first established
  # SSH-session connection (empty if none / undeterminable).
  _ss_ssh_field local
}
ipv6_in_subnet() {
  # ipv6_in_subnet <ipv6> <cidr> — membership via python3's ipaddress module
  # (stdlib; the same interpreter the Stage 1/7 pipeline already requires).
  # Anything unparseable -> non-zero, so callers fail closed.
  python3 - "$1" "$2" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False)
PY
}
peer_addr_in_subnet() {
  # peer_addr_in_subnet <addr> <v4-cidr> <v6-cidr> — true if the address is
  # IPv4 inside the v4 subnet or IPv6 inside the v6 subnet. Anything else
  # (empty, garbage, scope leftovers) returns 1 = fail closed.
  local addr="$1" v4="$2" v6="$3"
  case "${addr}" in
    *:*) ipv6_in_subnet "${addr}" "${v6}" ;;
    *.*) ip_in_subnet "${addr}" "${v4}" ;;
    *)   return 1 ;;
  esac
}

# --- 0. Prerequisites ---------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root (e.g. 'sudo -i')."

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) : ;;
  *) die "Unsupported OS '${ID}'. Module 1 targets Debian 12 / Ubuntu 24.04." ;;
esac

# --- 0b. Audit trail (T-03) ----------------------------------------------------
# Everything below is teed into a timestamped log under logs/ (git-ignored).
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/setup-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "${LOG_FILE}") 2>&1
log "Audit trail: ${LOG_FILE}"

# --- 1. Base packages (T-02) -----------------------------------------------------
log "Updating package lists"
DEBIAN_FRONTEND=noninteractive apt-get update -y

log "One-time full upgrade - the box starts patched"
DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y

log "Installing base packages (no recommends): ${BASE_PACKAGES[*]}"
DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y "${BASE_PACKAGES[@]}"

# --- 2. Hostname -------------------------------------------------------------------
log "Setting hostname to '${SB_HOSTNAME}' (FQDN: ${SB_FQDN})"
hostnamectl set-hostname "${SB_HOSTNAME}" || echo "${SB_HOSTNAME}" > /etc/hostname

# --- 3. /etc/hosts managed block (T-05) ----------------------------------------------
# Generated from lab.env at the repo root; the managed block is replaced on
# every run (BEGIN/END markers), so stale lab entries can never survive a re-run.
log "Managing lab /etc/hosts block (subnet ${SB_LAB_SUBNET})"
hosts_tmp="$(mktemp)"
awk -v begin="${HOSTS_BEGIN}" -v end="${HOSTS_END}" '
  index($0, begin) { skip=1; next }
  index($0, end)   { skip=0; next }
  !skip' /etc/hosts > "${hosts_tmp}"
cat >> "${hosts_tmp}" <<EOF
${HOSTS_BEGIN}
${SB_SRV_IP} ${SB_HOSTNAME} ${SB_FQDN}
${SB_KALI_IP} ${SB_KALI_HOSTNAME} ${SB_KALI_HOSTNAME}.${SB_DOMAIN}
${SB_ANALYZER_IP} ${SB_ANALYZER_HOSTNAME} ${SB_ANALYZER_HOSTNAME}.${SB_DOMAIN}
${HOSTS_END}
EOF
grep -qE '^127\.0\.0\.1[[:space:]]' "${hosts_tmp}" || sed -i '1i 127.0.0.1 localhost' "${hosts_tmp}"
mv "${hosts_tmp}" /etc/hosts

# --- 3b. Static lab addressing — Module 2 (C-16) -------------------------------------
# The plan (docs/network-design.md §2/§4b): the host-only NIC holds the static
# lab address (IPv4 + IPv6 ULA from lab.env); the NAT NIC is untouched and
# keeps DHCP for updates. Backend is detected at runtime: netplan when
# present, else systemd-networkd — no ifupdown support (deliberate).
log "Module 2: static lab addressing (C-16)"

# Runtime NIC detection — the lab NIC is the one already holding an address
# inside SB_LAB_SUBNET. Never hardcoded; follows lab.env on every run.
LAB_IFACE=""
for iface in $(ls /sys/class/net | grep -v '^lo$'); do
  addr_in_lab="$(ip -4 addr show dev "${iface}" scope global 2>/dev/null | awk '/inet /{print $2}' | while read -r cidr; do if ip_in_subnet "${cidr%%/*}" "${SB_LAB_SUBNET}"; then echo yes; break; fi; done)"
  if [ "${addr_in_lab}" = "yes" ]; then
    LAB_IFACE="${iface}"
    break
  fi
done
if [ -z "${LAB_IFACE}" ]; then
  die "Could not detect the lab NIC (no interface holds an address in ${SB_LAB_SUBNET}). Connect the host-only NIC, or re-run with SB_NET_SKIP=1 to skip static addressing (advanced)."
fi
log "Lab NIC detected: ${LAB_IFACE} (address inside ${SB_LAB_SUBNET})"

# Render-time values: prefix lengths from the (overridable) lab.env subnets
LAB_PREFIX="${SB_LAB_SUBNET##*/}"
IPV6_PREFIX="${SB_IPV6_LAB_SUBNET##*/}"

# Session-drop guard (Module 1's self-lockout-guard pattern, extended):
# applying the static address only interrupts this session if the session
# rides the lab NIC but its source address is NOT the final SB_SRV_IP —
# i.e. you SSH in via a temporary DHCP address on the host-only segment.
# Escape hatches (mirroring SB_FIREWALL_SKIP): SB_NET_SKIP=1 skips static
# addressing entirely; add SB_NET_FORCE=1 to apply it anyway and accept the
# session drop.
SB_NET_SKIP="${SB_NET_SKIP:-0}"
# This guard is about THIS HOST's address change, so it deliberately inspects
# the LOCAL side of the session (which local address the admin rides); the
# firewall guard below inspects the REMOTE peer instead (see its comment).
session_ip="$(parse_local)"
if [ -n "${session_ip}" ] && ip_in_subnet "${session_ip}" "${SB_LAB_SUBNET}" && [ "${session_ip}" != "${SB_SRV_IP}" ]; then
  if [ "${SB_NET_SKIP}" = "1" ] && [ -n "${SB_NET_FORCE:-}" ]; then
    log "WARNING: SB_NET_SKIP=1 + SB_NET_FORCE=1 - applying static ${SB_SRV_IP} on ${LAB_IFACE} anyway. Expect this SSH session to drop; reconnect to ${SB_SRV_IP} (the VM console always works)."
  else
    die "Session-drop guard: your live SSH session rides local address ${session_ip} on the lab NIC (${LAB_IFACE}), but the static plan sets ${SB_SRV_IP}. Applying it would cut this session. Run from the VM console, or re-run with SB_NET_SKIP=1 (plus SB_NET_FORCE=1 to accept the drop)."
  fi
fi

if [ "${SB_NET_SKIP:-0}" = "1" ] && [ -z "${SB_NET_FORCE:-}" ]; then
  log "Static addressing SKIPPED (SB_NET_SKIP=1). The lab NIC keeps its current (DHCP) address; the firewall's subnet rule still applies."
else
  # Backend detection: netplan wins when present (Ubuntu), else systemd-networkd
  # ('is-enabled' is checked loosely — on a disabled networkd the enable below
  # turns it on; 'static' is a valid preset). If neither backend exists, abort
  # rather than guess — no ifupdown support (deliberate).
  NET_BACKEND=""
  if command -v netplan >/dev/null 2>&1; then
    NET_BACKEND="netplan"
  elif [ -d /etc/systemd/network ] && ! systemctl is-enabled systemd-networkd 2>/dev/null | grep -qx 'masked'; then
    NET_BACKEND="networkd"
  else
    die "No supported network backend found (need netplan or systemd-networkd). Module 2 does not support ifupdown — see docs/network-design.md."
  fi
  log "Network backend detected: ${NET_BACKEND}"

  if [ "${NET_BACKEND}" = "netplan" ]; then
    log "Rendering netplan config -> ${NETPLAN_DST} (NIC ${LAB_IFACE}, ${SB_SRV_IP}/${LAB_PREFIX} + ${SB_SRV_IPV6}/${IPV6_PREFIX})"
    sed -e "s|@SB_LAB_IFACE@|${LAB_IFACE}|g" \
        -e "s|@SB_LAB_SUBNET@|${SB_LAB_SUBNET}|g" \
        -e "s|@SB_IPV6_LAB_SUBNET@|${SB_IPV6_LAB_SUBNET}|g" \
        -e "s|@SB_SRV_IP@|${SB_SRV_IP}|g" \
        -e "s|@SB_LAB_PREFIX@|${LAB_PREFIX}|g" \
        -e "s|@SB_SRV_IPV6@|${SB_SRV_IPV6}|g" \
        -e "s|@SB_IPV6_PREFIX@|${IPV6_PREFIX}|g" \
        "${NETPLAN_SRC}" > "${NETPLAN_DST}"
    chmod 0600 "${NETPLAN_DST}"   # netplan refuses world-readable files
    if command -v cloud-init >/dev/null 2>&1; then
      log "cloud-init present - installing the network opt-out -> ${CLOUD_NET_DST}"
      install -m 0644 "${REPO_DIR}/configs/etc/cloud/cloud.cfg.d/99-securebank-network.cfg" "${CLOUD_NET_DST}"
    fi
    log "Applying netplan (the session-drop guard above already cleared this)"
    netplan apply
  else
    log "Rendering systemd-networkd config -> ${NETWORKD_DST} (NIC ${LAB_IFACE}, ${SB_SRV_IP}/${LAB_PREFIX} + ${SB_SRV_IPV6}/${IPV6_PREFIX})"
    sed -e "s|@SB_LAB_IFACE@|${LAB_IFACE}|g" \
        -e "s|@SB_LAB_SUBNET@|${SB_LAB_SUBNET}|g" \
        -e "s|@SB_IPV6_LAB_SUBNET@|${SB_IPV6_LAB_SUBNET}|g" \
        -e "s|@SB_SRV_IP@|${SB_SRV_IP}|g" \
        -e "s|@SB_LAB_PREFIX@|${LAB_PREFIX}|g" \
        -e "s|@SB_SRV_IPV6@|${SB_SRV_IPV6}|g" \
        -e "s|@SB_IPV6_PREFIX@|${IPV6_PREFIX}|g" \
        "${NETWORKD_SRC}" > "${NETWORKD_DST}"
    chown root:root "${NETWORKD_DST}" && chmod 0644 "${NETWORKD_DST}"
    systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
    log "Restarting systemd-networkd (the session-drop guard above already cleared this)"
    systemctl restart systemd-networkd
  fi

  # Confirm effective state, not file existence (golden rule 6)
  if ip -4 addr show dev "${LAB_IFACE}" | grep -q "${SB_SRV_IP}/"; then
    log "Effective IPv4 on ${LAB_IFACE}: ${SB_SRV_IP}/${LAB_PREFIX} confirmed"
  else
    die "Static IPv4 did not take effect on ${LAB_IFACE} (expected ${SB_SRV_IP}/${LAB_PREFIX}). Inspect 'ip -4 addr show ${LAB_IFACE}' and the ${NET_BACKEND} config."
  fi
  if ip -6 addr show dev "${LAB_IFACE}" | grep -qw "${SB_SRV_IPV6}"; then
    log "Effective IPv6 on ${LAB_IFACE}: ${SB_SRV_IPV6}/${IPV6_PREFIX} confirmed"
  else
    die "Static IPv6 did not take effect on ${LAB_IFACE} (expected ${SB_SRV_IPV6}/${IPV6_PREFIX}). Inspect 'ip -6 addr show ${LAB_IFACE}'."
  fi
fi

# --- 4. Admin user ----------------------------------------------------------------------
if ! id "${SB_ADMIN_USER}" >/dev/null 2>&1; then
  log "Creating admin user '${SB_ADMIN_USER}' (home, bash, sudo group)"
  useradd --create-home --shell /bin/bash --groups sudo "${SB_ADMIN_USER}"
else
  log "User '${SB_ADMIN_USER}' already exists - ensuring sudo membership"
  usermod -aG sudo "${SB_ADMIN_USER}"
fi

case "$(passwd -S "${SB_ADMIN_USER}" 2>/dev/null | awk '{print $2}')" in
  P) log "Password already set for '${SB_ADMIN_USER}'" ;;
  *)
    log "No password set yet for '${SB_ADMIN_USER}'."
    log "Set one now:  passwd ${SB_ADMIN_USER}"
    ;;
esac

# --- 5. Admin SSH directory — no server-side keys (T-10) ---------------------------------------
# Kali is the SOLE origin of admin keys: keys are generated on Kali and
# installed with `ssh-copy-id ${SB_ADMIN_USER}@${SB_SRV_IP}` (README). This
# deliberately does NOT generate a server-side keypair: a self-authorized,
# server-generated private key has no legitimate use — it cannot authenticate
# Kali — and it muddies key provenance for Module 4's key-only switch and
# Stage 8 investigations. Existing keys are left untouched.
ADMIN_HOME="$(getent passwd "${SB_ADMIN_USER}" | cut -d: -f6)"
ADMIN_SSH_DIR="${ADMIN_HOME}/.ssh"
if [ ! -d "${ADMIN_SSH_DIR}" ]; then
  log "Creating ${ADMIN_SSH_DIR} (no key generated here - Kali is the sole key origin)"
  install -d -m 700 -o "${SB_ADMIN_USER}" -g "${SB_ADMIN_USER}" "${ADMIN_SSH_DIR}"
fi
if [ -f "${ADMIN_SSH_DIR}/authorized_keys" ]; then
  chmod 600 "${ADMIN_SSH_DIR}/authorized_keys"
  chown "${SB_ADMIN_USER}":"${SB_ADMIN_USER}" "${ADMIN_SSH_DIR}/authorized_keys"
  log "authorized_keys present (Kali-provisioned keys untouched)"
else
  log "No authorized_keys yet - provision admin access from Kali:"
  log "    ssh-keygen -t ed25519  &&  ssh-copy-id ${SB_ADMIN_USER}@${SB_SRV_IP}"
fi

# --- 6. SSH baseline (T-01/T-11) -----------------------------------------------------------------
log "Installing sshd baseline -> ${SSHD_CONF_DST} (AllowUsers rendered from lab.env)"
sed "s/^AllowUsers .*/AllowUsers ${SB_ADMIN_USER}/" "${SSHD_CONF_SRC}" > "${SSHD_CONF_DST}"
chown root:root "${SSHD_CONF_DST}"
chmod 0644 "${SSHD_CONF_DST}"

# --- 7. Authorized-use banner (T-12) --------------------------------------------------------------
log "Installing authorized-use banner (/etc/issue.net + console /etc/issue)"
install -m 0644 "${ISSUE_SRC}" /etc/issue.net
cp /etc/issue.net /etc/issue

if sshd -t; then
  systemctl enable --now ssh
  systemctl restart ssh
  log "sshd validated ('sshd -t') and restarted"
else
  die "sshd -t failed - inspect ${SSHD_CONF_DST} before continuing"
fi

# --- 8. Default-deny firewall (T-06/T-07) -----------------------------------------------------------
# Self-lockout guard: never apply the firewall while a live SSH session's
# REMOTE PEER would be cut by it. The peer — not the local socket address —
# is what decides who loses their connection: the firewall filters source
# addresses of incoming connections, and the local address is exactly what
# Module 2 changes on purpose. SB_FIREWALL_SKIP=1 is the explicit escape
# hatch for advanced users.
SKIP_FIREWALL=0
# The firewall guard validates the REMOTE PEER of the admin's SSH session
# (who would be cut by default-deny), NOT the local socket address — the
# local address is what the Module 2 static plan changes on purpose. Fail
# closed: if a session exists but its peer cannot be determined, refuse to
# apply the firewall. ss is part of iproute2 (always present); '|| true'
# keeps the pipelines alive under set -e when no SSH session is live.
session_peer="$(parse_peer)"
if [ -n "${session_peer}" ]; then
  if peer_addr_in_subnet "${session_peer}" "${SB_LAB_SUBNET}" "${SB_IPV6_LAB_SUBNET}"; then
    log "Self-lockout guard: SSH peer ${session_peer} is inside the lab subnets - safe to apply the firewall."
  elif [ "${SB_FIREWALL_SKIP:-0}" = "1" ]; then
    log "WARNING: SSH peer ${session_peer} is outside ${SB_LAB_SUBNET} (or undeterminable). SB_FIREWALL_SKIP=1 set - SKIPPING the firewall step. The box is NOT firewalled."
    SKIP_FIREWALL=1
  else
    die "Self-lockout guard: your SSH session's peer address (${session_peer}) is outside the lab subnet ${SB_LAB_SUBNET}. Applying the default-deny firewall would cut your session. Fix the VM NIC (Module 2 static IP) and re-run, use the VM console, or re-run with SB_FIREWALL_SKIP=1 to skip the firewall for now."
  fi
else
  session_local="$(parse_local)"
  if [ -n "${session_local}" ]; then
    if [ "${SB_FIREWALL_SKIP:-0}" = "1" ]; then
      log "WARNING: an SSH session is live but its peer address could not be determined. SB_FIREWALL_SKIP=1 set - SKIPPING the firewall step. The box is NOT firewalled."
      SKIP_FIREWALL=1
    else
      die "Self-lockout guard: an SSH session is live, but its peer address could not be determined - refusing to apply the firewall (fail closed). Run from the VM console, or re-run with SB_FIREWALL_SKIP=1 to skip the firewall for now."
    fi
  fi
fi

if [ "${SKIP_FIREWALL}" = "1" ]; then
  log "Firewall SKIPPED (SB_FIREWALL_SKIP=1). Re-run setup (or apply configs/etc/nftables.conf manually) once the NIC is on ${SB_LAB_SUBNET}."
else
  log "Applying default-deny nftables firewall (IPv4 + IPv6; subnet from lab.env)"
  sed "s|@SB_LAB_SUBNET@|${SB_LAB_SUBNET}|" "${NFT_SRC}" > "${NFT_DST}"
  nft -c -f "${NFT_DST}" || die "nftables config invalid - fix ${NFT_SRC} before continuing"
  nft -f "${NFT_DST}"
  systemctl enable --now nftables
  log "Firewall active. NOTE: inbound is default-deny - keep SSH on the lab segment (${SB_LAB_SUBNET}) or use the VM console."
fi

# --- 9. sysctl baseline (T-09) -------------------------------------------------------------------------
log "Applying sysctl network-hardening baseline"
install -m 0644 "${SYSCTL_SRC}" "${SYSCTL_DST}"
sysctl --system >/dev/null

# --- 10. Timezone + NTP (T-08) --------------------------------------------------------------------------
log "Setting timezone to ${SB_TIMEZONE} (UTC keeps timestamps comparable for Stages 7/8)"
timedatectl set-timezone "${SB_TIMEZONE}" 2>/dev/null || \
  ln -sf "/usr/share/zoneinfo/${SB_TIMEZONE}" /etc/localtime

log "Enabling NTP (systemd-timesyncd) so the clock is correct, not just UTC"
timedatectl set-ntp true 2>/dev/null || \
  log "NTP enable failed - set it manually (isolated lab may need a NAT/NTP decision; docs/security-review.md T-08)"

# --- 11. Security-only automatic updates (C-13) ------------------------------------------------------------
log "Installing unattended-upgrades config -> ${APT_AUTO_DST}"
install -m 0644 "${APT_AUTO_SRC}" "${APT_AUTO_DST}"
log "Security updates are automatic; reboots are NOT automatic (admin's call). Actions land in journald/syslog for Stage 7/8."

# --- 12. Persistent journal for host auditing (C-15) ---------------------------------------------------------
log "Enabling persistent journal -> ${JOURNALD_DST}"
mkdir -p /etc/systemd/journald.conf.d
install -m 0644 "${JOURNALD_SRC}" "${JOURNALD_DST}"
systemctl restart systemd-journald
log "journald now keeps logs on disk (survives reboot) - source for the Stage 7 syslog forwarder."

# --- 13. Baseline snapshot + hashes (T-02/T-03) ------------------------------------------------------------
log "Recording package baseline + applied-config hashes"
dpkg --get-selections > "${LOG_DIR}/package-baseline-$(date +%Y%m%d-%H%M%S).txt"
APPLIED_NET_FILE=""
if [ "${SB_NET_SKIP:-0}" = "1" ] && [ -z "${SB_NET_FORCE:-}" ]; then
  : # skipped — nothing to hash
elif [ "${NET_BACKEND:-}" = "netplan" ]; then
  APPLIED_NET_FILE="${NETPLAN_DST}"
elif [ "${NET_BACKEND:-}" = "networkd" ]; then
  APPLIED_NET_FILE="${NETWORKD_DST}"
fi
if [ -n "${APPLIED_NET_FILE}" ]; then
  sha256sum "${SSHD_CONF_DST}" "${NFT_DST}" "${SYSCTL_DST}" /etc/issue.net "${APT_AUTO_DST}" "${JOURNALD_DST}" /etc/hosts "${APPLIED_NET_FILE}" | tee -a "${LOG_FILE}"
else
  sha256sum "${SSHD_CONF_DST}" "${NFT_DST}" "${SYSCTL_DST}" /etc/issue.net "${APT_AUTO_DST}" "${JOURNALD_DST}" /etc/hosts | tee -a "${LOG_FILE}"
fi

# --- 14. Summary ----------------------------------------------------------------------------------------------
log "Modules 1+2 complete on ${SB_FQDN}"
cat <<EOF

  Admin user : ${SB_ADMIN_USER}   (login via SSH, elevate with 'sudo')
  sshd       : active on port 22, root login disabled, access limited to ${SB_ADMIN_USER}
  Lab NIC    : ${LAB_IFACE:-?} holds ${SB_SRV_IP}/${LAB_PREFIX:-24} + ${SB_SRV_IPV6}/${IPV6_PREFIX:-64} (backend: ${NET_BACKEND:-skipped})
  Firewall   : default-deny (nftables), SSH allowed from ${SB_LAB_SUBNET} only
  Updates    : security-only automatic (unattended-upgrades); reboots manual
  Audit      : persistent journal + SB-DROP firewall logs + forensics kit (C-15)
  Admin keys : server generates NONE - Kali is the sole key origin (T-10)

  Next steps:
    1. If the password prompt above was skipped:  passwd ${SB_ADMIN_USER}
       (choose a strong password - see README 'Admin password & lockout recovery')
    2. From Kali:                                 ssh ${SB_ADMIN_USER}@${SB_SRV_IP}
       (first run:  ssh-keygen -t ed25519  then  ssh-copy-id ${SB_ADMIN_USER}@${SB_SRV_IP})
    3. Verify Modules 1+2:                        ./tests/module1-verify.sh
    4. If a kernel was upgraded, reboot the VM before continuing.
    5. Peer VMs: render their static-config snippets and copy them over:
         ./scripts/render-peer-configs.sh   # -> outputs/peer-configs/
    6. Then read docs/architecture.md and start Module 3.
EOF
