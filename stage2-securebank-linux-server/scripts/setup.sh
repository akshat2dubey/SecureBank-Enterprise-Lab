#!/usr/bin/env bash
#
# SecureBank Linux Server — Module 1: Server Foundation
# ------------------------------------------------------
# Run on the SecureBank lab VM (Debian 12 / Ubuntu 24.04), as root:
#     sudo -i
#     ./scripts/setup.sh
#
# What this module does:
#   1. Verifies OS + root
#   2. Installs the minimal base package set
#   3. Sets hostname + lab /etc/hosts entries (identity groundwork)
#   4. Creates the SecureBank admin user (least privilege via sudo)
#   5. Applies the Module 1 SSH baseline (root login off; password auth TEMPORARY)
#   6. Sets timezone to UTC (comparable logs across the lab)
#
# Deliberately NOT done here (later modules):
#   - static lab IP / interface config   -> Module 2 (Network Configuration)
#   - full hardening (firewall, key-only SSH, fail2ban) -> Module 4
#   - logging/telemetry policy           -> Module 5
#
# The script is idempotent: safe to run more than once.

set -euo pipefail

# --- Tune via environment if you need to (defaults match docs/network-design.md)
SB_ADMIN_USER="${SB_ADMIN_USER:-securebank-admin}"
SB_TIMEZONE="${SB_TIMEZONE:-UTC}"
SB_HOSTNAME="securebank-srv"
SB_DOMAIN="securebank.lab"
SB_FQDN="${SB_HOSTNAME}.${SB_DOMAIN}"

BASE_PACKAGES=(
  openssh-server   # remote admin access
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
)

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOSTS_TEMPLATE="${REPO_DIR}/configs/etc/hosts"
SSHD_CONF_SRC="${REPO_DIR}/configs/etc/ssh/sshd_config.d/99-securebank.conf"
SSHD_CONF_DST="/etc/ssh/sshd_config.d/99-securebank.conf"

log() { printf '\n\033[1;34m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup][ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Prerequisites -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root (e.g. 'sudo -i')."

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) : ;;
  *) die "Unsupported OS '${ID}'. Module 1 targets Debian 12 / Ubuntu 24.04." ;;
esac

# --- 1. Base packages -------------------------------------------------------------
log "Installing base packages: ${BASE_PACKAGES[*]}"
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y "${BASE_PACKAGES[@]}"

# --- 2. Hostname -------------------------------------------------------------------
log "Setting hostname to '${SB_HOSTNAME}' (FQDN: ${SB_FQDN})"
hostnamectl set-hostname "${SB_HOSTNAME}" || echo "${SB_HOSTNAME}" > /etc/hostname

# --- 3. /etc/hosts (lab identity groundwork; reachability comes in Module 2) ----------
if [ -f "${HOSTS_TEMPLATE}" ]; then
  log "Merging lab host entries from ${HOSTS_TEMPLATE}"
  while IFS= read -r line || [ -n "${line}" ]; do
    case "${line}" in
      \#*|'') continue ;;
    esac
    ip="${line%%[[:space:]]*}"
    grep -qE "^${ip}[[:space:]]" /etc/hosts && continue
    echo "${line}" >> /etc/hosts
  done < "${HOSTS_TEMPLATE}"
fi

# --- 4. Admin user --------------------------------------------------------------------
if ! id "${SB_ADMIN_USER}" >/dev/null 2>&1; then
  log "Creating admin user '${SB_ADMIN_USER}' (home, bash, sudo group)"
  useradd --create-home --shell /bin/bash --groups sudo "${SB_ADMIN_USER}"
else
  log "User '${SB_ADMIN_USER}' already exists — ensuring sudo membership"
  usermod -aG sudo "${SB_ADMIN_USER}"
fi

case "$(passwd -S "${SB_ADMIN_USER}" 2>/dev/null | awk '{print $2}')" in
  P) log "Password already set for '${SB_ADMIN_USER}'" ;;
  *)
    log "No password set yet for '${SB_ADMIN_USER}'."
    log "Set one now:  passwd ${SB_ADMIN_USER}"
    ;;
esac

# --- 5. SSH baseline ---------------------------------------------------------------------
if [ -f "${SSHD_CONF_SRC}" ]; then
  log "Installing SecureBank sshd baseline -> ${SSHD_CONF_DST}"
  cp "${SSHD_CONF_SRC}" "${SSHD_CONF_DST}"
  chmod 0644 "${SSHD_CONF_DST}"
fi

if sshd -t; then
  systemctl enable --now ssh
  systemctl restart ssh
  log "sshd validated ('sshd -t') and restarted"
else
  die "sshd -t failed — inspect ${SSHD_CONF_DST} before continuing"
fi

# --- 6. Timezone ----------------------------------------------------------------------------
log "Setting timezone to ${SB_TIMEZONE} (UTC keeps timestamps comparable for Stages 7/8)"
timedatectl set-timezone "${SB_TIMEZONE}" 2>/dev/null || \
  ln -sf "/usr/share/zoneinfo/${SB_TIMEZONE}" /etc/localtime

# --- 7. Summary -------------------------------------------------------------------------------
log "Module 1 complete on ${SB_FQDN}"
cat <<EOF

  Admin user : ${SB_ADMIN_USER}   (login via SSH, elevate with 'sudo')
  sshd       : active on port 22, root login disabled

  Next steps:
    1. If the password prompt above was skipped:  passwd ${SB_ADMIN_USER}
    2. Find the VM's current IP:                  ip -4 addr show
    3. From Kali:                                 ssh ${SB_ADMIN_USER}@<ip>
    4. Verify this module:                        ./tests/module1-verify.sh
    5. Then read docs/architecture.md and start Module 2.
EOF
