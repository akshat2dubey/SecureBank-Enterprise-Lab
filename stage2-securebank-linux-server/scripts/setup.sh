#!/usr/bin/env bash
#
# SecureBank Linux Server — Module 1: Server Foundation + baseline hardening
# ---------------------------------------------------------------------------
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
#   4. Creates the SecureBank admin user (least privilege via sudo)
#   5. Provisions a local ed25519 keypair for the admin user (used by
#      the traffic script's loopback SSH; client keys come from Kali
#      via ssh-copy-id — see README)                                 (T-10)
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
#   - static lab IP / interface config   -> Module 2 (Network Configuration)
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

# --- 5. Admin keypair (T-10) ----------------------------------------------------------------
# A local ed25519 key makes the traffic script's loopback SSH (BatchMode,
# server -> itself) a genuine auth success and proves key auth works. It is
# NOT a client credential: a private key that never leaves the server cannot
# authenticate Kali. Real client access is provisioned from Kali with
# ssh-keygen + ssh-copy-id (see README 'Admin password & lockout recovery').
ADMIN_HOME="$(getent passwd "${SB_ADMIN_USER}" | cut -d: -f6)"
ADMIN_SSH_DIR="${ADMIN_HOME}/.ssh"
if [ ! -f "${ADMIN_SSH_DIR}/id_ed25519" ]; then
  log "Generating ed25519 keypair for '${SB_ADMIN_USER}' (public key self-authorized)"
  install -d -m 700 -o "${SB_ADMIN_USER}" -g "${SB_ADMIN_USER}" "${ADMIN_SSH_DIR}"
  ssh-keygen -t ed25519 -N "" -C "${SB_ADMIN_USER}@${SB_FQDN}" -f "${ADMIN_SSH_DIR}/id_ed25519" -q
  touch "${ADMIN_SSH_DIR}/authorized_keys"
  chmod 600 "${ADMIN_SSH_DIR}/authorized_keys"
fi
if ! grep -qF "$(cat "${ADMIN_SSH_DIR}/id_ed25519.pub")" "${ADMIN_SSH_DIR}/authorized_keys" 2>/dev/null; then
  cat "${ADMIN_SSH_DIR}/id_ed25519.pub" >> "${ADMIN_SSH_DIR}/authorized_keys"
fi
chown -R "${SB_ADMIN_USER}":"${SB_ADMIN_USER}" "${ADMIN_SSH_DIR}"
chmod 700 "${ADMIN_SSH_DIR}" && chmod 600 "${ADMIN_SSH_DIR}"/id_ed25519 "${ADMIN_SSH_DIR}/authorized_keys"

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
# Self-lockout guard: never apply the firewall while the live SSH session
# would be cut by it. Module 2 has not set the static lab IP yet, so a fresh
# VM may still hold a NAT/DHCP address - applying the drop policy then would
# kill the admin's own session mid-run. Abort with a clear message instead;
# SB_FIREWALL_SKIP=1 is the explicit escape hatch for advanced users.
SKIP_FIREWALL=0
# ss is part of iproute2 (always present on Debian/Ubuntu); '|| true' keeps
# the pipeline from aborting under set -e if the box has no SSH session yet.
session_ip="$(ss -tn state established '( sport = :22 )' 2>/dev/null | awk 'NR>1{print $4}' | head -n1 | sed -E 's/^\[?([0-9.]+).*/\1/' || true)"
if [ -n "${session_ip}" ]; then
  if ip_in_subnet "${session_ip}" "${SB_LAB_SUBNET}"; then
    log "Self-lockout guard: live SSH session from ${session_ip} is inside ${SB_LAB_SUBNET} - safe to apply the firewall."
  elif [ "${SB_FIREWALL_SKIP:-0}" = "1" ]; then
    log "WARNING: live SSH session is from ${session_ip} (outside ${SB_LAB_SUBNET}). SB_FIREWALL_SKIP=1 set - SKIPPING the firewall step. The box is NOT firewalled."
    SKIP_FIREWALL=1
  else
    die "Self-lockout guard: your live SSH session is from ${session_ip}, outside the lab subnet ${SB_LAB_SUBNET}. Applying the default-deny firewall would cut your session. Fix the VM NIC (Module 2 static IP) and re-run, use the VM console, or re-run with SB_FIREWALL_SKIP=1 to skip the firewall for now."
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
sha256sum "${SSHD_CONF_DST}" "${NFT_DST}" "${SYSCTL_DST}" /etc/issue.net "${APT_AUTO_DST}" "${JOURNALD_DST}" /etc/hosts | tee -a "${LOG_FILE}"

# --- 14. Summary ----------------------------------------------------------------------------------------------
log "Module 1 complete on ${SB_FQDN}"
cat <<EOF

  Admin user : ${SB_ADMIN_USER}   (login via SSH, elevate with 'sudo')
  sshd       : active on port 22, root login disabled, access limited to ${SB_ADMIN_USER}
  Firewall   : default-deny (nftables), SSH allowed from ${SB_LAB_SUBNET} only
  Updates    : security-only automatic (unattended-upgrades); reboots manual
  Audit      : persistent journal + SB-DROP firewall logs + forensics kit (C-15)
  Admin key  : ${ADMIN_SSH_DIR}/id_ed25519 (public key: ${ADMIN_SSH_DIR}/id_ed25519.pub)

  Next steps:
    1. If the password prompt above was skipped:  passwd ${SB_ADMIN_USER}
       (choose a strong password - see README 'Admin password & lockout recovery')
    2. Find the VM's current IP:                  ip -4 addr show
    3. From Kali:                                 ssh ${SB_ADMIN_USER}@<ip>
       (first run:  ssh-keygen -t ed25519  then  ssh-copy-id ${SB_ADMIN_USER}@<ip>
        - Kali's key, not the server's own key)
    4. Verify this module:                        ./tests/module1-verify.sh
    5. If a kernel was upgraded, reboot the VM before continuing.
    6. Then read docs/architecture.md and start Module 2.
EOF
