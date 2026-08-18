#!/usr/bin/env bash
#
# SecureBank Linux Server — Module 1 verification
# ------------------------------------------------
# Run as root on the SecureBank lab VM:
#     sudo ./tests/module1-verify.sh
# Prints PASS/FAIL per check; exits 0 only if everything passes.
#
# Covers the Module 1 foundation AND the baseline hardening applied by
# scripts/setup.sh (see docs/security-review.md). Verifies *effective*
# settings (sshd -T, nft list ruleset, sysctl) and config *content*
# (rendered drop-in, firewall, sysctl, banner, hosts block) — not just
# file existence (T-04).

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${REPO_DIR}/../lab.env"
if [ ! -f "${LAB_ENV}" ]; then
  echo "[verify][ERROR] Missing ${LAB_ENV} - lab.env lives at the SecureBank-Enterprise-Lab repo root; clone the whole repo." >&2
  exit 1
fi
# shellcheck disable=SC1091
. "${LAB_ENV}"

HOSTS_BEGIN="# BEGIN securebank.lab (managed by scripts/setup.sh - do not edit)"
HOSTS_END="# END securebank.lab"

PASS=0
FAIL=0

ok()  { printf '\033[32m[PASS]\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '\033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

# check <description> <command...>  — passes if the command exits 0
check() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then ok "${desc}"; else bad "${desc}"; fi
}

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)."; exit 1; }

echo "== SecureBank Linux Server — Module 1 verification =="

# --- Foundation -----------------------------------------------------------------
check "OS is Debian or Ubuntu" bash -c '. /etc/os-release; case "$ID" in debian|ubuntu) exit 0;; *) exit 1;; esac'
check "hostname is ${SB_HOSTNAME}" test "$(hostname)" = "${SB_HOSTNAME}"
check "admin user '${SB_ADMIN_USER}' exists" id "${SB_ADMIN_USER}"
check "admin user is in the sudo group" bash -c "getent group sudo | grep -qw '${SB_ADMIN_USER}'"
check "admin password is set (not locked)" bash -c "passwd -S '${SB_ADMIN_USER}' | awk '{print \$2}' | grep -qx 'P'"
check "openssh-server is installed" dpkg -s openssh-server
check "nftables is installed" dpkg -s nftables
check "sshd service is active" systemctl is-active ssh
check "sshd is listening on port 22" bash -c "ss -tln | grep -q ':22 '"
check "timezone is UTC" bash -c 'grep -qx "UTC" /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null | grep -qx "UTC"'

# --- SSH baseline: effective settings (T-01/T-04/T-10/T-11/T-12) --------------------
check "ssh: root login disabled" bash -c "sshd -T | grep -qi '^permitrootlogin no'"
check "ssh: password auth enabled (TEMPORARY, Module 1)" bash -c "sshd -T | grep -qi '^passwordauthentication yes'"
check "ssh: kbd-interactive matches password policy (flip both in Module 4)" bash -c "sshd -T | grep -qi '^kbdinteractiveauthentication yes'"
check "ssh: maxauthtries is 4" bash -c "sshd -T | grep -qi '^maxauthtries 4'"
check "ssh: access limited to ${SB_ADMIN_USER}" bash -c "sshd -T | grep -qi '^allowusers ${SB_ADMIN_USER}\$'"
check "ssh: empty passwords forbidden" bash -c "sshd -T | grep -qi '^permitemptypasswords no'"
check "ssh: agent forwarding disabled" bash -c "sshd -T | grep -qi '^allowagentforwarding no'"
check "ssh: pubkey auth explicit" bash -c "sshd -T | grep -qi '^pubkeyauthentication yes'"
check "ssh: logingracetime is 60" bash -c "sshd -T | grep -qi '^logingracetime 60'"
check "ssh: maxstartups is 5:30:60" bash -c "sshd -T | grep -qi '^maxstartups 5:30:60'"
check "ssh: usedns no" bash -c "sshd -T | grep -qi '^usedns no'"
check "ssh: gssapiauth disabled" bash -c "sshd -T | grep -qi '^gssapiauthentication no'"
check "ssh: banner is /etc/issue.net" bash -c "sshd -T | grep -qi '^banner /etc/issue.net'"

# --- SSH baseline: rendered file matches the repo template (T-04) ---------------------
exp="$(mktemp)"
sed "s/^AllowUsers .*/AllowUsers ${SB_ADMIN_USER}/" \
  "${REPO_DIR}/configs/etc/ssh/sshd_config.d/99-securebank.conf" > "${exp}"
check "sshd drop-in matches repo template" cmp -s "${exp}" /etc/ssh/sshd_config.d/99-securebank.conf
rm -f "${exp}"

# --- /etc/hosts managed block (T-05) -----------------------------------------------------
check "hosts: managed block present" bash -c "grep -qF '${HOSTS_BEGIN}' /etc/hosts"
check "hosts: managed block closed" bash -c "grep -qF '${HOSTS_END}' /etc/hosts"
check "hosts: server entry (${SB_SRV_IP})" bash -c "grep -qE '^${SB_SRV_IP}[[:space:]]' /etc/hosts"
check "hosts: kali entry (${SB_KALI_IP})" bash -c "grep -qE '^${SB_KALI_IP}[[:space:]]' /etc/hosts"
check "hosts: analyzer entry (${SB_ANALYZER_IP})" bash -c "grep -qE '^${SB_ANALYZER_IP}[[:space:]]' /etc/hosts"

# --- Banner (T-12) --------------------------------------------------------------------------
check "banner: /etc/issue.net installed" test -f /etc/issue.net
check "banner: matches repo template" cmp -s "${REPO_DIR}/configs/etc/issue.net" /etc/issue.net

# --- Firewall (T-06/T-07) ---------------------------------------------------------------------
check "firewall: nftables service active" systemctl is-active nftables
nftexp="$(mktemp)"
sed "s|@SB_LAB_SUBNET@|${SB_LAB_SUBNET}|" "${REPO_DIR}/configs/etc/nftables.conf" > "${nftexp}"
check "firewall: config matches repo template" cmp -s "${nftexp}" /etc/nftables.conf
rm -f "${nftexp}"
check "firewall: input policy is drop" bash -c "nft list ruleset | grep -q 'policy drop'"
check "firewall: SSH allowed from ${SB_LAB_SUBNET}" bash -c "nft list ruleset | grep -q '${SB_LAB_SUBNET}'"
check "firewall: covers IPv6 (inet table)" bash -c "nft list ruleset | grep -q 'table inet filter'"
check "firewall: dropped traffic is logged (SB-DROP)" bash -c "nft list ruleset | grep -q 'SB-DROP'"

# --- sysctl baseline (T-09) ---------------------------------------------------------------------
check "sysctl: config matches repo template" cmp -s "${REPO_DIR}/configs/etc/sysctl.d/99-securebank.conf" /etc/sysctl.d/99-securebank.conf
check "sysctl: rp_filter=1" test "$(sysctl -n net.ipv4.conf.all.rp_filter)" = "1"
check "sysctl: tcp_syncookies=1" test "$(sysctl -n net.ipv4.tcp_syncookies)" = "1"
check "sysctl: accept_redirects=0" test "$(sysctl -n net.ipv4.conf.all.accept_redirects)" = "0"

# --- Time (T-08) ---------------------------------------------------------------------------------
check "NTP enabled (systemd-timesyncd)" bash -c "timedatectl show -p NTP --value | grep -qx 'yes'"

# --- Patch management (C-13) --------------------------------------------------------------------------
check "unattended-upgrades installed" dpkg -s unattended-upgrades
check "apt auto-update drop-in matches repo template" cmp -s "${REPO_DIR}/configs/etc/apt/apt.conf.d/50securebank-unattended" /etc/apt/apt.conf.d/50securebank-unattended
check "auto-update: security origins only" bash -c "grep -q 'security' /etc/apt/apt.conf.d/50securebank-unattended"
check "auto-update: reboot NOT automatic" bash -c "grep -q 'Automatic-Reboot \"false\"' /etc/apt/apt.conf.d/50securebank-unattended"
check "auto-update: service is active (failures would be silent otherwise)" bash -c "systemctl is-active unattended-upgrades | grep -q active"

# --- Host auditing (C-15) ------------------------------------------------------------------------------
check "journald drop-in matches repo template" cmp -s "${REPO_DIR}/configs/etc/systemd/journald.conf.d/99-securebank.conf" /etc/systemd/journald.conf.d/99-securebank.conf
check "journal is persistent (on disk)" bash -c "test -d /var/log/journal"
if command -v aa-enabled >/dev/null 2>&1; then
  # AppArmor ships default-enforced on Ubuntu; on a minimal Debian install it
  # may be absent — then the MAC story is documented, not silently checked off
  # (see docs/host-auditing.md, C-14).
  check "apparmor is enabled" bash -c "aa-enabled 2>/dev/null | grep -qi 'Yes'"
  check "apparmor has enforced profiles" bash -c "aa-status --enforced 2>/dev/null | grep -q 'profiles are in enforce mode'"
else
  echo "  (skipping AppArmor checks: not installed — documented in docs/host-auditing.md C-14)"
fi

# --- Admin keypair (T-10) ---------------------------------------------------------------------------
ADMIN_HOME="$(getent passwd "${SB_ADMIN_USER}" | cut -d: -f6)"
check "admin ed25519 key exists" test -f "${ADMIN_HOME}/.ssh/id_ed25519"
check "admin public key self-authorized" bash -c "grep -qF \"\$(cat '${ADMIN_HOME}/.ssh/id_ed25519.pub')\" '${ADMIN_HOME}/.ssh/authorized_keys'"
check "ssh dir permissions (700)" test "$(stat -c %a "${ADMIN_HOME}/.ssh" 2>/dev/null)" = "700"
check "authorized_keys permissions (600)" test "$(stat -c %a "${ADMIN_HOME}/.ssh/authorized_keys" 2>/dev/null)" = "600"

# --- Packages -----------------------------------------------------------------------------------------
for p in curl wget git htop nano; do
  check "package '${p}' is installed" dpkg -s "${p}"
done

# --- Drift vs. the latest setup run (review bonus) ---------------------------------------------------------
# setup.sh records sha256sums of the applied configs in logs/setup-*.log;
# compare the live files against that record so drift is detected, not just
# documented. /etc/hosts is excluded — unrelated entries may legitimately change.
latest_setup_log="$(ls -1t "${REPO_DIR}"/logs/setup-*.log 2>/dev/null | head -n1)"
if [ -n "${latest_setup_log}" ]; then
  for f in /etc/ssh/sshd_config.d/99-securebank.conf /etc/nftables.conf /etc/sysctl.d/99-securebank.conf /etc/issue.net /etc/apt/apt.conf.d/50securebank-unattended /etc/systemd/journald.conf.d/99-securebank.conf; do
    rec="$(grep -F "  ${f}" "${latest_setup_log}" | tail -n1)"
    if [ -n "${rec}" ]; then
      cur_hash="$(sha256sum "${f}" | awk '{print $1}')"
      rec_hash="${rec%% *}"
      check "drift: $(basename "${f}") matches last setup run" test "${cur_hash}" = "${rec_hash}"
    fi
  done
else
  echo "  (skipping drift check: no logs/setup-*.log found — run scripts/setup.sh first)"
fi

echo
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
