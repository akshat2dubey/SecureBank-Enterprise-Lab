#!/usr/bin/env bash
#
# SecureBank Linux Server — Module 1 verification
# ------------------------------------------------
# Run as root on the SecureBank lab VM:
#     sudo ./tests/module1-verify.sh
# Prints PASS/FAIL per check; exits 0 only if everything passes.

set -uo pipefail

SB_ADMIN_USER="${SB_ADMIN_USER:-securebank-admin}"
SB_HOSTNAME="securebank-srv"
SB_LAB_IP="10.10.10.10"

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

check "OS is Debian or Ubuntu" bash -c '. /etc/os-release; case "$ID" in debian|ubuntu) exit 0;; *) exit 1;; esac'
check "hostname is ${SB_HOSTNAME}" test "$(hostname)" = "${SB_HOSTNAME}"
check "admin user '${SB_ADMIN_USER}' exists" id "${SB_ADMIN_USER}"
check "admin user is in the sudo group" bash -c "getent group sudo | grep -qw '${SB_ADMIN_USER}'"
check "openssh-server is installed" dpkg -s openssh-server
check "sshd service is active" systemctl is-active ssh
check "sshd is listening on port 22" bash -c "ss -tln | grep -q ':22 '"
check "root login over SSH is disabled" bash -c "sshd -T | grep -qi '^permitrootlogin no'"
check "SecureBank sshd config is installed" test -f /etc/ssh/sshd_config.d/99-securebank.conf
check "/etc/hosts has the lab server entry" bash -c "grep -qE '^${SB_LAB_IP}[[:space:]]' /etc/hosts"

for p in curl wget git htop nano; do
  check "package '${p}' is installed" dpkg -s "${p}"
done

check "timezone is UTC" bash -c 'grep -qx "UTC" /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null | grep -qx "UTC"'

echo
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
