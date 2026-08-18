#!/usr/bin/env bash
#
# SecureBank Linux Server — evidence-kit snapshot (review T-14, T-16)
# --------------------------------------------------------------------
# Run as root on the SecureBank VM. Snapshots the current state into
# logs/forensics-<timestamp>/ — the seed of the Stage 8 evidence map and a
# drift detector when compared against the hashes recorded by setup.sh in
# logs/setup-*.log.
#
# Also dumps host-key fingerprints (T-16): after the first run, record those
# in the lab notes so admins can verify the target is the target (no TOFU).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${REPO_DIR}/../lab.env"
if [ ! -f "${LAB_ENV}" ]; then
  echo "[forensics][ERROR] Missing ${LAB_ENV} - lab.env lives at the SecureBank-Enterprise-Lab repo root; clone the whole repo." >&2
  exit 1
fi
# shellcheck disable=SC1091
. "${LAB_ENV}"

LOG_DIR="${REPO_DIR}/logs"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${LOG_DIR}/forensics-${STAMP}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

mkdir -p "${OUT}"
echo "Collecting evidence snapshot -> ${OUT}"

# --- Effective configuration -------------------------------------------------
sshd -T > "${OUT}/sshd-effective.conf" 2>/dev/null || true
nft list ruleset > "${OUT}/nftables-ruleset.txt" 2>/dev/null || true
hostnamectl > "${OUT}/hostnamectl.txt" 2>/dev/null || true
timedatectl > "${OUT}/timedatectl.txt" 2>/dev/null || true

# --- Applied-config hashes (drift check vs. logs/setup-*.log) -----------------
# Must mirror the file set that setup.sh hashes (step 13) and that
# tests/module1-verify.sh checks — otherwise drift in a config the verify
# suite covers could be invisible to the Stage 8 evidence kit.
sha256sum /etc/ssh/sshd_config.d/99-securebank.conf \
          /etc/nftables.conf \
          /etc/sysctl.d/99-securebank.conf \
          /etc/issue.net \
          /etc/apt/apt.conf.d/50securebank-unattended \
          /etc/systemd/journald.conf.d/99-securebank.conf \
          /etc/hosts > "${OUT}/config-hashes.txt" 2>/dev/null || true

# --- Package baseline ----------------------------------------------------------
dpkg --get-selections > "${OUT}/packages.txt" 2>/dev/null || true

# --- Patch-management state (C-13) ------------------------------------------------
# Evidence for "was the box patched, and did auto-updates run without failure?".
apt-get --just-print dist-upgrade > "${OUT}/upgradable.txt" 2>/dev/null || true
timedatectl show -p LastNTPTime --value > "${OUT}/ntp-last-sync.txt" 2>/dev/null || true
journalctl -u unattended-upgrades --since "7 days ago" --no-pager > "${OUT}/unattended-upgrades.log" 2>/dev/null || true

# --- Host keys (T-16) -----------------------------------------------------------
: > "${OUT}/host-keys.txt"
for f in /etc/ssh/ssh_host_*_key.pub; do
  [ -e "${f}" ] || continue
  ssh-keygen -lf "${f}" >> "${OUT}/host-keys.txt"
done

# --- Users & auth activity -------------------------------------------------------
getent passwd > "${OUT}/passwd.txt" 2>/dev/null || true
last -n 20 > "${OUT}/last.txt" 2>/dev/null || true
journalctl -u ssh --since "24 hours ago" --no-pager > "${OUT}/ssh-journal-24h.log" 2>/dev/null || true
cp /var/log/auth.log "${OUT}/auth.log" 2>/dev/null || true

cat > "${OUT}/README.txt" <<EOF
Evidence snapshot ${STAMP}
Collector: scripts/collect-forensics.sh
Host: $(hostname)
Collected at: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Compare config-hashes.txt against the hashes recorded in logs/setup-*.log
to detect drift since the last setup run. Record host-keys.txt in the lab
manifest so future SSH first-connects can be verified (T-16).
EOF

echo "Done. Contents:"
ls -la "${OUT}"
