#!/usr/bin/env bash
#
# SecureBank Linux Server — Module 2: render peer-VM network configs
# ------------------------------------------------------------------
# Renders the ready-to-paste static-network snippets for the two peer VMs
# (Kali, Stage 1 traffic analyzer) from lab.env at the repo root, plus
# verbatim copies of the server's own backend templates for reference.
#
# Output (git-ignored): outputs/peer-configs/
#   ├── kali-securebank.md
#   ├── traffic-analyzer.md
#   ├── netplan-99-securebank.yaml.example
#   └── networkd-10-securebank-lab.network.example
#
# Why a renderer instead of static snippets: the golden rules forbid
# hardcoding lab addresses outside lab.env — templates carry @VAR@
# placeholders and this script fills them, so changing lab.env and
# re-running is the only way values ever change.
#
# No root needed: render here, copy the result to the peer VMs.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_ENV="${REPO_DIR}/../lab.env"
if [ ! -f "${LAB_ENV}" ]; then
  echo "[render][ERROR] Missing ${LAB_ENV} - lab.env lives at the SecureBank-Enterprise-Lab repo root; clone the whole repo." >&2
  exit 1
fi
# shellcheck disable=SC1091
. "${LAB_ENV}"

OUT_DIR="${REPO_DIR}/outputs/peer-configs"
TPL_DIR="${REPO_DIR}/configs/other-vms"
mkdir -p "${OUT_DIR}"

# Prefix lengths derived from the (overridable) lab.env subnets
LAB_PREFIX="${SB_LAB_SUBNET##*/}"
IPV6_PREFIX="${SB_IPV6_LAB_SUBNET##*/}"

render() {
  # render <template> <destination>
  sed -e "s|@SB_LAB_SUBNET@|${SB_LAB_SUBNET}|g" \
      -e "s|@SB_LAB_PREFIX@|${LAB_PREFIX}|g" \
      -e "s|@SB_IPV6_LAB_SUBNET@|${SB_IPV6_LAB_SUBNET}|g" \
      -e "s|@SB_IPV6_PREFIX@|${IPV6_PREFIX}|g" \
      -e "s|@SB_KALI_IP@|${SB_KALI_IP}|g" \
      -e "s|@SB_KALI_IPV6@|${SB_KALI_IPV6}|g" \
      -e "s|@SB_KALI_HOSTNAME@|${SB_KALI_HOSTNAME}|g" \
      -e "s|@SB_ANALYZER_IP@|${SB_ANALYZER_IP}|g" \
      -e "s|@SB_ANALYZER_IPV6@|${SB_ANALYZER_IPV6}|g" \
      -e "s|@SB_ANALYZER_HOSTNAME@|${SB_ANALYZER_HOSTNAME}|g" \
      -e "s|@SB_SRV_HOSTNAME_FQDN@|${SB_HOSTNAME}.${SB_DOMAIN}|g" \
      -e "s|@SB_DOMAIN@|${SB_DOMAIN}|g" \
      -e "s|@SB_SRV_IP@|${SB_SRV_IP}|g" \
      -e "s|@SB_SRV_IPV6@|${SB_SRV_IPV6}|g" \
      "$1" > "$2"
}

render "${TPL_DIR}/kali-securebank.template.md"       "${OUT_DIR}/kali-securebank.md"
render "${TPL_DIR}/traffic-analyzer.template.md"      "${OUT_DIR}/traffic-analyzer.md"
render "${REPO_DIR}/configs/etc/netplan/99-securebank.yaml" \
       "${OUT_DIR}/netplan-99-securebank.yaml.example"
render "${REPO_DIR}/configs/etc/systemd/network/10-securebank-lab.network" \
       "${OUT_DIR}/networkd-10-securebank-lab.network.example"

# Leave no unresolved placeholders behind in the paste-ready snippets — a
# leftover @VAR@ means a new lab.env variable was added without updating
# this renderer. The .example copies of the server's backend templates are
# excluded: @SB_LAB_IFACE@ there is filled at install time on the server VM
# (NIC names differ per machine; setup.sh detects it).
if grep -RnE '@SB_[A-Z_0-9]+@' "${OUT_DIR}"/*.md; then
  echo "[render][ERROR] Unresolved placeholders above - extend the render() call in $0." >&2
  exit 1
fi

echo "Rendered peer configs (values from lab.env):"
echo "  Kali      : ${SB_KALI_IP}/${LAB_PREFIX}  +  ${SB_KALI_IPV6}/${IPV6_PREFIX}"
echo "  Analyzer  : ${SB_ANALYZER_IP}/${LAB_PREFIX}  +  ${SB_ANALYZER_IPV6}/${IPV6_PREFIX}"
echo "Copy the .md snippets to each peer VM and follow them there:"
ls -1 "${OUT_DIR}"
