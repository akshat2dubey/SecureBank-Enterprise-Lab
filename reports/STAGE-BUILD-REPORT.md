# SecureBank Enterprise Lab — What Has Been Built So Far (Brief Stage Report)

**Date:** September 2026 · **Ecosystem:** one interconnected ecosystem bound by
`lab.env` + `INTEGRATION.md`, not nine mini-projects.

---

## Stage 1 — Network Traffic Analyzer ✅ foundation complete

A passive Python/Scapy analyzer that captures live traffic or reads PCAPs and
emits schema-versioned JSON reports — **metadata only by design** (never stores
payloads). It classifies TCP/UDP/ICMP/ARP/DNS, tracks addresses, ports, flows,
and TCP flags, bounds memory for long captures, and never crashes on malformed
packets (they are counted, not fatal). Three explainable heuristic detections
(SYN flood, port scan, plaintext service) run over flow metadata at report time.

- Report schema **`traffic-report/1.1`**: adds `report_id` (stable unique ID),
  `sensor`, and `capture_start`/`capture_end` on top of 1.0 — additive-only per
  the contract.
- `validate_report.py` is the ingestion gate: every report must validate before
  Stage 7 consumes it (enforced in the unit suite and the integration test).
- Verification: **25-test pytest suite**, plus a formal integration test that
  captures while Kali runs the Stage 2 traffic generator and enforces the
  **visibility contract** (cross-host SSH + HTTP flows must appear; an
  ARP/broadcast-only capture is a visibility failure, not a quiet network).
- Machine seam for Stage 7: `--json-only` keeps stdout pure JSON.

## Stage 2 — SecureBank Linux Server 🟡 foundation complete, Modules 2–8 planned

The hardened, monitored, reproducible backend — the center of gravity of the
lab (watched by 1 and 7, tested by 5 and 6, hosted on by 4, investigated by 8,
modeled by 3, deployed by 9).

**Module 1 (done):** idempotent `setup.sh` delivers a patched-from-day-one host
(security-only `unattended-upgrades`, C-13), default-deny nftables firewall on
both IP families (C-08), sysctl hardening (C-09), UTC + NTP (C-05/C-10),
restricted SSH baseline (root off, AllowUsers, banner; C-01/C-06/C-11),
persistent journal + `SB-DROP` logging + forensics snapshot kit (C-15),
AppArmor verified where the platform ships it (C-14). Every run is audited
(setup log + applied-config sha256 hashes); `tests/module1-verify.sh` checks
**effective state** (~75 checks) and fails on drift.

**Module 2 (code complete — verify on the VM):** static lab addressing from
`lab.env` (C-16): the host-only NIC holds `10.10.10.10/24` +
`fd00:10:10::10/64` via netplan or systemd-networkd; NAT NIC stays DHCP for
updates. Peer VM snippets (Kali, analyzer) render from `lab.env` via
`render-peer-configs.sh`.

**Review hardening (this change):** the firewall self-lockout guard now
validates the **remote peer** of the SSH session (IPv4 + IPv6, fail-closed)
instead of the local socket side — a real lockout-safety defect fixed. The
server no longer generates any SSH key: **Kali is the sole admin-key origin**
(C-12 revised). Logical planes (management / application / database /
monitoring) are documented with firewall/binding rules before services exist;
the DNS probe vs. DNS-service distinction and the honest unrestricted-egress
posture are documented in the contract.

## Stage 3 — STRIDE Threat Model 🔶 skeleton in progress

"Understand before you build": the skeleton docs (asset inventory A-01…A-22,
trust boundaries TB-1…TB-9, data-flow diagram, methodology, STRIDE risk
register R-01…R-13) consume the Stage 2 control register (C-01…C-16) and are
the input to Stages 4–8 planning. Untracked on disk — not yet committed.

## Stages 4–9 — planned, seams reserved

| Stage | What exists today |
|---|---|
| 4 — VulnBank | ports 80/443 reserved; logical-plane rules documented (app plane only exposure) |
| 5 — BankRecon | `lab.env` targets ready; ports reserved |
| 6 — Pentest | traffic generator + verified Stage 1 visibility = integration proof path |
| 7 — SIEM | schema 1.1 + `validate_report.py` = the ingestion seam; syslog integrity target (TCP/10514, authenticated encryption) recorded in the contract |
| 8 — IR | forensics kit layout + config-hash drift detection = evidence seed |
| 9 — DevSecOps | idempotent scripts render everything from `lab.env`; contract changelog discipline = CI-gateable |

**Deliberate boundaries:** metadata-only analyzer, no payload capture or
per-packet storage, no DNS service until deliberately deployed, one server VM
until Stage 4/7 needs more, auditd/Fail2Ban/AIDE deferred with triggers.

---

## Exact verification results (current tree)

| Check | Result |
|---|---|
| `bash -n` (setup.sh, generate-lab-traffic.sh, module1-verify.sh, integration_test.sh) | all OK |
| `python -m pytest tests/test_analyzer.py -q` | **25 passed** |
| `validate_report.py` on regenerated sample reports | VALID ×2 |
| Guard-helper smoke (faked `ss` layouts: v4 / v6 ULA / link-local / Netid / prefixes / two sessions / NAT / garbage / empty) | 13 passed, 0 failed |
| HANDOFF.md regenerated from sources | in sync |

*Status reflects the working tree as of this report; nothing is pushed until you approve — this report and the review fixes are being pushed together at your instruction.*
