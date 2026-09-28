# SecureBank Enterprise Lab — Project Status Report

**Date:** 2026-09-29 · **Branch:** `main @ 1b5e2f1` (pushed to
https://github.com/akshat2dubey/SecureBank-Enterprise-Lab) · **Tree:** clean

---

## 1. What was done this session (work log)

| # | Change | Commit | Verified by |
|---|---|---|---|
| 1 | **Review round, all 8 work packages** — visibility contract (§2 + enforcement in `integration_test.sh`), peer-safe firewall lockout guard (`_ss_ssh_field`/`parse_peer`/`ipv6_in_subnet`, fail-closed, 13-case smoke harness), no server-side SSH keys, status honesty, logical planes, DNS-probe labeling, report schema **1.0 → 1.1** (`report_id`, `sensor`, capture window) + `validate_report.py` ingestion gate, syslog-integrity + egress posture notes | `4132c93` | pytest 25/25 · validator VALID ×2 · guard smoke 13/13 · `bash -n` all scripts |
| 2 | **Stage-folder reorganization** — Stage 1 code flattened `Project/outputs/` → `src/` (+ `outputs/`, `docs/`); per-stage completion reports moved next to their stages (S1 → stage root, S2 → `docs/`); Stage 3 `Threat model skelton/` → `threat-model/`; every cross-reference updated in lockstep (tests, INTEGRATION §6 + changelog row, both build generators, stage2/stage3 docs, README, CONTRIBUTING); HANDOFF regenerated | `7d7b5a6` + `8d9a49e` | pytest 25/25 · validator VALID ×2 · `bash -n` · zero stale `Project/outputs`/`skelton` refs repo-wide · all moves recorded as git renames (100%) |
| 3 | **Pre-Module-3 registration (T-18 gate executed early)** — `docs/module3-service-register.md` (nginx 80/443 + DB **loopback-only**, planned controls C-17…C-19, install order, 3 owner sign-offs reserved); `RUNBOOK-VM-VERIFICATION.md`; Stage 3 model extended (assets A-24…A-28, boundary TB-10, risks R-14/R-15); `services.md`/README/INTEGRATION changelog updated; HANDOFF regenerated | `1b5e2f1` | `bash -n` verify suite · cross-ref greps · contract rule respected (no address/port change) |

---

## 2. What is in the project now

```
SecureBank-Enterprise-Lab/
├── lab.env + INTEGRATION.md        # the contract (identity + rules) — unchanged this session
├── HANDOFF.md                      # regenerated 3×; self-contained AI pack
├── reports/                        # cross-stage tooling only now
│   ├── STAGE-BUILD-REPORT.md       # per-stage build report (earlier session)
│   └── build_{reports,handoff}.py  # generators, stage-aware since the reorg
├── stage1-network-traffic-analyzer/
│   ├── src/        analyzer · detections · validate_report · main (launcher)
│   ├── outputs/    sample reports (schema traffic-report/1.1, VALID)
│   ├── docs/       usage.md · CODE_EXPLANATION.md
│   ├── tests/      25 pytest cases · integration_test.sh (visibility contract)
│   └── SecureBank-Stage1-Completion-Report.{md,docx,html}
├── stage2-securebank-linux-server/
│   ├── scripts/    setup.sh (M1+M2, guards) · generate-lab-traffic · collect-forensics · render-peer-configs
│   ├── tests/      module1-verify.sh (~75 effective-state checks, M1+M2)
│   ├── configs/    etc/ (sshd, nftables, sysctl, netplan, networkd, cloud-init, journald, apt) · other-vms templates
│   ├── docs/       architecture · network-design (§7+§8 planes) · security-hardening C-01…C-16
│   │               security-review · services · host-auditing · module3-service-register (NEW)
│   │               SecureBank-Stage2-Completion-Report.{md,docx,html}
│   └── RUNBOOK-VM-VERIFICATION.md  (NEW — the VM session checklist)
├── stage3-threat-model/
│   └── threat-model/docs/  methodology · asset-inventory (A-01…A-28) ·
│                           trust-boundaries (TB-1…TB-10) · data-flow-diagram ·
│                           risk-register (R-01…R-15)
└── stage4…stage9/          README placeholders (interfaces pre-reserved in INTEGRATION.md)
```

**Verification state:** everything *code-level* is proven (tests, validator,
syntax, cross-references). Everything *VM-level* is pending one runbook
session: Module 2 static addressing proof + Stage 1 integration test on the
real VMs.

---

## 3. Next target: Stage 3, connected to Stages 1–2

Stage 3's skeleton is complete; its value now comes from being **evidence-backed**
and **decision-producing**. Three targets, in order, each tied to what the
previous stages actually produce:

### Target 1 — Make the model readable and decision-ready (now, no VM needed)
- Render the DFD + trust zones as **Mermaid** (the ASCII diagram becomes a real figure).
- Add **attack trees** for the top risks (R-01 brute force, R-03 drift, R-14 web→DB) —
  every leaf must name a Stage 2 C-control or a Stage 1 detection that catches it.
- Start the **risk decision log**: per R-row, record accept / mitigate / defer +
  trigger. This is the artifact Stages 4–8 will consume.
- Fix the stage README status (skeleton ≠ not-started).

### Target 2 — Evidence import & re-rating (immediately after the VM runbook)
- Pull **real** artifacts into the model: `logs/setup-*.log` config hashes,
  `module1-verify.sh` results, integration-test evidence, T-16 host-key
  fingerprint manifest.
- Re-rate with evidence: R-02 confirmed by the nftables checks, R-03 by the
  drift check actually running, R-06/R-07 by the integration capture.
- **Detection-coverage matrix (the key connector):** map Stage 1 detections →
  Stage 2 log sources → Stage 7 rules. E.g. `possible_syn_flood` → `SB-DROP`
  logs → R-07 alert; `possible_port_scan` → recon phase of R-08; Stage 2
  journald auth events → R-01/R-05 timeline. One table that proves Stages 1+2
  outputs have a *consumer* — that is the ecosystem claim made checkable.

### Target 3 — Activate the reserved rows at Module 3 install
- TB-10 goes live, C-17…C-19 become real controls, A-24…A-28 become current
  assets, R-14/R-15 re-rated with running services.
- Stage 3 then produces its first real **deliverable**: the go/no-go risk input
  to Stage 4's VulnBank design (what the app may assume, what it must defend).

### Why this order
The model's inputs (Stage 2 controls, Stage 1 schema/evidence) are stable but
the *proof* is pending on the VMs; Stage 4 design depends on Stage 3's
decisions. So: make decisions explicit now (T1), ground them in evidence as
soon as the runbook runs (T2), and only then extend the surface (T3 → Stage 4).

---

## 4. Pending decisions & blockers

| Item | Owner | Blocks |
|---|---|---|
| VM runbook execution (pull, setup+verify, integration test) | you (on VMs) | Module 2 "verified" status, Stage 1 on-VM proof, Target 2 |
| Module 3 sign-offs: DB engine (MariaDB default) · TLS strategy (self-signed default) · account names (`securebank-app`, `vulnbank-db` default) | you | Module 3 install, Target 3 |

## 5. Commit trail (this session, all pushed)

`4132c93` review fixes → `7d7b5a6` reorg → `8d9a49e` reorg follow-up →
`1b5e2f1` pre-Module-3 registration → *(this report — not yet committed)*
