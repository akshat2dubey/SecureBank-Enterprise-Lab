# Risk Register (STRIDE)

**Method:** `docs/methodology.md` · **Assets:** `asset-inventory.md` ·
**Boundaries:** `trust-boundaries.md` · **Controls:** C-01…C-15 in
`stage2-securebank-linux-server/docs/security-hardening.md` (referenced by ID
only — that register is the single source of truth).

**Severity grid:** Likelihood × Impact (H/M/L) → High / Medium / Low, rated in
the **isolated lab** context (the realistic attacker is a lab participant or
the authorized Stage 6 pentest — not the Internet).

**Status legend:** ✅ Mitigated (controls in place) · ⚠️ Partially mitigated ·
🔲 Open · ✅✓ Accepted (lab scope, written reason) · 🔜 Future (arrives with a
named later stage).

---

## Current risks (Stages 1–2)

### R-01 — SSH credential guessing / brute force
- **STRIDE:** Spoofing, Elevation of privilege · **Assets:** A-02, A-03
- **Scenario:** while password auth is on (C-04, temporary), an attacker on
  the segment guesses the admin password and gains a foothold.
- **L/H:** M / H → **High**
- **Controls:** C-01 (no root SSH), C-02 (admin only), C-03 (minimal surface),
  C-04 (temporary), C-06 (AllowUsers), C-07 (MaxAuthTries 4, LoginGraceTime),
  C-12 (keys), C-13 (patching), C-08 (segment-only), C-11 (banner).
- **Residual:** password auth is on until Module 4; no fail2ban yet (deferred
  by design — see host-auditing.md).
- **Status:** ⚠️ **Partially** → **Closed in Module 4** (key-only SSH: flip
  `PasswordAuthentication` **and** `KbdInteractiveAuthentication` together,
  T-15). **Dependency:** Stage 2 Module 4.

### R-02 — SSH from outside the lab subnet
- **STRIDE:** Spoofing, EoP · **Assets:** A-01, A-02
- **Scenario:** a second NIC/NAT path reaches SSH; the "isolated lab" claim
  stops being enforced by config.
- **L/H:** L / H → **Medium**
- **Controls:** C-08 (SSH only from 10.10.10.0/24 + fe80::/10, both IP
  families), C-09 (rp_filter), self-lockout guard in `setup.sh`.
- **Residual:** a misconfigured VM NIC could still bypass; verify suite checks
  `nft list ruleset`.
- **Status:** ✅ **Mitigated** · verify: `module1-verify.sh` firewall checks.

### R-03 — Config tampering / drift (sshd, nftables, sysctl)
- **STRIDE:** Tampering · **Assets:** A-05, A-06, A-07, A-10
- **Scenario:** someone hand-edits the box config (or a partial setup run
  leaves stale state); the box silently stops matching the repo.
- **L/H:** M / H → **High**
- **Controls:** T-03 (setup audit log + hashes), drift detection in
  `module1-verify.sh`, `collect-forensics.sh` hash snapshot (A-09), C-13
  (patching doesn't drift configs).
- **Residual:** drift is only detected when the verify suite runs.
- **Status:** ⚠️ **Partially** → continuous integrity monitoring arrives with
  Stage 8 (and CI with Stage 9). **Dependency:** Stages 8/9.

### R-04 — Contract poisoning (lab.env / INTEGRATION.md)
- **STRIDE:** Tampering · **Assets:** A-11, A-12
- **Scenario:** a change to `lab.env`/`INTEGRATION.md` misconfigures *every*
  stage (addresses, ports, schema) — the highest-blast-radius file in the lab.
- **L/H:** L / H → **Medium**
- **Controls:** git history + review discipline, "update both in one commit"
  policy, `lab.env` has no secrets (nothing to steal, only to corrupt).
- **Residual:** no automated enforcement yet.
- **Status:** ⚠️ **Partially** → Stage 9 CI renders configs from `lab.env`
  and diffs them. **Dependency:** Stage 9.

### R-05 — Log tampering / repudiation
- **STRIDE:** Repudiation, Tampering · **Assets:** A-08, A-09
- **Scenario:** an attacker who reaches the host erases or edits journald
  entries so Stage 8 cannot reconstruct the incident.
- **L/H:** L / H → **Medium**
- **Controls:** C-15 (persistent journal, `SB-DROP` logs), A-09 forensics
  snapshots taken *before* incidents, T-03 hashes.
- **Residual:** journald is not tamper-evident and there is no remote log
  copy yet.
- **Status:** ⚠️ **Partially** → remote syslog to Stage 7 (Module 5) gives an
  off-host copy. **Dependency:** Stage 2 Module 5 / Stage 7.

### R-06 — Telemetry disclosure (reports / captures)
- **STRIDE:** Information disclosure · **Assets:** A-15, A-13
- **Scenario:** `traffic_report.json` (addresses/ports/flows) or a future
  PCAP with payloads reaches someone outside the lab.
- **L/H:** M / M → **Medium**
- **Controls:** metadata-only analyzer design (no payload capture/storage),
  `--json-only` machine mode, reports are git-ignored runtime artifacts,
  sample capture JSONs excluded from the repo, C-11 banner.
- **Residual:** real captures still contain metadata; treat reports as lab
  evidence.
- **Status:** ✅ **Mitigated** (by design) · re-check when Stage 4 traffic is
  captured.

### R-07 — DoS against SSH (SYN flood / connection exhaustion)
- **STRIDE:** Denial of service · **Assets:** A-02
- **Scenario:** a flood or connection burst makes admin access unavailable.
- **L/H:** M / M → **Medium**
- **Controls:** C-07 (MaxStartups 5:30:60, LoginGraceTime), C-08 (segment-only
  ingress), C-09 (tcp_syncookies); detection: Stage 1 `possible_syn_flood`
  heuristic + Stage 2 `SB-DROP` logs.
- **Residual:** no rate limiting/fail2ban (deferred — would fight Stage 6's
  authorized testing).
- **Status:** ✅✓ **Accepted** for lab scope · revisit if the lab grows an
  Internet-facing surface.

### R-08 — Segment spoofing / ARP poisoning (MITM on the shared segment)
- **STRIDE:** Spoofing, Tampering · **Assets:** A-17, A-01, A-13
- **Scenario:** another lab VM ARP-spoofs the server or analyzer, intercepting
  or redirecting traffic on the shared host-only segment.
- **L/H:** M / M → **Medium**
- **Controls:** C-09 (rp_filter, redirect/source-route off), C-08 (default
  deny limits exposure), C-12/T-16 (host-key pinning defeats SSH MITM).
- **Residual:** virtual switches offer no port security; ARP spoofing is
  *possible* — and a legitimate Stage 6 exercise.
- **Status:** ⚠️ **Partially** → convert into a Stage 6 pentest scenario +
  Stage 7 detection rule. **Dependency:** Stages 6/7.

### R-09 — Supply chain via apt
- **STRIDE:** Tampering, EoP · **Assets:** A-01, A-10
- **Scenario:** a compromised/malicious package slips in during updates.
- **L/H:** L / H → **Medium**
- **Controls:** C-13 (security-only origins), C-03 (minimal package set),
  `gnupg` signature verification (apt default), `ca-certificates`.
- **Residual:** standard apt trust model — accepted.
- **Status:** ✅ **Mitigated** (standard practice) · monitor via C-13 logs.

### R-10 — Privilege escalation via a future service (VulnBank / DB)
- **STRIDE:** Elevation of privilege, Tampering · **Assets:** A-19, A-20
- **Scenario:** the Stage 4 web app (deliberately vulnerable) is exploited;
  the service account reaches root or the DB.
- **L/H:** H / H → **High** (once Stage 4 exists — **not yet in scope**)
- **Controls (planned):** Module 3 gate (dedicated service accounts,
  least privilege — `services.md`), C-08 firewall extension, C-14 AppArmor
  profiles for real services (Module 4), C-13 patching.
- **Residual:** the app is *supposed* to be vulnerable — the controls bound
  the blast radius, they don't prevent exploitation.
- **Status:** 🔜 **Future** — register arrives with Stage 4; rows then feed
  Stage 6 (exploit) and Stage 7 (detect). **Dependency:** Stage 4.

### R-11 — Analyzer/report tampering feeding the SIEM
- **STRIDE:** Tampering, Spoofing · **Assets:** A-13, A-14, A-15
- **Scenario:** a compromised analyzer (or spoofed report) feeds false
  detections — or hides real ones — to the Stage 7 SIEM.
- **L/H:** L / M → **Low**
- **Controls:** metadata-only design, bounded memory (MAX_UNIQUE), schema
  versioning, integration test verifies expected content.
- **Residual:** analyzer runs as root on its own VM with no auth model.
- **Status:** ⚠️ **Partially** → Stage 7 ingestion gate must validate
  `schema_version` + fields (planned `consume_report.py`). **Dependency:**
  Stage 7.

### R-12 — Host-key spoofing on first connect (TOFU)
- **STRIDE:** Spoofing · **Assets:** A-04, A-16
- **Scenario:** the very first SSH connection to a fresh server accepts a
  fingerprint without verification (trust-on-first-use).
- **L/H:** M / M → **Medium**
- **Controls:** T-16 host-key fingerprints collected by `collect-forensics.sh`
  → record in the lab manifest; `ssh_known_hosts` on Kali.
- **Residual:** requires a human to record the manifest after first setup
  (documented "needs a human on the VM" step).
- **Status:** ✅ **Mitigated** (procedure) · verify fingerprints on first
  connect.

### R-13 — Credential leakage into the repo
- **STRIDE:** Information disclosure · **Assets:** A-03, A-04
- **Scenario:** the admin password or a private key is accidentally committed
  and pushed to the public repo.
- **L/H:** L / H → **Medium**
- **Controls:** no-secrets policy, `lab.env` explicitly holds no credentials,
  T-13 (password set interactively, never stored), `.gitignore` covers
  `logs/`, `.freebuff/`, `__pycache__/`.
- **Residual:** human discipline.
- **Status:** ⚠️ **Partially** → Stage 9 CI adds secret scanning (gitleaks).
  **Dependency:** Stage 9.

---

## Controls deliberately not mapped to a STRIDE row

- **C-05 (UTC timezone)** and **C-10 (NTP)** mitigate *correlation* failures,
  not a STRIDE category: a mis-set clock breaks Stage 7/8 timelines and the
  stage-1 timestamp convention (`INTEGRATION.md` §4). They are *enabling*
  controls — they make R-03/R-05 evidence trustworthy rather than blocking a
  specific attack. They appear at TB-7 in `trust-boundaries.md`.

## Register summary

| ID | Risk | STRIDE | Severity | Status | Closes when |
|---|---|---|---|---|---|
| R-01 | SSH brute force | S/E | High | ⚠️ | Stage 2 Module 4 |
| R-02 | SSH from outside subnet | S/E | Medium | ✅ | — |
| R-03 | Config drift/tampering | T | High | ⚠️ | Stages 8/9 |
| R-04 | Contract poisoning | T | Medium | ⚠️ | Stage 9 |
| R-05 | Log tampering/repudiation | R/T | Medium | ⚠️ | Module 5 / Stage 7 |
| R-06 | Telemetry disclosure | I | Medium | ✅ | re-check Stage 4 |
| R-07 | SSH DoS | D | Medium | ✅✓ | revisit w/ public surface |
| R-08 | Segment spoofing/MITM | S/T | Medium | ⚠️ | Stages 6/7 |
| R-09 | Apt supply chain | T/E | Medium | ✅ | — |
| R-10 | Service → root (future) | E/T | High | 🔜 | Stage 4 |
| R-11 | Report tampering → SIEM | T/S | Low | ⚠️ | Stage 7 |
| R-12 | Host-key TOFU | S | Medium | ✅ | — |
| R-13 | Credential leakage | I | Medium | ⚠️ | Stage 9 |

## Open actions (do not lose these)

1. **Module 4:** close R-01 (key-only SSH, flip both switches), extend C-08
   for real services, add AppArmor profiles (feeds R-10).
2. **Module 5 / Stage 7:** close R-05 (remote syslog) and R-11 (report
   ingestion gate); add R-08 ARP-spoofing detection rule.
3. **Stage 6:** turn R-08 + R-10 into authorized pentest scenarios; findings
   update this register.
4. **Stage 9:** close R-04 (CI config-diff) and R-13 (secret scanning).
5. **Every module:** add assets/flows/risks here *before* building (methodology
   §6).
