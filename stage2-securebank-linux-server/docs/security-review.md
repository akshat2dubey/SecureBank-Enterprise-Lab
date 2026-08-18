# SecureBank Linux Server — Security Architecture Review & TODO

**Status:** Reviewer punch list over the Module 1 codebase (scripts, configs,
tests, docs). This is not the Stage 3 threat model — it is the list of changes
I would make *before* Modules 2–4 build on top of Module 1.

**All items T-01…T-18 implemented** — see [Implementation notes](#implementation-notes)
at the bottom for where each one landed. This document remains the record of
*why* each control exists.

**How to read:** every item is an actionable todo with the same five fields the
hardening register uses — Why (risk), Change (what to do), Verify (how you know
it's done), Effort. Priorities:

- **P0** — cheap, correct, do now (still Module 1).
- **P1** — before or together with Modules 2–4.
- **P2** — architectural / process, lower urgency.

---

## P0 — Do now (still Module 1)

### T-01 — Restrict SSH to the admin account only
- **Why:** while `PasswordAuthentication yes` is on (C-04), **any** local account with a password and a shell can SSH in. Module 3 adds service accounts (nginx, DB app user); one misconfigured shell later and that's a lateral-movement path — and the pentest stages (5/6) will probe exactly that.
- **Change:** add `AllowUsers securebank-admin` to the sshd baseline. Generate the drop-in from the script variable (`SB_ADMIN_USER`) instead of copying a static file, so the config and the variable can't diverge.
- **Verify:** `sshd -T | grep -i allowusers`; SSH as a non-admin user fails with `Permission denied`.
- **Effort:** 15 minutes. Highest value-per-effort item on this list.

### T-02 — Baseline package hygiene: no recommends, start patched
- **Why:** `apt-get install -y` pulls recommended packages the server doesn't need (attack surface), and the box starts life with whatever the ISO shipped — possibly months of unpatched packages.
- **Change:** `apt-get install --no-install-recommends -y ...`; run one `apt-get full-upgrade -y` before installing; snapshot `dpkg --get-selections` into `logs/` as the reproducibility/drift baseline.
- **Verify:** `apt list --upgradable` is empty after setup; `logs/package-baseline-*.txt` exists.
- **Effort:** small; the upgrade adds setup time once.

### T-03 — Log the setup run and record applied-config hashes
- **Why:** "reproducible" is a claim; right now nothing records what was applied or when. That's the seed of Stage 8 evidence and the only way to detect drift later.
- **Change:** run setup through `tee -a logs/setup-$(date +%F).log` (the `logs/` dir is already git-ignored) and after applying, `sha256sum` the installed configs (`/etc/ssh/sshd_config.d/99-securebank.conf`, `/etc/hosts`, hostname) into the same log.
- **Verify:** a setup run produces a log with hashes; re-running produces identical hashes.
- **Effort:** small.

### T-04 — Verify content, not existence
- **Why:** `module1-verify.sh` mostly checks that files *exist* (`test -f ...`). Someone hand-edits the sshd drop-in to `PasswordAuthentication yes` + `PermitRootLogin yes` and the suite still prints PASS. "PASS" should mean the box matches the repo.
- **Change:** `cmp` the drop-in against `configs/etc/ssh/sshd_config.d/99-securebank.conf`; assert each effective setting via `sshd -T` (`permitrootlogin no`, `passwordauthentication yes` (temporary), `maxauthtries 4`, `allowusers`, plus the P0/P1 additions). Add `passwd -S` = `P` check so a locked admin account fails loudly instead of silently locking everyone out.
- **Verify:** corrupt the drop-in → suite fails; restore → passes.
- **Effort:** medium — a few new `check` lines.

### T-05 — One source of truth for lab addresses
- **Why:** `10.10.10.10/.20/.30` are hardcoded in `configs/etc/hosts`, `scripts/generate-lab-traffic.sh`, `tests/module1-verify.sh`, and the docs. That is exactly the drift that silently misconfigures a firewall in Module 4. The /etc/hosts merge is also append-only: a stale line for an IP is never fixed by re-running setup.
- **Change:** add `lab.env` at the repo root (subnet, server/Kali/analyzer IPs, domain, admin user, FQDN, IPv6 ULA) sourced by `setup.sh`, the traffic script, the forensics collector, and the verify script; generate `/etc/hosts` and the sshd drop-in from it. Fix the merge to replace the managed block (mark it with `# BEGIN/END securebank`) or at least diff + warn.
- **Verify:** change one IP in `lab.env` → every script and config follows; no hardcoded `10.10.10.*` left outside docs.
- **Effort:** medium refactor, immediate payoff when Modules 2–4 land.

---

## P1 — Before / together with Modules 2–4

### T-06 — Early default-deny firewall (don't wait for Module 4)
- **Why:** between now and Module 4 the box has an unfiltered NAT path to the internet, and host-only networks leak more often than people admit (misconfigured NIC, VM clone, DHCP quirk). The "isolated lab" claim should be enforced by config, not assumed.
- **Change:** ship `configs/etc/nftables.conf` now — allow loopback + established/related; allow `22/tcp` from `10.10.10.0/24` only; drop the rest on **both** NICs (including the NAT interface, which needs only outbound). Apply idempotently in setup (or a small `scripts/apply-firewall.sh`). Module 4 then extends the same file instead of inventing one.
- **Verify:** `nft list ruleset`; from Kali, SSH works; from the NAT side, inbound is dropped; `nft` rules survive reboot (`systemctl enable nftables`).
- **Effort:** one file + a few script lines.

### T-07 — IPv6 parity
- **Why:** sshd listens on IPv6 by default; nothing in the docs, firewall plan, or verify script covers v6. Half-configured IPv6 is a classic blind spot for Stages 5–7.
- **Change:** decide and document: either disable IPv6 on the lab NICs or commit to filtering both families in T-06 (same default-deny, v6 equivalents). Add a verify check for whichever is chosen.
- **Verify:** `ss -tln` shows the expected families; `nft list ruleset` covers both.
- **Effort:** small, but the decision must be made before the firewall file is written.

### T-08 — Time sync
- **Why:** C-05 sets UTC, but a *drifting* clock breaks Stage 7/8 log correlation as surely as a wrong zone. Nothing ensures the clock is correct.
- **Change:** `timedatectl set-ntp true` (systemd-timesyncd) and document the isolated-lab reality: outbound NTP may be blocked — either allow it via the NAT NIC (update-only traffic, consistent with the current posture) or document the manual `date` fallback.
- **Verify:** `timedatectl` shows `System clock synchronized: yes`; a verify check that the clock is within a sane window.
- **Effort:** small.

### T-09 — sysctl baseline drop-in
- **Why:** classic network-hardening knobs cost one file and give Module 4 a foundation instead of a scramble: `rp_filter=1`, `accept_redirects=0`, `accept_source_route=0`, `log_martians=1`, `tcp_syncookies=1` (+ IPv6 equivalents).
- **Change:** ship `configs/etc/sysctl.d/99-securebank.conf`, apply idempotently, verify with `sysctl <key>`.
- **Verify:** each key reports the hardened value after `sysctl --system`.
- **Effort:** small. (Formally Module 4 scope, but free now.)

### T-10 — Start key provisioning now
- **Why:** Module 4's key-only switch is a two-line config change *if* keys already exist, and a scramble if they don't. Keys also improve the traffic script: `ssh -o BatchMode=yes` today produces preauth *failures*; with a key it's a genuine auth success — better, less noisy telemetry.
- **Change:** generate an `ed25519` keypair for the admin user, install `authorized_keys` (via setup, idempotently), set `PubkeyAuthentication yes` explicitly in the baseline.
- **Verify:** `ssh -o IdentitiesOnly=yes -i <key> admin@10.10.10.10` works without a password.
- **Effort:** small.

### T-11 — SSH auth/DoS posture, made explicit
- **Why:** `MaxAuthTries 4` is per-connection — 4 tries × unlimited connections, so without fail2ban it's cosmetic (fine in the isolated lab; fail2ban arrives in Module 4 — document this so nobody thinks it's a real limit). `UseDNS` reverse lookups slow logins and are a log-poisoning vector; GSSAPI is unused.
- **Change:** baseline adds `LoginGraceTime 60`, `MaxStartups 5:30:60`, `UseDNS no`, `GSSAPIAuthentication no` — all explicit, each with a `sshd -T` verify entry.
- **Verify:** `sshd -T | grep -Ei 'logingracetime|maxstartups|usedns|gssapiauthentication'`.
- **Effort:** small.

### T-12 — Authorized-use banner
- **Why:** realism for the lab narrative and for Stage 5/8 write-ups; the single most-cited control in assessment reports. Costs one file.
- **Change:** ship `/etc/issue.net` + sshd `Banner /etc/issue.net` (and `/etc/issue` for console), clearly labeled "authorized lab use only".
- **Verify:** an SSH login shows the banner; `sshd -T | grep -i banner`.
- **Effort:** tiny.

### T-13 — Admin password policy + lockout recovery
- **Why:** the admin password is the highest-value secret in the lab, set manually with no policy, and a locked account today has no documented recovery path.
- **Change:** document a minimum password policy (e.g. ≥14 chars, not reused elsewhere), a rotation cadence, and the recovery path — use the **VM console** (`sudo -i`, `passwd`), never a factory reset. State plainly: the password must never be committed to the repo.
- **Verify:** verify-script check that `passwd -S` = `P` (from T-04); README section exists.
- **Effort:** documentation only.

---

## P2 — Architectural / process

### T-14 — Evidence-kit seed script
- **Why:** Stage 8 needs preserved evidence (logs, timestamps, config as applied). Build the habit now.
- **Change:** `scripts/collect-forensics.sh` snapshots `sshd -T`, dpkg selections, `/etc/hosts`, config hashes (from T-03), `last`, and recent ssh journal entries into timestamped `logs/` files. Doubles as a drift detector when compared against T-03 baselines.
- **Verify:** running it produces a timestamped bundle; diffing two runs shows only intended changes.
- **Effort:** medium.

### T-15 — Module 4 correctness: kill both password paths
- **Why:** the classic failure when switching to key-only is setting `PasswordAuthentication no` while PAM keyboard-interactive still accepts passwords. OpenSSH treats them as separate switches.
- **Change:** when Module 4 lands, set **both** `PasswordAuthentication no` and `KbdInteractiveAuthentication no`, and verify both in the test suite.
- **Verify:** `sshd -T | grep -Ei 'passwordauthentication|kbdinteractiveauthentication'` → both `no`; password login fails, key login works.
- **Effort:** none now — recorded so Module 4 doesn't get this wrong.

### T-16 — Host-key fingerprint manifest
- **Why:** "predictable identity" is a stated principle; a fingerprint manifest makes it real and gives Stage 6 a way to confirm the target is the target.
- **Change:** ship `ssh-keygen -lf` output for the server host keys in the repo (or a `ssh_known_hosts` file for Kali) and document verification in the lab notes.
- **Verify:** Kali's known_hosts fingerprint matches the manifest on first connect (no TOFU prompt).
- **Effort:** small; thematic fit.

### T-17 — Traffic-script input validation
- **Why:** `COUNT="${1:-3}"` is used raw in `seq` — a typo (`./generate-lab-traffic.sh abc`) aborts mid-run under `set -euo pipefail`, and an absurd value hammers the segment.
- **Change:** validate integer, `>= 1`, clamp to a sane max (e.g. 100).
- **Verify:** bad inputs are rejected with a usage message; `9999` clamps.
- **Effort:** tiny.

### T-18 — Keep (and formalize) the "document before install" gate
- **Why:** the project's best practice — nothing is installed before it's documented in `docs/services.md` with a hardening-register entry. Make it a hard check in Module 3's definition of done.
- **Change:** add a checklist item to Module 3 planning: service, port, bind address, dedicated user, threat addressed, verification — all present *before* the package is installed.
- **Verify:** no Module 3 service lands without its register row.
- **Effort:** process discipline; zero code.

---

## Implementation notes

All items below are implemented in the repo. Where a change can only take effect
on the VM, re-run `sudo ./scripts/setup.sh` and `sudo ./tests/module1-verify.sh`
on the SecureBank box.

| # | Landed in |
|---|---|
| T-01 | `configs/etc/ssh/sshd_config.d/99-securebank.conf` (`AllowUsers`, `PermitEmptyPasswords no`, `AllowAgentForwarding no`); `AllowUsers` is rendered by `scripts/setup.sh` from `lab.env` at the repo root |
| T-02 | `scripts/setup.sh` — `--no-install-recommends`, one-time `full-upgrade`, `dpkg --get-selections` snapshot into `logs/` |
| T-03 | `scripts/setup.sh` — every run teed to `logs/setup-<stamp>.log`, applied-config `sha256sum` appended |
| T-04 | `tests/module1-verify.sh` — rendered-template `cmp` for the sshd drop-in + per-setting `sshd -T` assertions; also `cmp` for firewall/sysctl/banner; `passwd -S` lockout check |
| T-05 | `lab.env` at the repo root (new, single source of truth, also consumed by Stages 5–7/9 per `INTEGRATION.md`); `scripts/setup.sh` generates the `# BEGIN/END securebank.lab` block in `/etc/hosts` (replaced every run); `configs/etc/hosts` deleted; all Stage 2 scripts source the root `lab.env` |
| T-06 | `configs/etc/nftables.conf` (new); applied + enabled idempotently by `scripts/setup.sh` |
| T-07 | IPv6 decision recorded in `docs/network-design.md` §4b; firewall uses an `inet` table covering both families |
| T-08 | `scripts/setup.sh` — `timedatectl set-ntp true`; verify check added; isolated-lab NTP caveat in T-08 entry above |
| T-09 | `configs/etc/sysctl.d/99-securebank.conf` (new), applied via `sysctl --system`, verified in the test suite |
| T-10 | `scripts/setup.sh` — local `ed25519` keypair + self-authorized pubkey; `PubkeyAuthentication yes` explicit; verify checks added |
| T-11 | sshd baseline — `LoginGraceTime 60`, `MaxStartups 5:30:60`, `UseDNS no`, `GSSAPIAuthentication no` |
| T-12 | `configs/etc/issue.net` (new) → `/etc/issue.net` + `/etc/issue`; `Banner` in sshd baseline; verify checks added |
| T-13 | README section "Admin password & lockout recovery" + `passwd -S` verify check |
| T-14 | `scripts/collect-forensics.sh` (new) — snapshots into `logs/forensics-<stamp>/` |
| T-15 | Comment + explicit `KbdInteractiveAuthentication` in the sshd baseline; verify asserts both switches; note in C-04 |
| T-16 | Host-key fingerprints collected by `scripts/collect-forensics.sh` → `host-keys.txt`; record them in the lab manifest after the first run |
| T-17 | `scripts/generate-lab-traffic.sh` — COUNT validated (integer 1–100, clamped) |
| T-18 | `docs/services.md` — "Module 3 definition of done" gate |

### What still needs a human on the VM

1. Run `sudo ./scripts/setup.sh`, set the admin password, then `sudo ./tests/module1-verify.sh`.
2. Record the host-key fingerprints from `logs/forensics-*/host-keys.txt` into the lab manifest (T-16).
3. If outbound NTP is blocked in the lab, decide the T-08 fallback (allow NTP via NAT or set the clock manually) and update `docs/security-hardening.md` C-10 accordingly.

---

## Round 2 — external review of Stages 1–2 (implemented)

A second reviewer examined Stages 1 and 2 with fresh eyes. Verdict on each
item, and where it landed:

| Reviewer item | Decision | Where it landed |
|---|---|---|
| Document the analyzer's operational limitation | ✅ Implemented | `stage1/Project/outputs/README.md` "Scope and limitations"; analyzer docstring |
| Malformed/truncated packet handling | ✅ Implemented | analyzer `process()` try/except → `malformed_packets` counter, never crashes; `display_report` guards `summary()` |
| Minimal detection hooks (3 explainable rules) | ✅ Implemented | `stage1/Project/outputs/detections.py` — SYN flood, port scan, plaintext service; thresholds configurable via CLI; findings in `report["detections"]` |
| Preserve the report schema, extend only | ✅ Implemented | `schema_version: "traffic-report/1.0"`; `top_flows` structured objects (planned in `INTEGRATION.md` §6); `malformed_packets`; `detections` |
| Formal Stage 1 ↔ Stage 2 integration test | ✅ Implemented | `stage1/tests/integration_test.sh` (capture → trigger Kali traffic → verify report → evidence) + `tests/test_analyzer.py` pytest suite |
| SSH key-only transition, defined + verified | ✅ Implemented (docs) | README "Module 4 transition" table; C-04/C-06 register entries; T-15 note (flip both switches) |
| Patch-management strategy | ✅ Implemented | `unattended-upgrades` (security-only, no auto-reboot) — C-13; drop-in `configs/etc/apt/apt.conf.d/50securebank-unattended`; verify checks |
| Host-auditing strategy | ✅ Implemented | `docs/host-auditing.md` — persistent journal (C-15), `SB-DROP` firewall logging, forensics kit; auditd deferred with triggers |
| AppArmor / MAC evaluation | ✅ Implemented (verify) | C-14 — enforced/verified where the platform ships it; graceful skip on minimal Debian; custom profiles Module 4 |
| Authentication abuse protection (Fail2Ban) | ⏸ Deferred, documented | `docs/host-auditing.md` — would suppress Stage 6's authorized attack traffic; firewall + AllowUsers already bound the surface |
| Filesystem hardening | ⏸ Deferred, documented | host-auditing.md — no threat model demands it; auth/logging/patching matter more |
| AIDE / file-integrity | ⏸ Deferred, documented | host-auditing.md — config-drift detection already exists; binary integrity has no consumer yet |
| Expand verification | ✅ Implemented | `tests/module1-verify.sh` — unattended-upgrades, apt drop-in, journald persistence, `SB-DROP` log rule, AppArmor |
| INTEGRATION.md changelog | ✅ Implemented | `INTEGRATION.md` §10 contract changelog + §6 report changelog |
| Dead code: `PermissionError` unreachable | ✅ Fixed | `except PermissionError` moved before `except OSError` (flagged by the project's own CODE_EXPLANATION.md) |
