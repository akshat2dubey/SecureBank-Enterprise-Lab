# SecureBank Host Auditing Strategy (C-15)

**Decision date:** Module 1 · **Owner:** Stage 2 (server hardening) → consumed
by Stages 7 (SIEM) and 8 (Incident Response).

This document answers one question before any "let's install auditd" reflex:
**what host evidence does SecureBank need, where does it come from, and is
the current telemetry enough?**

---

## 1. What SecureBank needs to prove (evidence requirements)

Stage 8 must be able to reconstruct, for any simulated incident:

| Question | Evidence source |
|---|---|
| Who logged in / tried to log in? | `auth` journal entries (sshd Accepted/ Failed password), `last`/`lastb` |
| What services were touched? | journald `daemon` entries, service logs |
| What did the firewall drop? | nftables `SB-DROP` log lines (rate-limited) |
| What was the box doing at time T? | journald timeline + `collect-forensics.sh` snapshot |
| What config was applied? | setup-run audit logs + config sha256 hashes (drift check) |

The **source of truth is journald, stored persistently** (`Storage=persistent`
via `configs/etc/systemd/journald.conf.d/99-securebank.conf`). Stage 7 will
forward from it over syslog/RFC 5424 (INTEGRATION.md §5); Stage 8 will query
it directly.

## 2. What is in place (Module 1)

- **Persistent journal** — survives reboot, covers SSH, services, cron, and
  the kernel/firewall messages.
- **sshd logging at default facility `auth`** — Accepted/Failed/Invalid user
  events land in the journal; `ss -tn` and `journalctl _COMM=sshd` give the
  Stage 6/8 narrative.
- **Firewall drop logging** — the nftables input chain logs dropped inbound
  traffic with prefix `SB-DROP`, rate-limited to 5/s burst 10 (no log flood,
  still enough to see scans — Stage 7 detection feeds on it).
- **Evidence kit** — `scripts/collect-forensics.sh` snapshots processes,
  connections, journal excerpts, and config hashes into
  `logs/forensics-<timestamp>/` on demand (seeded *before* any incident).
- **Setup audit trail** — every `setup.sh` run is teed to `logs/setup-*.log`
  with applied-config hashes; `tests/module1-verify.sh` fails on drift.

## 3. What is deliberately deferred — and why

### auditd — DEFERRED (revisit at Module 5/Stage 8)
`auditd` adds per-syscall/file/exec records — powerful, but it is justified
only when Stage 8 defines *which* forensic questions need syscall-level
answers (e.g., "which file did the attacker touch via this process?").
Installing it now would add a second logging subsystem, a second retention
policy, and noise — with no consumer. **Trigger to implement:** Stage 8's
scenario design needs `ausearch`-style evidence. Until then, journald +
firewall logs + forensics snapshots are the defensible answer.

### Fail2Ban — DEFERRED (revisit at Module 4)
The firewall already restricts SSH to the lab subnet, `AllowUsers` limits
accounts, `MaxAuthTries 4` bounds tries per connection. Fail2Ban's real job —
blocking Internet brute force — does not exist in an isolated lab, and its
ban action would **conflict with Stage 6's authorized pentest methodology**
(scan/brute-force attempts are supposed to happen and be *detected*, not
suppressed). **Trigger to implement:** if the lab grows an Internet-facing
surface. Until then it is documented, not silently skipped.

### AIDE / file-integrity monitoring — DEFERRED
Stage 2 already hashes the *applied configs* and fails on drift
(`module1-verify.sh`). AIDE additionally covers *binaries* — but nothing in
the lab yet threatens binary integrity, and AIDE's baseline updates would
fight Stage 9's CI builds. **Trigger to implement:** Stage 8 needs
binary-integrity evidence, or Stage 9's pipeline demands it for release
gating. Do not duplicate the config-drift mechanism.

### Filesystem hardening (LVM/LUKS/noexec/nosuid layouts) — DEFERRED
Authentication, logging, patch management, and monitoring matter more for a
training lab than exotic mount options, and aggressive `noexec`/`nosuid`
breaks lab tooling with no threat model behind it. **Trigger to implement:**
Stage 3's threat model produces a concrete filesystem-integrity requirement.
Recorded as possible future enhancement, not applied.

## 4. How Stage 7 and Stage 8 consume this

- **Stage 7 (SIEM):** forward journald → syslog RFC 5424 (port 514/10514,
  INTEGRATION.md §5). Detection rules read `auth` (SSH brute force),
  `SB-DROP` (scanning), and service logs.
- **Stage 8 (IR):** pull evidence from the persistent journal and
  `logs/forensics-*/` snapshots; the setup-log hashes answer "was this
  config applied, and has it drifted?".

## 5. Verification (also in tests/module1-verify.sh)

```bash
cmp configs/etc/systemd/journald.conf.d/99-securebank.conf /etc/systemd/journald.conf.d/99-securebank.conf
test -d /var/log/journal                                   # persistent, not volatile
nft list ruleset | grep SB-DROP                            # firewall drop logging on
systemctl is-active systemd-journald
```
