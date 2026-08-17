# SecureBank Linux Server — Security Hardening Register

**Method:** every control is defined by five fields — **Purpose**, **Threat
addressed**, **Configuration**, **Verification**, **Impact / trade-off**.
Nothing is applied "because someone said so"; each control earns its place.

## Applied controls

### C-01 — Root login over SSH disabled (Module 1) ✅
- **Purpose:** no direct root SSH; admins log in as a normal user and elevate with `sudo`.
- **Threat:** brute force / credential theft of the most privileged account.
- **Configuration:** `configs/etc/ssh/sshd_config.d/99-securebank.conf` → `PermitRootLogin no` (+ `MaxAuthTries 4`).
- **Verification:** `sshd -T | grep -i permitrootlogin`; also `tests/module1-verify.sh`.
- **Impact:** admins must use `sudo`; low effort, high value.

### C-02 — Dedicated admin user in the `sudo` group (Module 1) ✅
- **Purpose:** least privilege — everyday work is non-root; elevation is explicit.
- **Threat:** accidental damage or malware running with root from day one.
- **Configuration:** `scripts/setup.sh` creates `securebank-admin` (default) in group `sudo`.
- **Verification:** `getent group sudo`; `tests/module1-verify.sh`.
- **Impact:** none for the lab; mirrors enterprise practice.

### C-03 — Minimal base package set (Module 1) ✅
- **Purpose:** smaller attack surface; fewer packages to patch.
- **Threat:** vulnerabilities in software that is never used.
- **Configuration:** `BASE_PACKAGES` list in `scripts/setup.sh`, each with a comment explaining why it is installed.
- **Verification:** `dpkg -l | wc -l`; `tests/module1-verify.sh`.
- **Impact:** fewer "toys" on the server; add packages deliberately per module.

### C-04 — SSH password authentication — TEMPORARY (Module 1) ⚠️
- **Purpose:** learning only: key generation, `ssh`, `scp`, and password flows in Module 1.
- **Threat:** password brute force — acceptable **only** because the lab network is isolated.
- **Configuration:** `PasswordAuthentication yes` in the sshd baseline (explicit, not defaulted).
- **Verification:** `sshd -T | grep -i passwordauthentication`.
- **Impact:** **revoked in Module 4** (key-only + fail2ban). Never deploy outside the lab.

### C-05 — UTC timezone (Module 1) ✅
- **Purpose:** comparable timestamps across all lab hosts.
- **Threat:** log correlation errors during Stage 7 / Stage 8 investigations.
- **Configuration:** `scripts/setup.sh` → `timedatectl set-timezone UTC`.
- **Verification:** `timedatectl`; `tests/module1-verify.sh`.
- **Impact:** none for the lab.

## Planned but deliberately not applied yet

| Control | Module | Why it waits |
|---|---|---|
| Key-only SSH + fail2ban | 4 | Module 1 teaches password SSH safely inside the isolated lab |
| Firewall (nftables/UFW), default-deny | 4 | Module 3 must define the real service list first |
| Automatic security updates | 4 | Decide a policy, don't "just enable" |
| Log rotation / retention policy | 5 | Aligned with Stage 7 SIEM needs |
| AppArmor / auditd | 4–5 | After real services exist (Module 3) |

## Verification commands (run inside the lab)

```bash
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'
getent group sudo
systemctl status ssh
ss -tlnp
```
