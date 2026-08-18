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
- **Impact:** **revoked in Module 4** (key-only + fail2ban) — flip `PasswordAuthentication` **and** `KbdInteractiveAuthentication` to `no` together (T-15). Never deploy outside the lab.

### C-05 — UTC timezone (Module 1) ✅
- **Purpose:** comparable timestamps across all lab hosts.
- **Threat:** log correlation errors during Stage 7 / Stage 8 investigations.
- **Configuration:** `scripts/setup.sh` → `timedatectl set-timezone UTC`.
- **Verification:** `timedatectl`; `tests/module1-verify.sh`.
- **Impact:** none for the lab.

### C-06 — SSH access limited to the admin account (Module 1) ✅
- **Purpose:** only `securebank-admin` can SSH in, even while password auth is on.
- **Threat:** any local account with a password + shell becomes an SSH entry point; Module 3's service accounts become lateral-movement paths.
- **Configuration:** `AllowUsers` (rendered from `lab.env` at the repo root → `SB_ADMIN_USER` by `scripts/setup.sh`) + `PermitEmptyPasswords no` + `AllowAgentForwarding no` in the sshd baseline.
- **Verification:** `sshd -T | grep -i allowusers`; `tests/module1-verify.sh`.
- **Impact:** adding a new SSH user means touching one file; that's deliberate. (Review T-01.)

### C-07 — SSH DoS/auth posture made explicit (Module 1) ✅
- **Purpose:** bound trivial connection-exhaustion and remove unused/auth-slow mechanisms from the baseline.
- **Threat:** `MaxAuthTries 4` is per-connection (4 tries × unlimited connections — real limit arrives with fail2ban in Module 4); reverse-DNS lookups at login are slow and a log-poisoning vector; GSSAPI is unused.
- **Configuration:** `LoginGraceTime 60`, `MaxStartups 5:30:60`, `UseDNS no`, `GSSAPIAuthentication no`, `PubkeyAuthentication yes` in the sshd baseline.
- **Verification:** `sshd -T`; `tests/module1-verify.sh`.
- **Impact:** none in the lab. (Review T-11.)

### C-08 — Default-deny firewall, both IP families (Module 1) ✅
- **Purpose:** the box drops everything inbound except what the lab needs; the NAT NIC is no longer unfiltered.
- **Threat:** host-only/NAT misconfiguration leaks; services opened by later modules are exposed before Module 4 hardening.
- **Configuration:** `configs/etc/nftables.conf` (rendered from `lab.env` at the repo root), applied idempotently by `scripts/setup.sh` and loaded at boot by the `nftables` service. IPv6 filtered in the same `inet` table (T-07).
- **Verification:** `nft list ruleset` (input policy drop, SSH from `10.10.10.0/24`); `tests/module1-verify.sh`.
- **Impact:** new inbound services require an explicit rule — that is the point. Extend the file in Module 4; never hand-edit the box copy. (Review T-06/T-07.)

### C-09 — sysctl network-hardening baseline (Module 1) ✅
- **Purpose:** anti-spoofing, redirect/source-route rejection, martian logging, SYN cookies.
- **Threat:** ICMP-redirect MITM and spoofing on the shared lab segment; SYN-flood resource exhaustion.
- **Configuration:** `configs/etc/sysctl.d/99-securebank.conf` → `/etc/sysctl.d/`, applied with `sysctl --system`. IPv6 hardened, not disabled (T-07).
- **Verification:** `sysctl net.ipv4.conf.all.rp_filter` etc.; `tests/module1-verify.sh`.
- **Impact:** none for the lab. (Review T-09.)

### C-10 — NTP enabled (Module 1) ✅
- **Purpose:** a *correct* clock, not just a UTC zone — Stages 7/8 correlation depends on it.
- **Threat:** clock drift silently corrupts log correlation and evidence timestamps.
- **Configuration:** `timedatectl set-ntp true` (systemd-timesyncd). Isolated lab note: if NTP is blocked, allow it via the NAT NIC or set the clock manually — decision in `docs/security-review.md` T-08.
- **Verification:** `timedatectl show -p NTP --value` = `yes`; `tests/module1-verify.sh`.
- **Impact:** none for the lab.

### C-11 — Authorized-use banner (Module 1) ✅
- **Purpose:** legal/authorized-use notice on SSH and console logins — realism for the lab narrative and Stage 5/8 write-ups.
- **Threat:** unlabeled systems invite accidental unauthorized use; assessment findings will cite its absence.
- **Configuration:** `configs/etc/issue.net` → `/etc/issue.net` + `/etc/issue`; `Banner /etc/issue.net` in the sshd baseline.
- **Verification:** SSH login shows the banner; `sshd -T | grep -i banner`; `tests/module1-verify.sh`.
- **Impact:** none. (Review T-12.)

### C-12 — Local ed25519 admin keypair (Module 1) ✅
- **Purpose:** key auth works from day one, and Module 4's key-only switch is config-only instead of a scramble; the traffic script's loopback SSH becomes a genuine auth success.
- **Threat:** none directly — foundation for the Module 4 revocation of C-04.
- **Configuration:** `scripts/setup.sh` generates `~/.ssh/id_ed25519` for the admin user and self-authorizes the public key. **This key is loopback-only** — a private key that never leaves the server cannot authenticate clients. Kali's own key is provisioned with `ssh-keygen` + `ssh-copy-id` (README).
- **Verification:** key exists, `authorized_keys` contains its pubkey; `tests/module1-verify.sh`.
- **Impact:** a passwordless local key is safe in the lab because anyone who can read it already has admin. (Review T-10.)

### C-13 — Security-only automatic updates (Module 1) ✅
- **Purpose:** "starts patched" must not mean "stays unpatched" — security fixes arrive without admin action, feature updates and reboots do not.
- **Threat:** known, publicly-available vulnerabilities on an unpatched box (the #1 real-world initial-access vector).
- **Configuration:** `unattended-upgrades` + managed drop-in `configs/etc/apt/apt.conf.d/50securebank-unattended` → `/etc/apt/apt.conf.d/` — security origins only (`${distro_id}:${distro_codename}-security`), `Automatic-Reboot "false"`, actions logged to journald.
- **Verification:** `dpkg -s unattended-upgrades`; drop-in `cmp` against template; `tests/module1-verify.sh`.
- **Impact:** a lab VM may change under you after an update — acceptable and realistic; reboots stay manual so a live lab session is never interrupted. (Reviewer S2.2.)

### C-14 — AppArmor MAC — enforced where the platform ships it (Module 1) ✅
- **Purpose:** mandatory access control is deliberately *checked and enforced*, not installed to tick a box. Ubuntu ships AppArmor default-on; a minimal Debian install may not.
- **Threat:** a compromised service process escaping its role and touching the rest of the system.
- **Configuration:** none applied by us — the OS default; we *verify* it is enforcing (`aa-enabled`, `aa-status --enforced`) and record it as a control. Custom profiles are a Module 4 task once real services exist (Module 3).
- **Verification:** `aa-enabled` = Yes and ≥1 profile in enforce mode; `tests/module1-verify.sh` (skips gracefully when absent).
- **Impact:** on minimal Debian the check is skipped and the gap is documented, not silently ignored. (Reviewer S2.4.)

### C-15 — Host auditing: persistent journal + firewall drop logs (Module 1) ✅
- **Purpose:** a defensible host-evidence strategy *before* Incident Response exists — see `docs/host-auditing.md` for the full reasoning.
- **Threat:** no evidence to reconstruct an incident (Stage 8); no telemetry for detection (Stage 7).
- **Configuration:** journald `Storage=persistent` (`configs/etc/systemd/journald.conf.d/99-securebank.conf`); nftables `log prefix "SB-DROP"` (rate-limited 5/s burst 10) on the input drop path; `collect-forensics.sh` on-demand snapshots; setup-log config hashes.
- **Verification:** `test -d /var/log/journal`; `nft list ruleset | grep SB-DROP`; `tests/module1-verify.sh`.
- **Impact:** disk usage grows with logs — bounded by journald rotation, acceptable for the lab. auditd deliberately deferred (see host-auditing.md). (Reviewer S2.3.)

## Planned but deliberately not applied yet

| Control | Module | Why it waits |
|---|---|---|
| Key-only SSH | 4 | Module 1 teaches password SSH safely inside the isolated lab; flip `PasswordAuthentication` **and** `KbdInteractiveAuthentication` to `no` together (T-15) — Kali's key is already provisioned |
| Firewall extension for real services | 4 | The default-deny baseline is applied (C-08); Module 3 defines the service list, Module 4 opens it |
| Fail2Ban | 4 | Would suppress Stage 6's authorized attack traffic before SIEM can detect it; firewall + AllowUsers already bound the surface — see docs/host-auditing.md |
| AppArmor custom profiles | 4 | After real services exist (Module 3); enforcement itself is verified today (C-14) |
| Log rotation / retention policy | 5 | Aligned with Stage 7 SIEM needs |
| auditd | 5+ | Only when Stage 8's scenarios need syscall-level evidence — see docs/host-auditing.md |
| AIDE / file-integrity | deferred | Config-drift detection already exists; binary integrity has no consumer yet — see docs/host-auditing.md |
| Filesystem hardening (LVM/LUKS/noexec/nosuid) | deferred | No threat model demands it yet; authentication/logging/patching matter more — see docs/host-auditing.md |

## Verification commands (run inside the lab)

```bash
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|allowusers|permitemptypasswords|allowagentforwarding|logingracetime|maxstartups|usedns|gssapiauthentication|banner'
nft list ruleset | grep -E 'policy drop|10.10.10.0/24'
sysctl net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects
timedatectl show -p NTP --value
getent group sudo
systemctl status ssh nftables
ss -tlnp
```
