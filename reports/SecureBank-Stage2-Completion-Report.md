# SecureBank Enterprise Lab — Stage 2 Completion Report

**Stage:** 2 — SecureBank Linux Server
**Status:** ✅ Module 1 complete (Server Foundation + baseline hardening)
**Date:** August 2026
**Ecosystem:** one of nine interconnected stages (see `INTEGRATION.md` at the repo root)

---

## 1. Executive summary

Stage 2 is SecureBank's **hardened, monitored, reproducible backend server** —
the center of gravity of the lab: nearly every other stage watches it (1, 7),
tests it (5, 6), hosts on it (4), investigates it (8), models it (3), or
deploys it (9).

Module 1 delivered a foundation that is **patched from day one**, protected by a
default-deny firewall on both IP families, restricted at the SSH layer,
time-synchronized (UTC + NTP), and audited (persistent journal, firewall drop
logging, on-demand forensics snapshots, config-hash drift detection). Fifteen
hardening controls (C-01…C-15) are documented in a register with purpose,
threat, configuration, verification, and impact — nothing is applied "because
someone said so."

All automation is **idempotent Bash** driven by a single source of truth
(`lab.env` at the repo root), and the module is verified by a ~60-check
automated suite that checks *effective runtime state*, not just file existence.

## 2. Mission in the ecosystem

> "SecureBank now has infrastructure that needs to be protected and monitored."

- **Consumes:** `lab.env` (single source of truth), repo config templates.
- **Produces:** hardened host, managed `/etc/hosts`, sshd drop-in, firewall,
  sysctl, persistent journal, config hashes, forensics snapshots.
- **Feeds:** Stage 1 (traffic), Stage 3 (hardening register → threat model),
  Stage 7 (journald → syslog RFC 5424), Stage 8 (evidence kit), Stage 9 (IaC).
- **Contract:** every address/port/format reserved in `INTEGRATION.md`.

## 3. Module 1 deliverables

| Artifact | Role |
|---|---|
| `scripts/setup.sh` | idempotent foundation + hardening (run as root) |
| `scripts/generate-lab-traffic.sh` | Stage 1 traffic generation (client/self modes) |
| `scripts/collect-forensics.sh` | evidence snapshot + drift baseline (Stage 8 seed) |
| `tests/module1-verify.sh` | ~60 automated checks of effective state |
| `configs/etc/ssh/sshd_config.d/99-securebank.conf` | SSH baseline (AllowUsers rendered from lab.env) |
| `configs/etc/nftables.conf` | default-deny firewall, IPv4 + IPv6, `SB-DROP` logging |
| `configs/etc/sysctl.d/99-securebank.conf` | network-hardening kernel parameters |
| `configs/etc/issue.net` | authorized-use banner |
| `configs/etc/apt/apt.conf.d/50securebank-unattended` | security-only automatic updates |
| `configs/etc/systemd/journald.conf.d/99-securebank.conf` | persistent journal |
| `docs/security-hardening.md` | control register C-01…C-15 |
| `docs/host-auditing.md` | evidence strategy + documented deferrals |
| `lab.env` (repo root) | single source of truth for all lab identity |

## 4. Security controls applied (C-01 … C-15)

| ID | Control | Threat addressed |
|---|---|---|
| C-01 | Root SSH login disabled | credential theft of the most privileged account |
| C-02 | Dedicated admin user in `sudo` group | least privilege; no root-from-day-one |
| C-03 | Minimal base package set (`--no-install-recommends`) | smaller attack surface |
| C-04 | Password auth TEMPORARY (learning; isolated lab) | — revoked in Module 4 |
| C-05 | UTC timezone | log-correlation errors (Stages 7/8) |
| C-06 | SSH limited to the admin account (`AllowUsers`) | other accounts become entry points |
| C-07 | SSH DoS/auth posture explicit (LoginGraceTime, MaxStartups, UseDNS no, GSSAPI no, MaxAuthTries 4) | connection exhaustion, slow/pollutable logins |
| C-08 | Default-deny firewall, both IP families | exposure of not-yet-hardened services |
| C-09 | sysctl network hardening | spoofing, redirect MITM, SYN floods |
| C-10 | NTP enabled | clock drift corrupts evidence |
| C-11 | Authorized-use banner | legal/authorized-use notice |
| C-12 | Local ed25519 keypair (loopback; Kali key via ssh-copy-id) | Module 4 key-only switch is config-only |
| C-13 | Security-only automatic updates | known-vulnerability exploitation |
| C-14 | AppArmor enforced where the platform ships it | compromised service escape |
| C-15 | Persistent journal + firewall drop logging + forensics kit | no evidence to investigate incidents |

## 5. SSH baseline (effective settings)

| Setting | Value | Why |
|---|---|---|
| `PermitRootLogin` | no | no direct root SSH (C-01) |
| `PasswordAuthentication` | yes (TEMPORARY) | Module 1 learning; revoked in Module 4 |
| `KbdInteractiveAuthentication` | yes (TEMPORARY) | must flip **with** the above (T-15) |
| `MaxAuthTries` | 4 | bound per-connection guessing |
| `AllowUsers` | `securebank-admin` (from lab.env) | guest list (C-06) |
| `PermitEmptyPasswords` | no | no lockless doors |
| `AllowAgentForwarding` | no | cuts SSH-agent pivoting |
| `PubkeyAuthentication` | yes | key auth live from day one |
| `LoginGraceTime` | 60 | bound idle auth |
| `MaxStartups` | 5:30:60 | bound connection floods |
| `UseDNS` / `GSSAPIAuthentication` | no | remove slow/unused mechanisms |
| `Banner` | `/etc/issue.net` | authorized-use notice |

## 6. Firewall policy (nftables, `inet` table — IPv4 + IPv6)

Default deny inbound; outbound allowed (updates via NAT NIC); forward dropped.

| Rule | Action |
|---|---|
| established/related return traffic | accept |
| loopback | accept |
| DHCP client replies (67→68) | accept (Module 1; static in Module 2) |
| ICMP echo-request | accept (Stage 1 traffic script) |
| ICMPv6 echo + neighbor discovery | accept (IPv6 stays enabled, filtered) |
| SSH from `10.10.10.0/24` (IPv4) and `fe80::/10` (link-local v6) | accept |
| everything else inbound | **drop + log** `SB-DROP` (rate-limited 5/s burst 10) |

**Self-lockout guard:** setup.sh reads the live SSH session's source address
(`ss`) and aborts with a clear message before applying the firewall if it
would cut the admin's own session (escape hatch: `SB_FIREWALL_SKIP=1`).

## 7. sysctl network-hardening baseline

| Parameter | Value |
|---|---|
| `net.ipv4.conf.{all,default}.rp_filter` | 1 (anti-spoofing) |
| `net.ipv4/6.conf.{all,default}.accept_redirects` | 0 (redirect MITM) |
| `net.ipv4/6.conf.{all,default}.accept_source_route` | 0 |
| `net.ipv4.conf.{all,default}.log_martians` | 1 (visibility) |
| `net.ipv4.tcp_syncookies` | 1 (SYN-flood mitigation) |

IPv6 is hardened, not disabled — it is filtered by the same `inet` firewall.

## 8. Patch management & host auditing

**Patch management (C-13):** the box starts patched (one-time `full-upgrade`)
and **stays patched** — `unattended-upgrades` applies security-origin updates
only, daily, with reboots always manual. Failures are visible (service-active
verify check; journald + `/var/log/unattended-upgrades` logs).

**Host auditing (C-15)** — full strategy in `docs/host-auditing.md`:
persistent journal (survives reboot) → Stage 7 forwarder (syslog RFC 5424,
ports 514/10514 reserved); SSH auth events; rate-limited `SB-DROP` firewall
logs; `collect-forensics.sh` on-demand snapshots (processes, connections,
host-key fingerprints, config hashes, package baseline, update state).

**Deliberately deferred (documented, with triggers):** `auditd` (until Stage 8
needs syscall-level evidence), Fail2Ban (would suppress Stage 6's authorized
attack traffic; firewall + AllowUsers already bound the surface), AIDE
(config-drift detection already exists), filesystem hardening (no threat model
demands it yet).

## 9. Integration contract

- **`lab.env` (repo root):** subnet `10.10.10.0/24`, server `.10`, Kali `.20`,
  analyzer `.30`, hostnames, admin user, timezone, IPv6 ULA `fd00:10:10::/48`.
  Overridable per-run; **no secrets** ever.
- **`INTEGRATION.md` (v1.0):** address registry, reserved ports (22, 53,
  80/443, 3306/5432, 514/10514), UTC/ISO-8601 time rule, RFC 5424 log
  transport, Stage 1 report schema, artifact naming, change policy, contract
  changelog.
- **Reserved ports** are reserved *before* the services exist so Stages 1/5/6/7
  can rely on them.

## 10. Verification

`tests/module1-verify.sh` (~60 checks) verifies **effective state**, not file
existence: per-setting `sshd -T`, `nft list ruleset`, `sysctl`, `passwd -S`
lockout, rendered-template `cmp`, package presence, patch policy, journal
persistence, AppArmor (where present), and **drift detection** — live config
hashes compared against the last `setup.sh` run; drift = FAIL (seed of Stage 8
integrity monitoring).

Setup itself records an audit trail: every run is teed to
`logs/setup-<stamp>.log` with applied-config sha256 hashes; package baseline
snapshots to `logs/package-baseline-<stamp>.txt`.

## 11. Admin procedures (must-know)

- **Password:** ≥ 14 characters, not reused elsewhere; set on the box with
  `passwd securebank-admin`; **never** committed to the repo.
- **Locked out?** Use the VM console (not SSH): `sudo -i` then `passwd`.
- **Kali access (key):** on Kali once — `ssh-keygen -t ed25519`, then
  `ssh-copy-id securebank-admin@<server-ip>`. The server's own key is
  loopback-only (traffic script).
- **Reboot after kernel upgrade** before continuing to Module 2.

## 12. Roadmap — what comes next for Stage 2

| Module | Focus | Status |
|---|---|---|
| 2 | Network Configuration — static IPs, DNS, routing, IPv6 ULA | 🔜 Next |
| 3 | Services & Application Infrastructure (minimal banking services) | ⏳ Planned |
| 4 | Server Hardening — key-only SSH (flip both switches, T-15), firewall extension, AppArmor profiles | ⏳ Planned |
| 5 | Logging & Telemetry — journald → syslog RFC 5424 to Stage 7 | ⏳ Planned |
| 6 | Stage 1 Integration — verified traffic between Stage 1 ↔ Stage 2 | ⏳ Planned |
| 7 | Security Validation — nmap, lynis, posture report | ⏳ Planned |
| 8 | Documentation & Reproducibility | ⏳ Planned |
