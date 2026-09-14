# Stage 2 — SecureBank Linux Server

> The infrastructure foundation of the SecureBank Enterprise Lab.
> **Status: foundation complete (Module 1) + Module 2 code complete — verify on the VM. Modules 2–8 planned — see the roadmap below.** Static addressing is code-complete; service isolation, telemetry forwarding, and full validation land in Modules 3–7.

## What this is

A hardened, monitored, reproducible Linux server that plays the role of SecureBank's
backend infrastructure inside the lab. It is one component of the **interconnected**
SecureBank Enterprise Lab, not a standalone exercise:

```
Stage 1 Traffic Analyzer  <->  Stage 2 Linux Server  <->  Stages 3–9
       (observes)                    (this stage)            (consume/provide)
```

The server will eventually:

- expose controlled services (web, application, database) that later stages host and test,
- generate meaningful network traffic for **Stage 1** to analyze,
- produce clean security telemetry for the **Stage 7 SIEM** and **Stage 8 incident response**,
- be documented well enough for the **Stage 3 threat model** and **Stage 5 reconnaissance**,
- be reproducible enough for **Stage 9 DevSecOps** automation.

## Design principles

1. **Predictable identity** — static lab IPs, stable hostnames, documented ports.
2. **Loose coupling** — standard logs and services only; no SIEM/agent/framework lock-in before a later stage decides.
3. **Minimalism** — only install what SecureBank needs; document every service.
4. **Reproducibility** — idempotent Bash scripts now; Ansible/IaC can wrap them later.
5. **Integration-first** — before any decision, ask: *does this make Stages 3–9 harder?*

Full reasoning: [docs/architecture.md](docs/architecture.md)

## Module roadmap

| # | Module | Focus | Status |
|---|--------|-------|--------|
| 1 | Server Foundation | VM, OS, users, groups, packages, SSH, baseline hardening (firewall, sysctl, banner, NTP) | ✅ Done |
| 2 | Network Configuration | static IP + IPv6 ULA on the lab NIC, peer snippets, verify checks | 🟡 Code complete — verify on the VM |
| 3 | Services & Application Infrastructure | minimal banking services | ⏳ Planned |
| 4 | Server Hardening | SSH hardening, firewall, least privilege, updates | ⏳ Planned |
| 5 | Logging & Telemetry | auth/SSH/system/service/firewall logs | ⏳ Planned |
| 6 | Stage 1 Integration | verified traffic between Stage 1 <-> Stage 2 | ⏳ Planned |
| 7 | Security Validation | nmap, lynis, posture report | ⏳ Planned |
| 8 | Documentation & Reproducibility | full docs + repeatable setup | ⏳ Planned |

## Repository layout

```
stage2-securebank-linux-server/
├── README.md
├── docs/
│   ├── architecture.md        # design, decisions, Stage 3–9 integration points
│   ├── network-design.md      # topology, IP/hostname/port plan, DNS strategy
│   ├── security-hardening.md  # control register (purpose / threat / config / verify / impact)
│   ├── security-review.md     # architecture review punch list (T-01…T-18, all implemented)
│   ├── host-auditing.md       # host evidence strategy + deferrals (auditd/Fail2Ban/AIDE)
│   └── services.md            # service inventory + log locations
├── scripts/
│   ├── setup.sh               # Modules 1+2: foundation, hardening, static lab addressing (run as root on the VM)
│   ├── generate-lab-traffic.sh# Stage 1 traffic generation
│   ├── collect-forensics.sh   # evidence snapshot (Stage 8 seed) + drift detection
│   └── render-peer-configs.sh # Module 2: render Kali/analyzer snippets from lab.env (no root)
├── configs/
│   ├── etc/                   # banner, firewall, sshd, sysctl, apt, journald, net configs (rendered from lab.env)
│   │   ├── issue.net          # authorized-use banner
│   │   ├── nftables.conf      # default-deny firewall, IPv4 + IPv6, SB-DROP logging
│   │   ├── ssh/sshd_config.d/99-securebank.conf
│   │   ├── sysctl.d/99-securebank.conf
│   │   ├── apt/apt.conf.d/50securebank-unattended   # security-only auto-updates
│   │   ├── netplan/99-securebank.yaml               # Module 2: static lab NIC (Ubuntu)
│   │   ├── systemd/network/10-securebank-lab.network # Module 2: static lab NIC (Debian)
│   │   └── cloud/cloud.cfg.d/99-securebank-network.cfg # cloud-init network opt-out
│   └── other-vms/             # peer-VM snippet TEMPLATES (@VAR@ placeholders; render, don't copy)
├── outputs/                   # rendered peer snippets (git-ignored)
├── logs/                      # runtime logs (git-ignored)
└── tests/
    └── module1-verify.sh      # Modules 1+2 automated verification
```

## Quick start (Module 1)

Requires: a **Debian 12 / Ubuntu 24.04 server VM** in the lab (see
[docs/architecture.md](docs/architecture.md) — do not use your Kali box as the server).

```bash
# 1. Copy this stage into the VM (from your host), then run as root
sudo -i
./scripts/setup.sh

# 2. Set the admin password (the script tells you if it's missing)
passwd securebank-admin
# NOTE: setup.sh also applies a default-deny firewall, but a self-lockout
# guard aborts first if your live SSH session's REMOTE PEER is outside the
# lab subnet (10.10.10.0/24) — or if it cannot determine the peer at all
# (fail closed). Fix the NIC or re-run with SB_FIREWALL_SKIP=1 to skip the
# firewall for now — the VM console always works.

# 3. From Kali, connect and confirm (first time: provision Kali's key)
#    Kali is the SOLE admin-key origin — the server generates no keys.
ssh-keygen -t ed25519
ssh-copy-id securebank-admin@<server-ip>
ssh securebank-admin@<server-ip>

# 4. Verify the module on the server
./tests/module1-verify.sh

# 5. Optional, once Stage 1 is ready: generate traffic it can see.
#    Run this ON KALI (client mode) so SSH/HTTP/ping cross the segment:
./scripts/generate-lab-traffic.sh   # see docs/network-design.md §5
```

## Module 2: static lab addressing (quick reference)

The lab NIC holds `10.10.10.10/24` + `fd00:10:10::10/64` statically (C-16);
the NAT NIC keeps DHCP for updates. Details, failure modes, and the peer-VM
snippets: [docs/network-design.md §7](docs/network-design.md).

```bash
# On the server VM (console or SSH from the final address):
sudo ./scripts/setup.sh            # applies static addressing + everything from Module 1
sudo ./tests/module1-verify.sh     # now also verifies Module 2 effective state

# On your host (no root): render the peer VM snippets and copy them over
./scripts/render-peer-configs.sh   # -> outputs/peer-configs/*.md

# Escape hatches (mirroring SB_FIREWALL_SKIP):
#   SB_NET_SKIP=1               skip static addressing this run
#   SB_NET_SKIP=1 SB_NET_FORCE=1  apply anyway and accept the SSH session drop
```

## Patch management (C-13)

The box **starts patched** (`setup.sh` runs a one-time `full-upgrade`). To make
sure it **stays patched**, security updates are automatic:

- **What:** security-origin packages only (`-security` pocket) — no surprise
  feature upgrades or backports.
- **How often:** `unattended-upgrades` checks daily; actions are logged to
  journald (visible to Stage 7/8).
- **Reboots:** never automatic — the admin reboots on their own schedule, so a
  live lab session is never interrupted.
- **Verified:** `tests/module1-verify.sh` checks the package + drop-in content.

Config: `configs/etc/apt/apt.conf.d/50securebank-unattended`.

## Host auditing (C-15)

SecureBank's evidence strategy is written down **before** Incident Response
needs it — see [docs/host-auditing.md](docs/host-auditing.md). In short:
persistent journal + SSH auth logs + rate-limited firewall drop logs
(`SB-DROP`) + on-demand forensics snapshots. `auditd`, Fail2Ban, and AIDE are
**deliberately deferred** with documented triggers — not installed to tick a box.

## Admin password & lockout recovery (T-13)

- **Policy:** the admin password must be ≥ 14 characters and not reused from any
  other system. It is set on the box (`passwd securebank-admin`) and **never**
  stored in this repository.
- **Rotation:** change it whenever the lab is shared or a participant leaves.
- **Locked out?** Use the **VM console** (not SSH): log in on the console and run
  `sudo -i` then `passwd securebank-admin`. No factory reset needed.
- **Going forward:** Module 4 switches to key-only SSH. The key that matters
  is **Kali's**, generated on Kali and authorized on the server:

  ```bash
  # on Kali (once):
  ssh-keygen -t ed25519
  ssh-copy-id securebank-admin@<server-ip>
  ```

  The server generates NO keys of its own: admin keys come from Kali only.
  A private key created on the server could never authenticate Kali, so
  setup.sh only ensures `~/.ssh` exists with correct permissions and leaves
  whatever Kali provisioned untouched. Never move a private key between
  machines.

## Module 4 transition: SSH key-only authentication

Module 1 deliberately leaves password auth **on** so you learn the password
flow safely inside the isolated lab. Module 4 revokes it. The switch is
**config-only** because Kali's key is already provisioned — nothing to rebuild:

```
Module 1 baseline (current)          Module 4 hardened SSH (planned)
----------------------------         ------------------------------
PasswordAuthentication      yes  ->  no
KbdInteractiveAuthentication yes  ->  no     # flip BOTH together (T-15)
PubkeyAuthentication        yes  ->  yes    # unchanged — already enforced
PermitRootLogin             no   ->  no     # unchanged
AllowUsers                  admin->  admin  # unchanged
```

**The rule that prevents lockout:** `PasswordAuthentication` and
`KbdInteractiveAuthentication` must change **in the same edit** — PAM still
accepts passwords through keyboard-interactive if only the first is flipped.
Test after the flip: `sshd -t && systemctl restart ssh`, then log in **from
Kali with the key** before closing your current session. See
[docs/security-hardening.md](docs/security-hardening.md) C-04/C-06 and the
sshd drop-in comment.

## Lab security notice

This is an **isolated, authorized training lab**. The server must never be reachable
from the internet or a production network. All testing against it (Stages 5–6) is
performed by you, on your own VMs, inside the lab network only.
