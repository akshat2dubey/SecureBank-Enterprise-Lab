# Stage 2 — SecureBank Linux Server

> The infrastructure foundation of the SecureBank Enterprise Lab.
> **Status: Module 1 complete (Server Foundation).** Modules 2–8 planned — see the roadmap below.

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
| 1 | Server Foundation | VM, OS, users, groups, packages, SSH | ✅ Done |
| 2 | Network Configuration | static IP, interfaces, DNS, routing, ports | 🔜 Next |
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
│   └── services.md            # service inventory + log locations
├── scripts/
│   └── setup.sh               # Module 1: server foundation (run on the VM, as root)
├── configs/
│   └── etc/
│       ├── hosts              # lab host table (one source of truth)
│       └── ssh/sshd_config.d/99-securebank.conf
├── logs/                      # runtime logs (git-ignored)
└── tests/
    └── module1-verify.sh      # Module 1 automated verification
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

# 3. From Kali, connect and confirm
ssh securebank-admin@<server-ip>

# 4. Verify the module on the server
./tests/module1-verify.sh

# 5. Optional, once Stage 1 is ready: generate the traffic it analyzes
./scripts/generate-lab-traffic.sh   # see docs/network-design.md §5
```

## Lab security notice

This is an **isolated, authorized training lab**. The server must never be reachable
from the internet or a production network. All testing against it (Stages 5–6) is
performed by you, on your own VMs, inside the lab network only.
