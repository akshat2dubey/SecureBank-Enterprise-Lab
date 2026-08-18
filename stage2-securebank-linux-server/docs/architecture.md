# SecureBank Linux Server — Architecture

**Status:** Module 1 complete. This document is the canonical reference for how
Stage 2 fits the SecureBank Enterprise Lab and how it reserves integration
points for Stages 3–9.

## 1. Role in the ecosystem

The SecureBank Linux Server is the **target / enterprise** component of the lab.
It represents the backend infrastructure of the fictional SecureBank and is the
node that later stages observe, model, test, monitor, and investigate.

```
Kali (attacker/testing env)  ──►  SecureBank Linux Server (target/enterprise)
        ▲  network traffic                    │
        │                                     ├─► logs & telemetry (Stages 7, 8)
        └──────────────  Stage 1 Traffic Analyzer (passive capture)
```

Stage 1 monitors *traffic to/from* the server. Stages 3–9 consume *artifacts of
the server*: documentation, addressing, services, logs, and reproducible config.

## 2. Design principles

| Principle | What it means for Stage 2 |
|---|---|
| **Predictable identity** | Static lab IPs, stable hostnames, documented ports — Stage 1 filters, Stage 5 scans, Stage 6 targets, and Stage 7 sources all rely on these. |
| **Loose coupling** | Standard logs and services only. No SIEM, agent, or framework is chosen now; Stage 7 decides that later. Nothing in Stage 2 assumes a specific future tool. |
| **Minimalism** | Only services SecureBank actually needs. Every service is documented with purpose + security notes before it is installed. |
| **Reproducibility** | Idempotent Bash scripts and file-based configs today; Ansible/IaC can wrap them in Stage 9 without rework. |
| **Integration-first** | Before any decision: *"Does this make Stages 3–9 harder?"* If yes → identify the problem, weigh the trade-off, propose an alternative. |

## 3. Component view

One server VM for now. The design keeps *identity, naming, and ports* centralized
in docs/network-design.md so the server can later be split into web/db/monitoring
hosts without renaming anything.

| Plane | Contains | Status |
|---|---|---|
| Foundation | OS, users, groups, packages, SSH | Module 1 ✅ |
| Network identity | static IP, interfaces, /etc/hosts, DNS strategy | Module 2 |
| Services | sshd today; web / app / DB reserved | Module 3 |
| Hardening | Baseline applied Module 1 (default-deny firewall, sysctl, banner, NTP, SSH allow-list); full hardening (key-only SSH, fail2ban, updates policy) | Module 4 |
| Telemetry | auth/SSH/system/service/firewall logs + retention | Module 5 |

## 4. Reserved integration points (Stages 3–9)

| Stage | What it needs from Stage 2 | Where it is reserved |
|---|---|---|
| **3 — Threat model** | Asset inventory, services, users, trust boundaries, attack surface | `docs/architecture.md`, `docs/services.md`, `docs/network-design.md` |
| **4 — VulnBank app** | A home for the app + database, predictable addressing | Ports 80/443 + 3306/5432 reserved; app/service user role planned in Module 3 |
| **5 — BankRecon** | Authoritative target list: hostnames, IPs, services | IP/hostname/port tables in `docs/network-design.md` |
| **6 — Pentest** | Authorized, documented targets inside the lab | The VM list in `docs/network-design.md` is the scope boundary |
| **7 — SIEM** | Clean, forwardable logs (auth, syslog, journald, service, firewall) | Module 5; standard formats only, no vendor lock-in |
| **8 — Incident response** | Preserved evidence: logs, timestamps, process info | Module 5 log retention + evidence map |
| **9 — DevSecOps** | Reproducible setup | Idempotent scripts in `scripts/`, configs as files, docs |

## 5. Key decisions and their integration impact

| Decision | Why | Integration impact |
|---|---|---|
| **Debian/Ubuntu server, not Kali** | Kali is a testing distro, not enterprise infrastructure. The attacker/target boundary must stay visible. | Standard OS for all later stage tooling; no conflicts. |
| **Static lab IP 10.10.10.10** | Stage 1 filters, Stage 5 scans, Stage 6 targets, Stage 7 sources all need a stable address. | Predictable everywhere; configured in Module 2. |
| **Host-only + NAT NICs** | Host-only = lab traffic (visible to Stage 1); NAT = package updates only. | Stage 1 captures the host-only segment; the firewall never blinds the analyzer because capture is passive. |
| **/etc/hosts names, no DNS server yet** | Zero moving parts; names like `securebank-srv.securebank.lab` work lab-wide. | A real DNS server (dnsmasq/BIND) can be added later without renaming anything. |
| **Standard logs only** | The SIEM choice stays open until Stage 7. | rsyslog/journald are forwardable to any SIEM later. |
| **Bash + config files, not Ansible yet** | Matches current skill level; scripts are idempotent. | Stage 9 can wrap these scripts in Ansible/Terraform. |
| **SSH on port 22 (default)** | Realistic for pentest stages; changing the port is weak security anyway. | Stage 1 sees "normal" SSH; Stage 6 tests the real configuration. |

## 6. Security model

The lab is a **trust boundary**. Everything inside `10.10.10.0/24` is lab-owned
and authorized for testing by you; nothing inside is reachable from outside the
lab. Stage 2 hardening (Module 4) defends against the *simulated* attacker inside
the lab — not the internet. See [security-hardening.md](security-hardening.md).

## 7. Module roadmap

| # | Module | Focus | Status |
|---|--------|-------|--------|
| 1 | Server Foundation | VM, OS, users, groups, packages, SSH, baseline hardening (firewall, sysctl, banner, NTP) | ✅ Done |
| 2 | Network Configuration | static IP, interfaces, DNS, routing, ports | 🔜 Next |
| 3 | Services & Application Infrastructure | minimal banking services | ⏳ Planned |
| 4 | Server Hardening | SSH hardening, firewall, least privilege, updates | ⏳ Planned |
| 5 | Logging & Telemetry | auth/SSH/system/service/firewall logs | ⏳ Planned |
| 6 | Stage 1 Integration | verified traffic between Stage 1 <-> Stage 2 | ⏳ Planned |
| 7 | Security Validation | nmap, lynis, posture report | ⏳ Planned |
| 8 | Documentation & Reproducibility | full docs + repeatable setup | ⏳ Planned |
