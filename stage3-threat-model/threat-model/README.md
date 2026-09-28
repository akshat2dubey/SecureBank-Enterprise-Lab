# Stage 3 — SecureBank Threat Model

> **Mission (Stage 3 of the SecureBank Enterprise Lab):** understand what can
> go wrong **before** we build, attack, or defend it.
>
> *"What could an attacker target, and how should SecureBank defend against
> it?"*

**Status:** 🔶 Skeleton — the register is complete for **Stages 1–2** (the only
stages built so far) and carries placeholders for Stages 4–8. It is the living
input to every later stage, not a one-time document.

---

## 1. What this stage is

A **threat model** decomposes the lab into assets, trust boundaries, and data
flows, then asks for each asset: *what can go wrong?* (STRIDE) and *are we
already protected?* (the hardening register). The output is a **risk register**
that tells Stages 4–8 what to build, what to test, and what to monitor.

It is the "understand the environment" step of the security lifecycle:

```
Understand (3) ──► Discover (5) ──► Build (2,4) ──► Test (6) ──► Detect (7) ──► Respond (8)
```

## 2. Inputs (consumed from Stages 1–2 — do not duplicate them)

| Input | Where it lives | Used for |
|---|---|---|
| Hardening register C-01…C-15 | `stage2-securebank-linux-server/docs/security-hardening.md` | existing controls → risk mitigation mapping |
| Network design (IPs, ports, IPv6 ULA) | `stage2-securebank-linux-server/docs/network-design.md` | trust boundaries, attack surface |
| Architecture & integration points | `stage2-securebank-linux-server/docs/architecture.md` | DFD, asset ownership |
| Services + Module 3 gate | `stage2-securebank-linux-server/docs/services.md` | future-service placeholders |
| Host auditing + deferrals | `stage2-securebank-linux-server/docs/host-auditing.md` | evidence + deliberate gaps |
| Single source of truth | `lab.env` (repo root) | addresses used in the DFD |
| The cross-stage contract | `INTEGRATION.md` (repo root) | reserved ports, schema, log transport |
| Analyzer report schema | `INTEGRATION.md` §6 | telemetry asset (A-15) |

## 3. Outputs (consumed by later stages)

| Artifact | Consumed by |
|---|---|
| `docs/asset-inventory.md` | Stage 5 (target selection), Stage 7 (what to monitor) |
| `docs/trust-boundaries.md` | Stage 4 (app placement), Stage 6 (scope), Stage 8 (containment) |
| `docs/data-flow-diagram.md` | Stage 6 (attack paths), Stage 7 (flow-based detection), Stage 8 (timeline) |
| `docs/risk-register.md` | Stages 4–8: what to build, test, detect, and investigate |
| `docs/methodology.md` | the how-to, so the model stays maintainable |

## 4. Repository layout

```
stage3-securebank-threat-model/
├── README.md                    # this file
└── docs/
    ├── methodology.md           # STRIDE primer + workflow (beginner-friendly)
    ├── asset-inventory.md       # A-01 … A-19 (current + placeholder)
    ├── trust-boundaries.md      # TB-1 … TB-6 + trust zones
    ├── data-flow-diagram.md     # DFD + boundary diagram (ASCII)
    └── risk-register.md         # R-01 … R-13, mapped to C-01…C-15
```

## 5. How to keep this stage alive (the discipline)

1. **Before every new module** (Stage 2 Module 2–8, Stage 4 app, Stage 7 SIEM):
   add the new assets, flows, and a risk row *first*, then build.
2. **After every change to `lab.env` / `INTEGRATION.md` / the hardening
   register**: re-check the affected rows and update `Trust`/`Controls` fields.
3. **Risk rows are never deleted** — they are closed with `Status: accepted`
   and a reason (e.g., lab-isolated), so the register is an audit trail of
   decisions.
4. **Severity = Likelihood × Impact** on a High/Medium/Low grid; every
   `High` row must have at least one control or an explicit acceptance.

## 6. Status vs. the 9-stage plan

| Stage | In scope of this model? |
|---|---|
| 1 — Traffic Analyzer | ✅ modeled (A-13…A-15, R-06, R-11) |
| 2 — Linux Server | ✅ modeled (A-01…A-10, most of the register) |
| 3 — Threat Model | this stage |
| 4 — VulnBank App | 🔲 placeholder rows ready (R-10, A-19) |
| 5 — BankRecon | 🔲 consumes this model for target scope |
| 6 — Pentest | 🔲 *validates* this model — findings update the register |
| 7 — SIEM | 🔲 consumes R-rows → detection rules |
| 8 — Incident Response | 🔲 consumes R-rows → scenarios & evidence needs |
| 9 — DevSecOps | 🔲 enforces the register (CI gates) |
