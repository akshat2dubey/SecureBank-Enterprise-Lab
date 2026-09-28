# Threat-Modeling Methodology (STRIDE primer)

**Why this document exists:** threat modeling is only useful if it is
repeatable. This page explains the method in plain language so anyone — a
beginner student or a new contributor — can extend the model without breaking
its structure.

---

## 1. The four questions (any threat model answers these)

1. **What are we building?** → the asset inventory (`asset-inventory.md`)
2. **Where are the seams?** → trust boundaries (`trust-boundaries.md`)
3. **How does data move?** → the data-flow diagram (`data-flow-diagram.md`)
4. **What can go wrong, and are we covered?** → the risk register
   (`risk-register.md`)

The SecureBank model documents the *current* system (Stages 1–2) and reserves
space for *planned* components (Stages 4–8), because the register is the input
that shapes what later stages build.

## 2. STRIDE — the six ways things go wrong

STRIDE is a mnemonic for threat categories, applied to **every asset**:

| Letter | Threat | Plain meaning | Example in SecureBank |
|---|---|---|---|
| **S** | Spoofing | Pretending to be someone/something else | Attacker pretends to be the admin to SSH in; fake host key on first connect (TOFU) |
| **T** | Tampering | Modifying data or config without permission | Editing the sshd drop-in or `nftables.conf` so the box is misconfigured |
| **R** | Repudiation | Denying you did something, with no proof | Attacker erases log entries so there is no record of the intrusion |
| **I** | Information disclosure | Secrets/private data leaking | Traffic report metadata or captured headers leaking to the wrong person |
| **D** | Denial of service | Making a service unusable | SYN flood / connection exhaustion against SSH |
| **E** | Elevation of privilege | Getting more rights than you should | Exploiting a service account to reach root |

**How to use it:** for each asset, walk the six letters and ask "can this
happen here?" Only *plausible* threats become rows in the register — STRIDE is
a checklist, not a mandate to invent 60 rows.

## 3. The workflow (how a row is born)

```
1. Pick an asset (A-XX) and a trust boundary it crosses (TB-XX)
2. Ask STRIDE over it → list plausible threats
3. For each: name the attack scenario in one sentence
4. Rate Likelihood (H/M/L) and Impact (H/M/L) in THIS lab's context
5. Map existing controls from the hardening register (C-01…C-15)
6. Decide: Mitigated / Partially / Open / Accepted (with reason) / Future
7. Record residual risk and which later stage must close the gap
```

**Lab-context rule:** likelihood is judged *inside the isolated lab*
(10.10.10.0/24, host-only), where the realistic attacker is a fellow student
in the lab or the lab's own authorized pentest stages — not the Internet at
large. Internet-scale threats are noted but rated lower.

## 4. Rating grid

| | Impact H | Impact M | Impact L |
|---|---|---|---|
| **Likelihood H** | High | High | Medium |
| **Likelihood M** | High | Medium | Low |
| **Likelihood L** | Medium | Low | Low |

- **High:** must be closed by a control or explicitly accepted with a written
  reason before the related module ships.
- **Medium:** plan a control in a named later module.
- **Low:** monitor; often accepted for lab scope.

## 5. How the register consumes the hardening register (C-01…C-15)

Every risk row lists the controls that already mitigate it. Controls are **not
threats** — they are the *answers*. If a row has no C-number and no future
stage dependency, that is a gap the register is designed to surface. The full
control list lives in
`stage2-securebank-linux-server/docs/security-hardening.md`; the register
references it by ID only (never copy the control text into this stage — one
source of truth).

## 6. When to re-run the model

- New stage or module starts (Module 2 of Stage 2, the Stage 4 app, the Stage
  7 SIEM, …).
- `lab.env` or `INTEGRATION.md` changes an address, port, or format.
- The hardening register gains or loses a control.
- Stage 6 (pentest) produces findings → those become new/updated rows.
- Stage 8 (IR) investigates an incident → that scenario becomes a row if not
  already modeled.
