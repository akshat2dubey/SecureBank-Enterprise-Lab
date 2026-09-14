#!/usr/bin/env python3
"""Build HANDOFF.md — a single, self-contained pack that lets ANY other AI
(ChatGPT, Claude web, Gemini, another Codebuff, …) understand the SecureBank
Enterprise Lab and continue the work without needing repository access.

    python reports/build_handoff.py

The pack embeds the integration contract, lab.env, both completion reports,
the repository map, and proven starter prompts. Paste the whole file into
any AI chat, or point an AI with file access at HANDOFF.md itself.
Standard library only.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # SecureBank-Enterprise-Lab
OUT = ROOT / "HANDOFF.md"

EXCLUDE_DIRS = {".git", "logs", "node_modules", "__pycache__", ".freebuff", ".venv", "venv"}
EXCLUDE_FILES = {"HANDOFF.md", "AI-README-PROMPT.md"}

TREE = """SecureBank-Enterprise-Lab/
├── README.md                          # project overview + reports link
├── lab.env                            # single source of truth (all identity)
├── INTEGRATION.md                     # the cross-stage contract (v1.0)
├── HANDOFF.md                         # THIS file — paste into any AI
├── AI-README-PROMPT.md                # prompt for AI README writers
├── reports/                           # completion reports (md/docx/html)
│   ├── SecureBank-Stage1-Completion-Report.{md,docx,html}
│   ├── SecureBank-Stage2-Completion-Report.{md,docx,html}
│   ├── build_reports.py               # markdown -> docx/html generator
│   └── build_handoff.py               # this generator
├── stage3-securebank-threat-model/
│   ├── README.md                  # mission, inputs/outputs, status
│   └── docs/                      # methodology, asset-inventory,
│                                 # trust-boundaries, data-flow-diagram,
│                                 # risk-register (STRIDE, consumes C-01..C-15)
├── stage1-network-traffic-analyzer/
│   ├── Project/outputs/network_traffic_analyzer.py   # the analyzer
│   ├── Project/outputs/detections.py                 # heuristic rules
│   ├── Project/outputs/README.md                     # usage + scope boundary
│   ├── Project/outputs/CODE_EXPLANATION.md           # learning walkthrough
│   ├── tests/test_analyzer.py                        # 25-test pytest suite
│   ├── Project/outputs/validate_report.py            # schema validator (Stage 7 ingestion gate)
│   ├── tests/integration_test.sh                     # Stage1 <-> Stage2 proof
│   └── requirements.txt
└── stage2-securebank-linux-server/
    ├── scripts/setup.sh              # idempotent foundation + hardening + Module 2 static addressing
    ├── scripts/generate-lab-traffic.sh
    ├── scripts/collect-forensics.sh
    ├── scripts/render-peer-configs.sh # renders Kali/analyzer snippets from lab.env
    ├── tests/module1-verify.sh       # ~75 checks of effective state (Modules 1+2)
    ├── configs/etc/                  # sshd, nftables, sysctl, issue, apt, journald, netplan, networkd
    ├── configs/other-vms/            # peer-VM snippet templates (@VAR@ placeholders)
    ├── docs/                         # architecture, network-design (§7 Module 2),
    │                                 # security-hardening (C-01..C-16),
    │                                 # security-review, services, host-auditing
    └── logs/                         # runtime logs (git-ignored)
"""

INTRO = """# SecureBank Enterprise Lab — AI Handoff Pack

**How to use this file**
- **Chat-only AI (no file access):** paste the ENTIRE content of this file into
  the chat, then add one of the starter prompts in section 7. It is fully
  self-contained — the AI needs nothing else.
- **AI with file/terminal access (like Codebuff):** you may not need a paste —
  tell it: *"Read HANDOFF.md, then README.md and INTEGRATION.md at the repo
  root, then explore; ask me before changing anything."* Prefer this mode: the
  AI can then read the actual scripts and configs itself.

**What this project is (one paragraph)**
SecureBank Enterprise Lab is a single, interconnected cybersecurity ecosystem
of **nine stages** simulating a modern banking organization: (1) network
traffic analyzer, (2) hardened Linux server, (3) threat model, (4) vulnerable
banking app, (5) recon/OSINT tool, (6) authorized pentest, (7) SIEM, (8)
incident response, (9) DevSecOps pipeline. The design goal is that every stage
consumes, monitors, tests, or protects another stage — the repository must feel
like ONE security ecosystem, never nine unrelated mini-projects. The two glue
files at the root — `lab.env` and `INTEGRATION.md` — are what make it one
ecosystem.

**Current status:** Stage 1 (analyzer) foundation complete and tested (report
schema 1.1 + validator). Stage 2 foundation complete (Module 1) with Module 2
(static lab addressing) code complete — verify on the VM; Modules 2–8 planned.
Stage 3 has a threat-model skeleton (asset inventory, trust boundaries, DFD,
STRIDE risk register consuming the C-01…C-16 controls). Everything else is
planned. The `reports/` directory holds human-readable completion reports
(Markdown + Word + HTML) for the finished stages.

---

## 1. Repository map

```
{TREE}```

## 2. The integration contract (INTEGRATION.md — full text)

```{INTEGRATION}```

## 3. lab.env — the single source of truth (full text)

```{LABENV}```

## 4. Stage 1 completion report (full text)

{STAGE1}

## 5. Stage 2 completion report (full text)

{STAGE2}

## 6. Golden rules for any AI touching this repo

1. **Never break the contract.** Any change to an address, port, or artifact
   format must update `lab.env` + `INTEGRATION.md` in the same change. Never
   hardcode an IP inside a script, config, or test.
2. **No secrets ever.** Credentials (especially the admin password) never
   belong in the repository. `logs/` is git-ignored runtime output.
3. **Stage 1 schema is additive-only.** A report field may be *added*; never
   remove or re-purpose one without bumping `schema_version`.
4. **Deferrals are deliberate.** `docs/host-auditing.md` documents WHY auditd,
   Fail2Ban, AIDE, and filesystem hardening are deferred, with triggers.
   Don't "just install" them to tick a box.
5. **Scope boundaries are deliberate.** The Stage 1 analyzer is metadata-only
   and lab-scale by design — no payload capture, no Zeek/Suricata migration,
   no full IDS, unless a future stage provides a concrete requirement.
6. **Verify effective state, not file existence.** Follow the pattern of
   `tests/module1-verify.sh` (checks `sshd -T`, `nft list ruleset`, `sysctl`,
   rendered-template `cmp`, drift detection).
7. **Idempotent Bash is the automation style.** Later stages may wrap it in
   IaC (Ansible/Terraform), but the scripts themselves stay re-runnable.
8. **Document before install.** Every new service/control needs a register row
   (purpose / threat / config / verification) before it is added — see
   `docs/services.md` (Module 3 gate).

## 7. Proven starter prompts (pick one and paste after this file)

- **Build the next module:**
  "Design and implement Stage 2 Module 2 (Network Configuration): static IPs
  from lab.env, interface config, IPv6 ULA plan, DNS/routing, verify checks —
  keeping INTEGRATION.md and the existing verify suite intact."
- **Continue the threat model:**
  "Create the Stage 3 threat model skeleton: asset inventory from the Stage 1/2
  docs, trust boundaries on the lab network, and a STRIDE risk register that
  consumes the C-01..C-15 controls."
- **Review the work:**
  "Act as a security architect. Review the Stage 1/2 implementation for
  correctness, integration risks, and drift from INTEGRATION.md. Do not
  redesign; recommend only justified changes."
- **Write documentation:**
  "Using AI-README-PROMPT.md at the repo root, write the Stage 1 and Stage 2
  README sections, step by step, Stage 1 first then Stage 2."
- **Explain to a beginner:**
  "Explain Stages 1 and 2 to a beginner student using exact terminology with
  plain-language meanings, step by step."

## 8. The 9-stage vision (for context)

The final system: BankRecon (5) and Threat Model (3) inform the Linux server
(2), the VulnBank app (4), and the network layer (1); everything feeds the SIEM
(7) and Incident Response (8); Stage 6 pentests the environment; Stage 9
protects how the system is built, tested, and deployed. The continuous
lifecycle: PLAN -> BUILD -> SECURE -> TEST -> MONITOR -> DETECT -> RESPOND ->
IMPROVE -> BUILD AGAIN. Stages 3-9 must consume the artifacts Stages 1-2
produce (`lab.env`, `INTEGRATION.md`, the traffic report schema, logs, the
hardening register, forensics kit).
"""


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> int:
    integration = read(ROOT / "INTEGRATION.md")
    labenv = read(ROOT / "lab.env")
    stage1 = read(ROOT / "reports" / "SecureBank-Stage1-Completion-Report.md")
    stage2 = read(ROOT / "reports" / "SecureBank-Stage2-Completion-Report.md")

    body = INTRO.format(TREE=TREE, INTEGRATION=integration, LABENV=labenv,
                        STAGE1=stage1, STAGE2=stage2)
    OUT.write_text(body, encoding="utf-8")
    print(f"Wrote {OUT} ({len(body):,} chars / {body.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
