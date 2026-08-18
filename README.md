# SecureBank Enterprise Lab

> **One interconnected cybersecurity ecosystem, not nine mini-projects.** A
> simulated modern banking environment where every stage consumes, monitors,
> tests, or protects another: traffic analysis → hardened Linux infrastructure
> → threat modeling → vulnerable banking app → reconnaissance → authorized
> penetration testing → SIEM → incident response → DevSecOps.

**Status:** ✅ Stages 1–2 complete & verified · **Glue:** `lab.env` +
`INTEGRATION.md` make the stages one ecosystem · **Style:** idempotent Bash +
Python, documentation-first, verify-the-effective-state testing · **Reports:**
human-readable completion reports in [`reports/`](reports/)

---

### 🌐 GitHub repository settings (paste-ready)

**Description** (Settings → About → Description):

```text
SecureBank Enterprise Lab — one interconnected cybersecurity ecosystem simulating a modern banking environment. Nine stages (traffic analysis, hardened Linux server, threat modeling, vulnerable app, reconnaissance, pentesting, SIEM, incident response, DevSecOps) consume, monitor, test, and protect each other, bound by a single integration contract. Build it stage by stage.
```

**Topics** (Settings → About → Topics, up to 20):

```text
cybersecurity  security-engineering  blue-team  red-team  penetration-testing
ethical-hacking  threat-modeling  siem  incident-response  devsecops
linux-hardening  network-security  network-analysis  scapy  python  bash
osint  security-automation
```

---

## 📖 Overview

SecureBank Enterprise Lab is a comprehensive cybersecurity project that simulates the infrastructure, applications, and security operations of a modern banking enterprise.

Instead of building isolated cybersecurity projects, this repository combines multiple interconnected modules into a single enterprise ecosystem. Each stage builds upon the previous one to demonstrate how real-world organizations design, secure, monitor, test, and automate their infrastructure.

The objective is to gain practical experience across networking, Linux administration, application security, penetration testing, threat modeling, SIEM, incident response, and DevSecOps while creating a professional portfolio that reflects enterprise-level security practices.

## 🔗 Integration contract

Two files at the repo root make the stages one ecosystem instead of nine projects:

- **`lab.env`** — the single source of truth for lab identity (subnet, IPs, hostnames, admin user, timezone). Every stage sources it; never hardcode an address.
- **`INTEGRATION.md`** — the cross-stage contract: address registry, reserved ports, UTC timestamp convention, log transport (RFC 5424 → Stage 7 SIEM), and the Stage 1 report schema.

Any change to an address, port, or artifact format must update `lab.env` + `INTEGRATION.md` in the same commit.

## 📑 Completion reports

Human-readable completion reports for each finished stage live in
[`reports/`](reports/) — Markdown sources plus generated **Word (.docx)** and
print-ready **HTML** (open in a browser → Print → Save as PDF). Rebuild them
any time with `python reports/build_reports.py`.

- `reports/SecureBank-Stage1-Completion-Report.{md,docx,html}`
- `reports/SecureBank-Stage2-Completion-Report.{md,docx,html}`
