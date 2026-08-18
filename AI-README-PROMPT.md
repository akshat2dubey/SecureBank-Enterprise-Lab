# Prompt: Write the SecureBank Stage 1 + Stage 2 README

> Copy everything between the markers below and paste it to any AI assistant
> (ChatGPT, Claude, Gemini, …). It is self-contained: the other AI does not
> need access to the repository.

---

```
You are a senior technical writer who also happens to be a security engineer.
I am building a long-term portfolio project called "SecureBank Enterprise Lab":
a realistic simulation of how a modern banking organization designs, secures,
monitors, ethically attacks, investigates, and continuously hardens its
environment. It is ONE interconnected ecosystem made of 9 stages, not 9
unrelated mini-projects. Later stages consume artifacts from earlier stages.

Your job: write a README for the first two completed stages. The README must
document Stage 1 first, then Stage 2, each step by step, in the voice of a
security engineer explaining to a beginner what was built, why it was built
that way, and how it works. Use correct terminology and explain every term
the first time it appears.

============================================================
PROJECT CONTEXT (trust this as ground truth)
============================================================

The 9 stages:
 1. Network Traffic Analyzer (Python/Scapy)  — can SecureBank SEE its network?
 2. SecureBank Linux Server (hardened host)  — can SecureBank run infrastructure safely?
 3. Threat Model (STRIDE, data-flow diagrams) — what could an attacker target?
 4. VulnBank App (deliberately vulnerable web app) — the application attack surface
 5. BankRecon Tool (OSINT/recon)             — what can be learned before an attack?
 6. VulnBank Pentest (authorized)            — can we find and prove the weaknesses?
 7. SIEM (centralized detection)             — can we detect an attack in progress?
 8. Incident Response                        — can we investigate, contain, recover?
 9. DevSecOps pipeline                       — can we ship without shipping vulnerabilities?

The ecosystem lifecycle: PLAN -> BUILD -> SECURE -> TEST -> MONITOR -> DETECT
-> RESPOND -> IMPROVE -> BUILD AGAIN.

Two root-level files glue the stages together:
- lab.env — the single source of truth for lab identity (subnet 10.10.10.0/24,
  server 10.10.10.10, Kali 10.10.10.20, analyzer 10.10.10.30, hostnames,
  admin user, timezone, IPv6 ULA fd00:10:10::/48). Every stage sources it;
  no script hardcodes an address.
- INTEGRATION.md — the cross-stage contract: address registry, reserved ports
  (22, 53, 80/443, 3306/5432, 514/10514), UTC ISO-8601 timestamp convention,
  log transport (journald -> RFC 5424 syslog -> Stage 7 SIEM), the Stage 1
  report schema, artifact naming, and a change policy.

============================================================
STAGE 1 — NETWORK TRAFFIC ANALYZER (what I need you to document)
============================================================

What it is:
- A passive network traffic analysis tool written in Python with Scapy.
- Captures live traffic on an interface OR reads PCAP files offline.
- Collects METADATA ONLY (protocols, addresses, ports, TCP flags, counts) —
  it never stores packet payloads. This is a deliberate privacy/legal design
  decision: authorized passive visibility without content capture.

What it reports (the JSON schema — Stage 7 SIEM will consume this):
- generated_at (UTC ISO-8601 timestamp), packets, bytes
- protocols breakdown (TCP, UDP, ICMP, ARP, IPv4-other, IPv6-other, Other)
- top sources / top destinations (IP addresses with counts)
- top flows (e.g. "TCP 10.10.10.20:54321 -> 10.10.10.10:22")
- TCP flags (handshake S/SA/A, RST, FIN activity)

Key design features / pros to highlight:
- Passive: no agent required on the target server, invisible to the target.
- Memory-bounded: caps unique values (MAX_UNIQUE) so long captures cannot
  exhaust RAM.
- Single-pass packet dissection for efficiency.
- Command-line options: --interface, --timeout, --top, --json-out, --bpf
  (e.g. "tcp port 22"), --read-pcap for offline analysis.
- Sample outputs: traffic_report.json and report.json under
  stage1-network-traffic-analyzer/Project/outputs/.
- Status: stage scaffolded and analyzer working; README is what you are writing.

============================================================
STAGE 2 — SECUREBANK LINUX SERVER (the main event — document this deeply)
============================================================

What it is:
- A hardened Debian 12 / Ubuntu 24.04 server that plays the role of
  SecureBank's backend infrastructure inside the lab.
- Module 1 (Server Foundation + baseline hardening) is COMPLETE and automated
  by idempotent Bash scripts — safe to run more than once.
- It is the center of gravity of the lab: Stage 1 observes it, Stage 3 models
  it, Stages 5/6 scan and test it, Stage 4 hosts apps on it, Stage 7 ingests
  its logs, Stage 8 investigates it, Stage 9 deploys it.

Step-by-step, what scripts/setup.sh does (document each step):
 1. Verifies OS (Debian/Ubuntu) and root privileges.
 2. One-time full-upgrade + installs a minimal package set with
    --no-install-recommends (openssh-server, nftables, sudo, curl, wget,
    dnsutils, git, ca-certificates, gnupg, htop, nano, tree, rsync) —
    the box starts patched and minimal.
 3. Sets the hostname and manages a BEGIN/END "managed block" in /etc/hosts,
    generated from lab.env — replaced on every run so stale entries never
    survive (single source of truth, T-05).
 4. Creates the admin user (least privilege: normal user + sudo; root never
    logs in directly).
 5. Provisions a local ed25519 keypair — used only for the traffic script's
    loopback SSH and to prove key auth works. Real client access comes from
    Kali: ssh-keygen then ssh-copy-id (a private key that never leaves the
    server cannot authenticate a client).
 6. Applies the sshd baseline drop-in (with comments explaining each control):
    PermitRootLogin no; PasswordAuthentication yes (TEMPORARY — learning lab,
    Module 4 switches to key-only); KbdInteractiveAuthentication yes (must be
    flipped TOGETHER with PasswordAuthentication in Module 4 — T-15);
    MaxAuthTries 4; AllowUsers rendered from lab.env (guest list — only the
    admin can log in); PermitEmptyPasswords no; AllowAgentForwarding no (cuts
    SSH-agent pivoting during pentest stages); PubkeyAuthentication yes;
    LoginGraceTime 60; MaxStartups 5:30:60; UseDNS no; GSSAPIAuthentication no;
    Banner /etc/issue.net.
 7. Installs the authorized-use banner (/etc/issue.net for SSH, /etc/issue
    for the console).
 8. Applies a default-deny nftables firewall covering IPv4 AND IPv6 in one
    inet table: inbound drop by default; allows established/related, loopback,
    DHCP replies, ICMP echo + ICMPv6 neighbor discovery, and SSH only from the
    lab subnet (plus IPv6 link-local). A SELF-LOCKOUT GUARD checks the live
    SSH session's IP against the lab subnet BEFORE applying the firewall and
    aborts with a clear message if it would cut the admin's own session
    (escape hatch: SB_FIREWALL_SKIP=1).
 9. Applies the sysctl network-hardening baseline (rp_filter, TCP SYN cookies,
    no redirects/source-route, martian logging, etc.).
10. Sets timezone to UTC and enables NTP — comparable timestamps are what make
    Stage 7 correlation and Stage 8 timelines possible.
11. Records an audit trail: every run is teed to logs/setup-<timestamp>.log,
    a package baseline is snapshotted, and sha256 hashes of all applied configs
    are recorded.

What the other scripts do:
- scripts/generate-lab-traffic.sh — generates exactly the traffic the Stage 1
  analyzer reports (SSH handshake, DNS, ping, HTTP attempt, ARP). It
  auto-detects CLIENT mode when run from Kali (traffic crosses the segment and
  the analyzer sees it) vs SELF mode on the server (loopback telemetry only).
- scripts/collect-forensics.sh — evidence kit: effective sshd config, live
  nftables ruleset, config hashes (drift check), package list, host-key
  fingerprints, recent logins, SSH journal — the Stage 8 seed.
- tests/module1-verify.sh — 40+ automated checks that verify EFFECTIVE
  settings (sshd -T per setting, nft list ruleset, sysctl values) and CONFIG
  CONTENT (rendered files compared against repo templates), plus password
  state, key permissions, managed hosts block, and DRIFT DETECTION (live
  hashes vs. the last setup log).

Security controls register (docs/security-hardening.md): C-01..C-12, each
with purpose / threat / config / verify — this is the "book of why" that feeds
the Stage 3 threat model.

Configs (all rendered from lab.env, never hand-edited on the box):
- configs/etc/nftables.conf, configs/etc/sysctl.d/99-securebank.conf,
  configs/etc/ssh/sshd_config.d/99-securebank.conf, configs/etc/issue.net.

Docs: architecture.md (design + Stage 3-9 integration points),
network-design.md (topology, address/port plan, IPv6 posture, Stage 1
observation points), security-hardening.md (control register),
security-review.md (review punch list T-01..T-18, all implemented),
services.md (service inventory + log locations).

Pros of Stage 2 to highlight:
- Reproducible and idempotent — the whole foundation rebuilds identically.
- Verified, not assumed — tests check effective settings and content.
- Drift detection — configs that silently change are caught.
- Evidence-ready — forensics snapshots exist before any incident.
- Integration-ready — single source of truth (lab.env) and a root contract
  (INTEGRATION.md) that Stages 3-9 consume.
- Self-documenting — every control carries its "why" (hardening register).

============================================================
HOW STAGE 1 AND STAGE 2 CONNECT (document this at the end)
============================================================

- Stage 1 passively captures the lab segment (10.10.10.0/24) from its own VM.
- Stage 2's admin logs in from Kali; generate-lab-traffic.sh (run on Kali,
  client mode) produces SSH/DNS/ICMP/HTTP/ARP traffic that physically crosses
  the segment — the analyzer sees it and reports it.
- The report schema (Stage 1) and the log/timestamp conventions (Stage 2) are
  already reserved in INTEGRATION.md so Stage 7 can ingest both.
- Stage 2's hardening register becomes Stage 3's threat-model input; its
  forensics kit becomes Stage 8's evidence map; its lab.env rendering becomes
  Stage 9's IaC seed.

============================================================
OUTPUT REQUIREMENTS
============================================================

Write the README with this structure:
1. Title + one-paragraph pitch for the whole SecureBank Enterprise Lab.
2. "How to read this document" (1-2 lines).
3. STAGE 1 section — step by step: what it is, how it works, report schema
   table, key design decisions and pros, example command, what Stage 1 makes
   possible for later stages.
4. STAGE 2 section — step by step in the order setup.sh runs: what each step
   does and WHY (security reasoning for every control), the scripts, the
   configs, the verify suite, the docs, and a pros/benefits list.
5. "How Stage 1 and Stage 2 talk to each other" section.
6. A short "what's next" (Modules 2-8 for Stage 2, and Stage 3).

Style rules:
- Beginner-friendly: explain terms like SSH, firewall, sysctl, SIEM, drift,
  allow-list, least privilege, passive capture, metadata, default-deny on first
  use — but keep the professional terminology.
- Use tables for the report schema, the sshd controls, and the port/address
  plan. Use fenced code blocks for commands.
- Mark clearly what is DONE (Stage 1 analyzer working, Stage 2 Module 1
  complete) vs PLANNED (Modules 2-8, Stages 3-9).
- Length: thorough but scannable — aim for a README a beginner can follow
  end-to-end in one sitting.
```
