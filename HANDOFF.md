# SecureBank Enterprise Lab — AI Handoff Pack

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

**Current status:** Stages 1 and 2 are COMPLETE and verified. Everything else
is planned. The `reports/` directory holds human-readable completion reports
(Markdown + Word + HTML) for both finished stages.

---

## 1. Repository map

```
SecureBank-Enterprise-Lab/
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
├── stage1-network-traffic-analyzer/
│   ├── Project/outputs/network_traffic_analyzer.py   # the analyzer
│   ├── Project/outputs/detections.py                 # heuristic rules
│   ├── Project/outputs/README.md                     # usage + scope boundary
│   ├── Project/outputs/CODE_EXPLANATION.md           # learning walkthrough
│   ├── tests/test_analyzer.py                        # 18-test pytest suite
│   ├── tests/integration_test.sh                     # Stage1 <-> Stage2 proof
│   └── requirements.txt
└── stage2-securebank-linux-server/
    ├── scripts/setup.sh              # idempotent foundation + hardening
    ├── scripts/generate-lab-traffic.sh
    ├── scripts/collect-forensics.sh
    ├── tests/module1-verify.sh       # ~60 checks of effective state
    ├── configs/etc/                  # sshd, nftables, sysctl, issue, apt, journald
    ├── docs/                         # architecture, network-design,
    │                                 # security-hardening (C-01..C-15),
    │                                 # security-review, services, host-auditing
    └── logs/                         # runtime logs (git-ignored)
```

## 2. The integration contract (INTEGRATION.md — full text)

```# SecureBank Enterprise Lab — Integration Contract (v1.0)

One ecosystem, one set of seams. This document defines how the nine stages
communicate, depend on, monitor, test, and protect each other. **Any change to
an address, port, or artifact format must update this document AND `lab.env`
in the same commit** — a stage that violates the contract breaks the lab.

---

## 1. Single source of truth: `lab.env` (repo root)

- All lab IPs, hostnames, the subnet, the admin user, and the timezone live in
  **`lab.env` at the repository root**, and only there.
- Every stage that needs an address **sources this file** — never hardcode an
  IP inside a script, config, or test.
- Defaults are the canonical plan; they may be overridden via the environment
  (e.g. `SB_ADMIN_USER=alice ./scripts/setup.sh`).
- Stage 2 currently consumes it (setup, traffic generator, forensics collector,
  verify tests). Stages 5–7 and 9 must consume it too.

## 2. Address registry (from `lab.env`)

| Role | Hostname | IPv4 | Consumed by |
|---|---|---|---|
| SecureBank server | `securebank-srv.securebank.lab` | 10.10.10.10 | Stages 2, 4, 6, 7, 8 |
| Kali | `kali-securebank.securebank.lab` | 10.10.10.20 | Stages 5, 6 |
| Stage 1 analyzer | `traffic-analyzer.securebank.lab` | 10.10.10.30 | Stages 1, 7 |
| Lab subnet | — | 10.10.10.0/24 | host-only lab segment |

**IPv6:** stays enabled and filtered (T-07) by the Stage 2 nftables `inet`
table. ULA block `fd00:10:10::/48` is reserved for Module 2's static config;
link-local `fe80::/10` SSH is already allowed. Stages 5–7 must scan/test both
families.

## 3. Port reservations

| Port | Protocol | Service | Stage |
|---|---|---|---|
| 22 | TCP | SSH (server) | 2, 5, 6 |
| 53 | UDP | dnsmasq/BIND on the server (optional) | 1, 2, 3 |
| 80, 443 | TCP | web — nginx + VulnBank app | 4, 6, 7 |
| 3306 or 5432 | TCP | database (MariaDB / PostgreSQL) | 4 |
| 514 (UDP) or 10514 (TCP) | syslog | log forwarding to the Stage 7 SIEM | 5, 7 |

Ports are reserved before the services exist so Stage 1 filters and Stage 5/6
scans can rely on them. Nothing binds a reserved port without updating this
table.

## 4. Time convention

- **All timestamps: UTC, ISO-8601 with offset** (e.g.
  `2026-08-09T04:56:31.670573+00:00`) — matches the Stage 1 analyzer's
  `generated_at`.
- Stage 2 enforces timezone UTC + NTP (`systemd-timesyncd`) in `setup.sh`
  (T-08). Stages 1 and 7 must do the same.
- Stages 7/8 correlation (log timelines, capture windows) depends on this —
  a mis-set clock breaks the SIEM.

## 5. Log transport (reserved for Module 5)

- Stage 2 logs live in **journald**, stored **persistently** (implemented in
  Module 1 — `Storage=persistent`, C-15); forward them via **syslog, RFC 5424**
  on port 514 (UDP) or 10514 (TCP) to the Stage 7 SIEM. No stage picks a SIEM
  agent or a proprietary format before this section is updated.
- The syslog `HOSTNAME` field must be the FQDN (`securebank-srv.securebank.lab`).
- Facilities: `auth`/`authpriv` for SSH, `daemon` for services, `cron` for
  scheduled jobs.
- Firewall drops are logged with prefix `SB-DROP` (rate-limited) and land in
  journald — Stage 7 scanning detection reads them.
- Evidence snapshots follow Stage 2's `collect-forensics.sh` layout
  (`logs/forensics-<timestamp>/` with a `README.txt`), which Stage 8 consumes.

## 6. Stage 1 traffic report schema (implemented, v1.0)

The analyzer emits `traffic_report.json` / `report.json` with:
`schema_version` ("traffic-report/1.0"), `generated_at` (UTC ISO-8601),
`packets`, `bytes`, `malformed_packets`, `protocols`, `top_sources`,
`top_destinations`, `top_flows`, `tcp_flags`, `detections`.

- **`top_flows` entries are structured objects** — `{proto, src, src_port, dst,
  dst_port, count}` — never flat strings; SIEM consumers must not regex-parse
  flows.
- **`detections`** is an array of heuristic findings
  (`type`, `severity`, `source`/`detail`, `evidence`) — see
  `stage1-network-traffic-analyzer/Project/outputs/detections.py`. Absence or
  an empty array means "nothing tripped a threshold".
- **`malformed_packets`** counts packets that could not be parsed; the analyzer
  never crashes on them.
- Backward compatibility rule: a field may be *added*, never removed or
  re-purposed; any semantic change bumps `schema_version` and this section.
- Reports land in `stage1-network-traffic-analyzer/Project/outputs/*.json`
  and integration-test evidence in `.../reports/integration-*/`.
- **Consumption seam:** run the analyzer with `--json-only` for machine
  output — JSON to stdout (or `--json-out`, leaving stdout empty), status on
  stderr. This is the Stage 7 polling contract; the human summary is never on
  stdout in that mode.

### Report changelog

| Version | Change | Reason | Impact |
|---|---|---|---|
| 1.0 | `schema_version`, structured `top_flows`, `malformed_packets`, `detections` added | SIEM-ready fields; flat flow strings were parsing-hostile | Consumers must read structured flows; older flat-string reports predate the contract |

## 7. Artifact and naming conventions

- Runtime logs are git-ignored: `stage2-securebank-linux-server/logs/` holds
  `setup-*.log`, `package-baseline-*.txt`, and `forensics-<timestamp>/`.
- Stage 2 setup runs record sha256sums of applied configs; `module1-verify.sh`
  now fails on drift. Stages 8/9 can build on this as integrity monitoring.
- The hardening register (`stage2-securebank-linux-server/docs/
  security-hardening.md`) is the control book of record for the Stage 3 threat
  model.

## 8. Cross-stage dependency map

| Stage | Consumes | Produces |
|---|---|---|
| 1 — Traffic Analyzer | lab traffic from Stages 2/4/6 | `traffic_report.json` → Stage 7 |
| 2 — Linux Server | `lab.env` | hardened host, logs, `/etc/hosts` block, config hashes → Stages 3, 7, 8, 9 |
| 3 — Threat Model | architecture/hardening docs from all stages | risk register → Stages 4–8 |
| 4 — VulnBank | Stage 2 host, ports 80/443 | attack surface → Stages 6, 7, 8 |
| 5 — BankRecon | `lab.env` (targets), public OSINT | recon report → Stage 6 |
| 6 — Pentest | Stages 3, 4, 5 | findings + evidence → Stage 7 (detection) and Stage 8 (investigation) |
| 7 — SIEM | Stage 1 reports, Stage 2/4 logs | alerts/dashboards → Stage 8 |
| 8 — Incident Response | Stage 7 alerts, Stage 2 forensics snapshots | incident timeline + root cause → remediation |
| 9 — DevSecOps | the whole repo | CI gates: configs render from `lab.env`, reports validate against §6, secrets never in `lab.env` |

## 9. Change policy

1. Change `lab.env` → re-run Stage 2 `setup.sh` on each VM (regenerates
   `/etc/hosts`, sshd `AllowUsers`, firewall) → re-run `module1-verify.sh`.
2. Change a port or format → update §3/§6 here first.
3. Stage 9 CI will eventually enforce: `lab.env` renders all generated configs
   identically, Stage 1 reports match §6, and no secrets are committed.
4. Every architectural decision gets a **changelog row** below.

## 10. Contract changelog

| Date | Stage | Change | Reason | Impact |
|---|---|---|---|---|
| Module 1 | 2 | Patch management: security-only `unattended-upgrades` (C-13) | Starts-patched ≠ stays-patched | Box applies security fixes daily; reboots stay manual |
| Module 1 | 2 | Persistent journal + `SB-DROP` firewall logging (C-15) | Defensible host evidence before Stage 8 | journald survives reboot; drop logs feed Stage 7 scanning detection |
| Module 1 | 2 | AppArmor enforced/verified where the platform ships it (C-14); auditd, Fail2Ban, AIDE deferred | MAC deliberate, not decorative; deferrals have triggers | Verify suite checks MAC state; see docs/host-auditing.md |
| Module 1 | 1 | Analyzer v1.0 report + pytest suite + `detections.py` | SIEM-ready schema, tests, heuristic detections | See §6; integration test proves Stage 1 observes Stage 2 traffic |
| Module 1 | 1 | Integration test `tests/integration_test.sh` | Formal Stage 1 ↔ Stage 2 proof | Evidence in `stage1/.../reports/integration-*/` |
```

## 3. lab.env — the single source of truth (full text)

```# SecureBank Enterprise Lab — single source of truth for lab identity (T-05)
# ---------------------------------------------------------------------------
# Lives at the REPO ROOT (SecureBank-Enterprise-Lab/lab.env) so every stage
# consumes the same values — see INTEGRATION.md (section 1) at the repo root.
# Sourced by Stage 2: scripts/setup.sh, scripts/generate-lab-traffic.sh,
#                     scripts/collect-forensics.sh, tests/module1-verify.sh
#
# These values feed:
#   - the managed /etc/hosts block (generated by setup.sh, BEGIN/END markers)
#   - the sshd AllowUsers line (rendered by setup.sh into the drop-in)
#   - the nftables lab-subnet rule (rendered by setup.sh into nftables.conf)
#
# No secrets here. Credentials never belong in this repo — the admin
# password is set interactively on the VM with `passwd` (T-13).
#
# Every value can be overridden via the environment (the default is the
# canonical lab plan; change it HERE, never inside a script):
#   SB_ADMIN_USER=alice ./scripts/setup.sh

SB_LAB_SUBNET="${SB_LAB_SUBNET:-10.10.10.0/24}"

SB_SRV_IP="${SB_SRV_IP:-10.10.10.10}"
SB_KALI_IP="${SB_KALI_IP:-10.10.10.20}"
SB_ANALYZER_IP="${SB_ANALYZER_IP:-10.10.10.30}"

# IPv6: stays ENABLED and filtered (T-07). ULA block reserved for Module 2's
# static config; link-local (fe80::/10) SSH is already allowed by the firewall.
SB_IPV6_ULA="${SB_IPV6_ULA:-fd00:10:10::/48}"

SB_DOMAIN="${SB_DOMAIN:-securebank.lab}"
SB_HOSTNAME="${SB_HOSTNAME:-securebank-srv}"
SB_KALI_HOSTNAME="${SB_KALI_HOSTNAME:-kali-securebank}"
SB_ANALYZER_HOSTNAME="${SB_ANALYZER_HOSTNAME:-traffic-analyzer}"

SB_ADMIN_USER="${SB_ADMIN_USER:-securebank-admin}"
SB_TIMEZONE="${SB_TIMEZONE:-UTC}"
```

## 4. Stage 1 completion report (full text)

# SecureBank Enterprise Lab — Stage 1 Completion Report

**Stage:** 1 — Bank Traffic Analyzer
**Status:** ✅ Foundation complete (Module 1)
**Date:** August 2026
**Ecosystem:** one of nine interconnected stages (see `INTEGRATION.md` at the repo root)

---

## 1. Executive summary

Stage 1 gives SecureBank **network visibility**: a passive Python/Scapy
analyzer that captures or ingests traffic, parses packets, identifies
protocols, tracks addresses/ports/flows, and produces structured, schema-versioned
JSON reports that later stages consume.

The analyzer is **metadata-only by design** — it never stores or inspects packet
payloads. It is a lab-scale, explainable tool, deliberately not a Zeek/Suricata
replacement (a documented scope boundary, not a defect).

The stage is verified: a 18-test unit suite, a formal integration test that
proves **Stage 1 can observe traffic generated by Stage 2**, and a machine-output
mode (`--json-only`) that gives the future Stage 7 SIEM a clean ingestion seam.

## 2. Mission in the ecosystem

> "Can SecureBank see and understand what is happening on its network?"

- **Consumes:** lab traffic from Stage 2 (and later Stages 4 and 6).
- **Produces:** `traffic_report.json` (schema `traffic-report/1.0`).
- **Feeds:** Stage 7 SIEM (detection/reporting) and Stage 8 Incident Response
  (capture evidence).
- **Integration proof:** `tests/integration_test.sh` — captures on the analyzer
  VM while Kali runs Stage 2's traffic generator, then verifies the report
  contains the expected protocols, the server's address, and SSH flows.

## 3. What was built

| Capability | Detail |
|---|---|
| Capture sources | Live interface (`--interface`) or offline PCAP (`--read-pcap`) |
| Protocol identification | TCP, UDP, ICMP, ARP, DNS, IPv4/IPv6, catch-all "Other" |
| Metadata tracking | source/destination addresses, ports, flow tuples, TCP flags |
| Memory bound | O(MAX_UNIQUE = 100,000) — long captures never grow unbounded |
| Malformed-packet handling | never crashes; counted in `malformed_packets` and skipped |
| Heuristic detections | 3 explainable threshold rules (see §5) |
| Output | human summary (terminal) + schema-versioned JSON |
| Machine mode | `--json-only`: stdout stays parseable; status goes to stderr |

## 4. Report schema (`traffic-report/1.0`)

Defined and versioned in `INTEGRATION.md` §6. SIEM consumers key on
`schema_version`; fields may only be *added*, never removed or re-purposed.

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `"traffic-report/1.0"` — bump on any semantic change |
| `generated_at` | string | UTC, ISO-8601 with offset (e.g. `2026-08-09T04:56:31.670573+00:00`) |
| `packets` | int | total packets processed |
| `bytes` | int | total bytes observed |
| `malformed_packets` | int | packets skipped due to parse failure |
| `protocols` | dict | protocol → count |
| `top_sources` | list | `{value, count}` — busiest source addresses |
| `top_destinations` | list | `{value, count}` — busiest destination addresses |
| `top_flows` | list | **structured** `{proto, src, src_port, dst, dst_port, count}` — never flat strings |
| `tcp_flags` | dict | TCP flag combination → count |
| `detections` | list | heuristic findings (see §5); empty = nothing tripped |

## 5. Detection layer (`detections.py`)

Rule-based, explainable, configurable — **not** an IDS. Each finding carries
`type`, `severity`, `source`/`detail`, and an `evidence` dict so a SIEM or
incident handler can consume it without parsing prose.

| Rule | Looks for | Default threshold | Severity |
|---|---|---|---|
| `possible_syn_flood` | many SYN packets, few completed handshakes | ≥ 100 SYNs and ≥ 3× more SYNs than SYN-ACKs | medium |
| `possible_port_scan` | one source touching many destination ports | ≥ 15 distinct ports | low |
| `suspicious_service` | plaintext legacy services | port 23 (Telnet) | low |

Thresholds are overridable per run (`--syn-flood-min`, `--port-scan-min-ports`,
`--telnet-ports`). Rules run at report time over already-collected metadata
(O(flows), not O(packets)), so detection adds no per-packet cost.

## 6. Command-line reference

| Option | Purpose |
|---|---|
| `--interface NAME` | live capture (mutually exclusive with `--read-pcap`) |
| `--read-pcap FILE` | offline analysis |
| `--bpf 'expr'` | BPF filter (live only; rejected with `--read-pcap`) |
| `--count N` | stop after N packets (0 = until timeout/Ctrl+C) |
| `--timeout SECS` | live-capture duration |
| `--top N` | rows per ranking (default 10) |
| `--show-packets` | print Scapy one-line summaries (interactive only) |
| `--json-out FILE` | write the JSON report (parent dirs auto-created) |
| `--json-only` | machine mode: no human summary; JSON → stdout or `--json-out` |
| `--syn-flood-min N` | detection threshold override |
| `--port-scan-min-ports N` | detection threshold override |
| `--telnet-ports a,b` | detection threshold override |

## 7. Verification & testing

**Unit suite** — `tests/test_analyzer.py` (18 pytest cases):
empty capture, JSON round-trip validity, protocol classification (IPv4/IPv6,
TCP/UDP/DNS/ICMP/ARP), structured flows, malformed-packet counting + pcap-loop
survival, PCAP replay through `main()`, BPF argument validation, all three
detection rules (+ thresholds configurable, + normal-traffic silence), and
three `--json-only` contract tests (stdout is pure JSON; clean stdout with
`--json-out`; `--show-packets` rejected).

**Runtime verification during implementation:** 15/15 checks passed (schema,
classification, malformed handling, full replay, detections, nested `--json-out`,
`--json-only` pipe cleanliness via real subprocess).

**Integration test** — `tests/integration_test.sh`:
capture on the analyzer VM → trigger Stage 2 traffic generator on Kali →
verify report contains TCP (SSH), ICMP, the server IP, and port-22 flows →
store evidence under `reports/integration-<timestamp>/`.

## 8. Files & deliverables

| File | Role |
|---|---|
| `Project/outputs/network_traffic_analyzer.py` | the analyzer (entry: `src/main.py`) |
| `Project/outputs/detections.py` | heuristic detection rules |
| `Project/outputs/README.md` | usage, scope boundary, detections |
| `Project/outputs/CODE_EXPLANATION.md` | line-by-line learning walkthrough |
| `tests/test_analyzer.py` | 18-test pytest suite |
| `tests/integration_test.sh` | Stage 1 ↔ Stage 2 formal integration test |
| `requirements.txt` | scapy (+ pytest for tests) |

## 9. How to run

```bash
python3 -m pip install -r requirements.txt

# live capture (authorized interface only), human report
sudo python3 Project/outputs/network_traffic_analyzer.py --interface eth0 --timeout 60

# offline analysis to JSON
python3 Project/outputs/network_traffic_analyzer.py --read-pcap incident.pcap --json-out report.json

# machine output for Stage 7 / cron
python3 Project/outputs/network_traffic_analyzer.py --interface eth0 --timeout 60 --json-only

# tests
python3 -m pytest tests/ -q
sudo ./tests/integration_test.sh eth0        # on the analyzer VM, Kali + server running
```

## 10. Deliberate scope boundaries (intentional, documented)

- **No payload capture/storage** — metadata only.
- **Not an IDS** — three explainable heuristics, not production detection.
- **Lab-scale throughput** — not a Zeek/Suricata replacement.
- **No Zeek/Suricata migration** — deferred unless a future stage requires it.

## 11. Roadmap — what comes next for Stage 1

| Item | When |
|---|---|
| Consume Stage 2/4/6 traffic in the SIEM pipeline | Stage 7 |
| Time-windowed detection rules (rolling windows) | future enhancement |
| Report validator (`consume_report.py`) as the Stage 7 ingestion gate | Stage 7 |
| Polling loop (cron-style `--json-only`) | Stage 7 |


## 5. Stage 2 completion report (full text)

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
