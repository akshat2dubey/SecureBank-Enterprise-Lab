# SecureBank Enterprise Lab — Integration Contract (v1.0)

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
