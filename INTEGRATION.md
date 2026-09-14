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
table. Module 2 assigned the first /64 of the reserved ULA block statically
(`SB_IPV6_LAB_SUBNET` = `fd00:10:10::/64`): server `fd00:10:10::10`, Kali
`fd00:10:10::20`, analyzer `fd00:10:10::30` — per-host values live in
`lab.env`. The server's address is applied by Stage 2 `setup.sh` (netplan or
systemd-networkd); peer VMs apply the snippets rendered by Stage 2's
`scripts/render-peer-configs.sh`. Link-local `fe80::/10` SSH is already
allowed. Stages 5–7 must scan/test both families.

**Sensor visibility (Stage 1):** promiscuous mode alone does **not** guarantee
that the analyzer sees unicast traffic between Kali and the server — virtual
switches learn MAC→port and forward unicast only to the destination port.
The lab therefore defines ONE supported observation mechanism, configured
deliberately:

- **Preferred:** hypervisor port mirroring / promiscuous forwarding for the
  lab segment (VMware: port-group *Promiscuous Mode: Accept*; Proxmox: bridge
  mirror; libvirt: bridged forwarding). VirtualBox host-only offers none —
  use the fallback there.
- **Fallback:** capture on the **server itself** (tcpdump → `--read-pcap`, or
  the analyzer run on the server's lab NIC). This is then a **host-based
  sensor**, not a passive network sensor, and evidence must say so.
- **Acceptance:** Stage 1's integration test passes only if the report shows
  the known **Kali ↔ server SSH flow AND an HTTP (80/443) flow**. An
  ARP/broadcast-only capture is a visibility FAILURE (misconfigured
  mirroring), never "a quiet network".

## 3. Port reservations

| Port | Protocol | Service | Stage |
|---|---|---|---|
| 22 | TCP | SSH (server) | 2, 5, 6 |
| 53 | UDP | dnsmasq/BIND on the server — RESERVED, **no DNS service deployed** | 1, 2, 3 |
| 80, 443 | TCP | web — nginx + VulnBank app | 4, 6, 7 |
| 3306 or 5432 | TCP | database (MariaDB / PostgreSQL) | 4 |
| 514 (UDP) or 10514 (TCP) | syslog | log forwarding to the Stage 7 SIEM | 5, 7 |

Ports are reserved before the services exist so Stage 1 filters and Stage 5/6
scans can rely on them. Nothing binds a reserved port without updating this
table.

**Until a DNS service is deliberately deployed**, the traffic generator's
`dig @${SB_SRV_IP}` step is a **closed-port probe** — the server answers ICMP
port-unreachable. It is useful synthetic UDP/53 traffic for Stage 1, but it
is **not legitimate DNS**; label it as a probe in reports and evidence. Real
DNS arrives only with a documented dnsmasq/BIND deployment (Module 3+).

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
- **Integrity target (Stage 7 gate):** incident-grade evidence requires
  **TCP/10514 with authenticated encryption** (TLS with mutual authentication,
  RFC 5425-style) as the design goal. **UDP/514 is unacknowledged and
  unauthenticated** — acceptable for development visibility, never the sole
  transport for trustworthy incident evidence on a shared segment. Module 5
  picks the concrete mechanism here before anything ships.
- **Machine-readable seam:** Stage 7 consumes the Stage 1 **JSON schema (§6)
  via `validate_report.py`** — it validates structured fields; it never
  regex-parses the human summary or flat strings. Host logs are consumed as
  structured journald/syslog records, not prose.
- The syslog `HOSTNAME` field must be the FQDN (`securebank-srv.securebank.lab`).
- Facilities: `auth`/`authpriv` for SSH, `daemon` for services, `cron` for
  scheduled jobs.
- Firewall drops are logged with prefix `SB-DROP` (rate-limited) and land in
  journald — Stage 7 scanning detection reads them.
- Evidence snapshots follow Stage 2's `collect-forensics.sh` layout
  (`logs/forensics-<timestamp>/` with a `README.txt`), which Stage 8 consumes.

## 6. Stage 1 traffic report schema (implemented, v1.0)

The analyzer emits `traffic_report.json` / `report.json` with:
`schema_version` ("traffic-report/1.1"), `report_id`, `generated_at` (UTC
ISO-8601), `sensor`, `capture_start`, `capture_end`, `packets`, `bytes`,
`malformed_packets`, `protocols`, `top_sources`, `top_destinations`,
`top_flows`, `tcp_flags`, `detections`.

- **`top_flows` entries are structured objects** — `{proto, src, src_port, dst,
  dst_port, count}` — never flat strings; SIEM consumers must not regex-parse
  flows.
- **`detections`** is an array of heuristic findings
  (`type`, `severity`, `source`/`detail`, `evidence`) — see
  `stage1-network-traffic-analyzer/Project/outputs/detections.py`. Absence or
  an empty array means "nothing tripped a threshold".
- **`malformed_packets`** counts packets that could not be parsed; the analyzer
  never crashes on them.
- **`report_id`** (1.1) is a stable unique ID — `sb-tr-<UTCstamp>-<8hex>` —
  for SIEM correlation and de-duplication of repeated polls.
- **`sensor`** (1.1) names the capturing host; **`capture_start`/`capture_end`**
  (1.1) bound the capture window (first/last packet seen, UTC ISO-8601; `null`
  when zero packets were seen — PCAP replay reports the ORIGINAL window, not
  the replay wall-clock). Stage 7 joins these against log timelines.
- **Every report must pass `Project/outputs/validate_report.py`** (the Stage 7
  ingestion gate; accepts 1.0 and 1.1) before it is ingested. The pytest suite
  and the integration test enforce this on every run.
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
| 1.1 | Additive: `report_id`, `sensor`, `capture_start`/`capture_end`; `validate_report.py` ingestion gate | Stage 7 correlation needs capture windows + sensor identity; SIEM must never ingest unvalidated reports | 1.0 reports stay valid; 1.1 consumers must tolerate `null` windows on empty captures |

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
| Module 1 | 3 | Threat-model skeleton (asset inventory A-01…A-22, trust boundaries TB-1…TB-9, STRIDE register R-01…R-13 consuming C-01…C-15) | "Understand before you build": feeds Stages 4–8 | Risk register is the input to Stage 4/6/7/8 planning |
| Module 2 | 2 | Static lab addressing: `SB_IPV6_LAB_SUBNET` + per-host ULA vars in `lab.env`; server applies `10.10.10.10/24` + `fd00:10:10::10/64` via netplan/systemd-networkd (C-16); peer snippets rendered by `render-peer-configs.sh` | Stable identity is the dependency of Stages 1, 5, 6, 7 | New `lab.env` keys are additive; consumers may treat ULA as optional until peers apply theirs |
| Review | 1 | Sensor-visibility contract formalized (§2): hypervisor mirroring preferred, host-based capture fallback; integration test requires cross-host SSH + HTTP flows, ARP-only = FAIL | Promiscuous mode ≠ unicast visibility on virtual switches | Hypervisor mirroring becomes a documented prerequisite; acceptance is testable |
| Review | 2 | Firewall self-lockout guard now validates the SSH **remote peer** (IPv4+IPv6, fail-closed); server-side SSH key generation removed — Kali is the sole key origin | The guard read the local socket side (a real lockout-safety defect); a self-authorized server key has no legitimate use | Re-run `setup.sh` on the VM; delete any pre-existing server-side key manually |
| Review | 1 | Report schema 1.0 → 1.1 (additive): `report_id`, `sensor`, `capture_start`/`capture_end`; `validate_report.py` ingestion gate | Stage 7 needs capture windows, sensor identity, and validated reports | 1.0 reports remain valid; Stage 7 accepts both versions |
| Review | 2 | Logical planes (management/application/database/monitoring) documented (Stage 2 network-design §8) | Plane separation designed before services exist (one VM today) | Module 3/4 firewall + binding rules implement it; DB never exposes 3306/5432 to the segment by default |
