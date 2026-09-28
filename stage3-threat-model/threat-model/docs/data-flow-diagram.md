# Data-Flow Diagram (DFD) + Trust Boundaries

Addresses come from `lab.env`; ports from `INTEGRATION.md` §3. This diagram
is the *current* system (Stages 1–2) with the *planned* flows shown dashed.

## 1. Trust-zone diagram

```
                    ┌────────────────────────────────────────────┐
                    │           ZONE C  (untrusted)              │
                    │   NAT / Internet  (outbound updates, NTP)  │
                    └───────────────────┬────────────────────────┘
                          TB-1  (default-deny, IPv4+IPv6 — C-08)
                                        │
              ┌─────────────────────────┴─────────────────────────┐
              │              ZONE A + ZONE B  (lab, 10.10.10.0/24)│
              │                                                   │
   ┌──────────┴──────────┐        TB-2 (SSH 22 only, from subnet) │
   │ ZONE A  Kali        │  ┌────► securebank-srv 10.10.10.10    │
   │ 10.10.10.20         │  │  ┌─ A-01..A-10                     │
   │ (admin/traffic gen) │  │  │  TB-3/4/5 (auth, sudo, kernel)  │
   └──────────┬──────────┘  │  └─────────────────────────────────┤
              │  SSH(22)/DNS(53)/HTTP(80)/ICMP                   │
              │  TB-6 (passive)   │                              │
   ┌──────────┴──────────┐        │        ┌─────────────────────┤
   │ ZONE B  Analyzer    │◄───────┘        │ journald (A-08)     │
   │ 10.10.10.30 (A-13)  │                 └───────┬─────────────┘
   └──────────┬──────────┘                         │ TB-8 (future:
              │ traffic_report.json (A-15)         │ syslog 514/10514)
              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▼───────────────
              └──────────► ZONE E (future) SIEM / IR (Stages 7-8)
```

## 2. Data flows (numbered)

| # | From | To | Data | Transport / port | Notes |
|---|---|---|---|---|---|
| F-1 | Kali (A-16) | server (A-01) | SSH auth + session | TCP 22 | admin plane; key/password auth |
| F-2 | Kali (traffic script) | server | DNS, HTTP, ICMP, ARP (controlled traffic) | UDP 53, TCP 80, ICMP | Stage 1 integration test observes these |
| F-3 | server | analyzer (A-13) | *broadcast of F-1/F-2 on the segment* | passive | analyzer is **metadata-only** (no payload storage) |
| F-4 | analyzer | reports (A-15) | `traffic-report/1.0` JSON | file / `--json-only` stdout | schema in INTEGRATION.md §6 |
| F-5 | server | NAT (C) | apt updates, NTP | outbound | only outbound crosses TB-1 |
| F-6 | server | (future SIEM) | journald → syslog RFC 5424 | UDP 514 / TCP 10514 | reserved; forwarder in Module 5 |
| F-7 | analyzer | (future SIEM) | traffic reports | JSON | ingestion gate validates schema |
| F-8 | repo (A-11/A-12) | all hosts | config via `setup.sh` | — | TB-7; drift-checked by verify suite |

## 3. DFD elements glossary (context-DFD style)

- **Processes (round shapes):** `sshd` (A-02), `nftables`, `journald` (A-08),
  the analyzer (A-13), the traffic generator (on Kali).
- **Data stores:** journald (A-08), forensics kit (A-09), traffic reports
  (A-15), repo configs (A-10).
- **External entities:** Kali (A-16), NAT/upstream (A-18), future SIEM/IR
  (A-21/A-23), future app/DB (A-19/A-20).

## 4. What to check before extending the DFD

1. Every new flow must already have its **port reserved** in
   `INTEGRATION.md` §3 (add it there first).
2. Every flow crossing a trust boundary must reference a **TB-xx** from
   `trust-boundaries.md` and at least one **C-xx** control.
3. A flow that carries **payloads** (future PCAPs, DB queries) is treated
   differently from a metadata flow (F-3) — note it explicitly.
4. When Stage 4/7 land, add F-6/F-7 solid (not dashed) and update the zone
   diagram with Zones D/E detail.
