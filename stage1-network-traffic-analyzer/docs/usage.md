# Network Traffic Analyzer

Passive Scapy-based monitoring for authorized network-security analysis. It
records only packet metadata for aggregate reporting; it does not inject,
modify, replay, or save payload contents.

## Scope and limitations (intentional)

This is a **lab-scale user-space packet analyzer** built with Scapy. It is
*not* intended to provide production-grade packet capture throughput, and it
does **not** replace dedicated network-monitoring platforms such as **Zeek** or
**Suricata**.

- Scapy is the right tool for this educational/project environment: readable
  code, easy protocol inspection, and full control over what is collected.
- High-throughput production monitoring needs kernel-level capture and a
  different architecture entirely — that is outside this project's scope.
- The analyzer therefore trades raw performance for **explainability and
  learning value**. This boundary is a design decision, not a defect.

It is one component of the SecureBank Enterprise Lab: its JSON report feeds
Stage 7 (SIEM), and Stage 2's traffic generator produces the traffic it
observes (see `INTEGRATION.md` at the repo root).

## Install

```powershell
py -m pip install scapy
```

Windows live capture also requires [Npcap](https://npcap.com/#download), typically
installed with compatibility mode for WinPcap applications enabled. Run the
terminal with the capture permissions required by your environment.

## Examples

Analyze a PCAP without touching the live network:

```powershell
py .\network_traffic_analyzer.py --read-pcap .\incident.pcap --top 15 --json-out .\report.json
```

Capture up to 500 HTTPS packets from an authorized interface:

```powershell
py .\network_traffic_analyzer.py --interface Ethernet --bpf "tcp port 443" --count 500 --show-packets
```

Capture an authorized interface for two minutes:

```powershell
py .\network_traffic_analyzer.py --interface Ethernet --timeout 120
```

**Machine output (SIEM / cron):** `--json-only` skips the human summary and
keeps stdout parseable. JSON goes to stdout, or to `--json-out` if given (then
stdout stays completely empty; status goes to stderr).

```powershell
# pipe a report straight to a consumer (Stage 7 polling style)
py .\network_traffic_analyzer.py --interface Ethernet --timeout 60 --json-only | py .\consumer.py

# or write a file with clean stdout
py .\network_traffic_analyzer.py --read-pcap .\incident.pcap --json-only --json-out .\report.json
```

`--json-only` cannot be combined with `--show-packets` (interactive noise would
pollute the machine output).

Use `Get-NetAdapter | Select-Object Name, Status` to find a Windows interface
name. Capture only networks and systems you are authorized to monitor.

## Detection (heuristic indicators)

The analyzer includes a small, rule-based detection layer (`detections.py`).
It is **not** an IDS: each rule is a simple threshold check over the collected
metadata, designed to point a human at something worth a second look. Findings
appear in the `detections` array of the JSON report with `type`, `severity`,
`source`/`detail`, and `evidence`.

| Rule | What it looks for | Default threshold | Severity |
|---|---|---|---|
| `possible_syn_flood` | Many pure-SYN packets with few SYN-ACK responses | ≥ 100 SYNs and ≥ 3× more SYNs than SYN-ACKs | medium |
| `possible_port_scan` | One source touching many distinct destination ports | ≥ 15 distinct ports | low |
| `suspicious_service` | Connections to plaintext legacy ports (Telnet) | port 23 | low |

Thresholds are adjustable per run:

```powershell
py .\network_traffic_analyzer.py --interface Ethernet --timeout 120 --syn-flood-min 50 --port-scan-min-ports 10 --telnet-ports 23,513
```

## Output

The terminal report includes protocol counts, top source/destination IP
addresses, top flow tuples, TCP-flag counts, malformed-packet count, and any
detections. The optional JSON file contains the same metadata and no packet
payloads.

Report format: `schema_version: "traffic-report/1.0"` (see `INTEGRATION.md`
section 6). Malformed or truncated packets never crash the run — they are
counted in `malformed_packets` and skipped.

> **Note on `report.json` / `traffic_report.json` in this directory:** these
> are pre-contract sample outputs from an earlier capture (flat flow strings,
> no `schema_version`). Re-run the analyzer to regenerate samples in the
> current v1.0 format — the old files are kept as historical evidence only.
