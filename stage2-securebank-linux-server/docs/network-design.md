# SecureBank Linux Server — Network Design

**Status:** The *plan* is fixed now (Stages 1, 5, 6, 7 depend on it); the static
IP configuration itself is applied in Module 2.

## 1. Topology

```
[ Internet ]
     │ NAT — package updates only (e.g. 10.0.2.0/24 in VirtualBox)
     ▼
+--------------------------------------------------------------+
| Hypervisor (VirtualBox / VMware / Proxmox)                    |
|   NAT network      : guest → internet (updates, downloads)    |
|   Host-only lab    : 10.10.10.0/24  (all lab traffic)         |
+--------------------------------------------------------------+
     │ 10.10.10.0/24  (host-only / internal network)
     ├── SecureBank server   10.10.10.10   securebank-srv
     ├── Kali                10.10.10.20   kali-securebank
     └── Stage 1 analyzer    10.10.10.30   traffic-analyzer
```

## 2. Address plan

| Host | FQDN | Lab IP | Role |
|---|---|---|---|
| SecureBank server | `securebank-srv.securebank.lab` | 10.10.10.10 | target / enterprise infrastructure |
| Kali | `kali-securebank.securebank.lab` | 10.10.10.20 | attacker / security testing environment |
| Stage 1 analyzer | `traffic-analyzer.securebank.lab` | 10.10.10.30 | passive traffic capture |

The `securebank.lab` domain exists **only** in the lab's `/etc/hosts` files
(managed block generated from `lab.env` at the repo root by
`scripts/setup.sh`). It must never be registered in public DNS.

## 3. Port plan

| Port | Service | Status |
|---|---|---|
| 22/tcp | sshd | Module 1 ✅ |
| 80, 443/tcp | web (nginx + VulnBank app, Stage 4) | reserved — Module 3 |
| 3306 or 5432/tcp | database (MariaDB / PostgreSQL) | reserved — Module 3 |
| 514/udp or 10514/tcp | log forwarding to Stage 7 SIEM | reserved — Module 5 |

Ports are reserved now so Stage 1 filters and Stage 5/6 scans can rely on them
before the services exist.

## 4. DNS strategy

- **Now:** `/etc/hosts` on every lab VM, generated from `lab.env` at the repo
  root (one source of truth — see `INTEGRATION.md` §1). `setup.sh` manages the
  block between `# BEGIN/END securebank.lab` markers and replaces it on every
  run, so stale entries can't survive a re-run (T-05).
- **Later (optional):** dnsmasq or BIND on the server for real DNS. Names chosen
  now remain valid, so adding DNS later is non-breaking.

## 4b. IPv6 posture (T-07)

IPv6 stays **enabled** on the lab NICs and is filtered by the same default-deny
firewall as IPv4 (`configs/etc/nftables.conf` uses an `inet` table that covers
both families; SSH is allowed from the lab subnet over IPv4 and from
link-local `fe80::/10` over IPv6). Nothing is v4-only by accident, and Stages
5–7 must scan/test both families. Do not switch to "disable IPv6" without
updating the firewall and this doc together.

The ULA block `fd00:10:10::/48` (`SB_IPV6_ULA` in `lab.env`) is reserved for
Module 2's static IPv6 config — assign `fd00:10:10::10`/`::20`/`::30` to
server/Kali/analyzer so the v6 address plan mirrors the v4 one.

## 5. Stage 1 observation points

Stage 1 is a **passive Scapy analyzer**:
`stage1-network-traffic-analyzer/Project/outputs/network_traffic_analyzer.py`.
It records **metadata only** (never payloads) and reports:

| Report section | Meaning |
|---|---|
| packets / bytes | traffic volume |
| protocols | TCP, UDP, ICMP, ARP, IPv4-other, IPv6-other, Other |
| top sources / destinations | IP addresses |
| top flows | e.g. `TCP 10.10.10.20:54321 -> 10.10.10.10:22` |
| TCP flags | handshake / reset / fin activity |

Capture is passive (promiscuous mode on the host-only segment, `10.10.10.0/24`),
so the server's firewall (Module 4) never blocks it — **no agent is required on
the server**.

### Capture command (on the capture host — Kali or the analyzer VM)

```bash
# Find the interface that holds the 10.10.10.0/24 address
ip -4 addr show
# Capture 60 seconds of lab traffic
sudo python3 network_traffic_analyzer.py --interface <iface> --timeout 60 --top 15 --json-out report.json
# Or filter, e.g. SSH only
sudo python3 network_traffic_analyzer.py --interface <iface> --bpf "tcp port 22" --timeout 60
```

### Traffic the lab generates (`scripts/generate-lab-traffic.sh`)

**Run it on Kali (client mode) — the default when the local hostname is not
the server.** Traffic only crosses the host-only segment when it travels
*between two hosts*; the server talking to itself is invisible to the analyzer
VM. The script auto-detects client vs self mode (`SB_TRAFFIC_MODE=client|self`
overrides).

| Activity | Analyzer report | Note |
|---|---|---|
| SSH connections (22) | TCP flows + TCP flags; `auth.log` entries | client mode: Kali → server, a real cross-segment login |
| DNS lookups (53) | UDP flows | NAT resolver queries are invisible to the analyzer; `dig @10.10.10.10` from the client crosses the segment (refused until dnsmasq exists, still visible traffic) |
| HTTP/HTTPS (80/443) | TCP flows + TCP flags | the analyzer reports TLS as TCP (transport-layer dissection only); deep TLS inspection is a planned Stage 1 enhancement |
| ping (ICMP) | ICMP counts + flows | health checks |
| ARP discovery | ARP counts | automatic on the segment |

Offline analysis: tcpdump (added in a later module) can write PCAPs on the
server for `--read-pcap` — these same PCAPs become evidence for Stage 8.

### Why this design holds up

Because capture is passive and the address plan is fixed (`10.10.10.10` server,
`10.10.10.20` Kali, `10.10.10.30` analyzer), Stage 1's BPF filters and report
patterns stay stable across all later modules.

## 6. Adding VMs later

Follow the same conventions so the ecosystem stays coherent:

1. One host per role, FQDN `<role>.securebank.lab`.
2. Next free IP in `10.10.10.0/24`.
3. Add the host to `lab.env` at the repo root, then re-run `scripts/setup.sh`
   on each VM — the managed `/etc/hosts` block is regenerated idempotently
   (T-05).
