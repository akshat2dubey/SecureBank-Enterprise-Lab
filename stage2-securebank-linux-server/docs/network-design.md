# SecureBank Linux Server — Network Design

**Status:** The plan is fixed (Stages 1, 5, 6, 7 depend on it) and the static
configuration is **applied by Module 2** (§7) — the server VM holds
`10.10.10.10` + `fd00:10:10::10` statically on the host-only NIC; peer VM
snippets are rendered by `scripts/render-peer-configs.sh`.

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
the lab; Module 2 assigns its first /64 (`SB_IPV6_LAB_SUBNET`,
`fd00:10:10::/64`) statically — `fd00:10:10::10`/`::20`/`::30` to
server/Kali/analyzer (`SB_SRV_IPV6`/`SB_KALI_IPV6`/`SB_ANALYZER_IPV6` in
`lab.env`), so the v6 address plan mirrors the v4 one. The server's address
is applied by Module 2 (§7); peer VMs get theirs from the rendered snippets
(`scripts/render-peer-configs.sh`).

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

Capture is passive and metadata-only, so the server's firewall never blocks
it — **no agent is required on the server**. But promiscuous mode alone does
**not** guarantee unicast visibility on a virtual switch: a switch forwards
unicast only to the destination's port. Observing Kali → server traffic
requires ONE of (see `INTEGRATION.md` §2 for the formal contract):

- **Preferred:** hypervisor port mirroring / promiscuous forwarding on the
  lab segment (VMware: port-group *Promiscuous Mode: Accept*; Proxmox: bridge
  mirror; libvirt: bridged forwarding). VirtualBox host-only offers none.
- **Fallback:** capture **on the server itself** (tcpdump → `--read-pcap`) —
  then the sensor is host-based, and evidence must label it as such.
- **Acceptance:** the integration test requires the cross-host SSH flow AND
  an HTTP (80/443) flow; an ARP-only capture is a visibility FAILURE.

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
| DNS lookups (53) | UDP flows | NAT resolver queries are invisible to the analyzer; `dig @10.10.10.10` from the client crosses the segment but is a **closed-port probe, not legitimate DNS** — the server runs no resolver yet (ICMP port-unreachable reply; INTEGRATION.md §3) |
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
2. Next free IP in `10.10.10.0/24` (and the matching ULA host byte in
   `fd00:10:10::/64` — see §4b).
3. Add the host to `lab.env` at the repo root, then re-run `scripts/setup.sh`
   on each VM — the managed `/etc/hosts` block is regenerated idempotently
   (T-05), and `scripts/render-peer-configs.sh` re-renders peer snippets.

## 7. Static addressing — how Module 2 applies the plan (C-16)

**What is static:** the host-only lab NIC on the SecureBank server holds
`SB_SRV_IP/LAB_PREFIX` (`10.10.10.10/24`) + `SB_SRV_IPV6/IPV6_PREFIX`
(`fd00:10:10::10/64`). **What stays DHCP:** the NAT NIC — untouched, updates
only. **Names:** still the managed `/etc/hosts` block (§4) — no DNS server
this module, so nothing new to harden yet.

**How `scripts/setup.sh` does it (idempotent, re-runnable):**

1. **Detect the lab NIC** — the interface holding an address inside
   `SB_LAB_SUBNET` (the verify suite re-derives this itself rather than
   trusting a variable).
2. **Detect the backend** — netplan when present (Ubuntu), else
   systemd-networkd (Debian). No ifupdown support; the script aborts rather
   than guess.
3. **Session-drop guard** — if the live SSH session comes from the lab NIC
   but not from the final `SB_SRV_IP`, applying the static plan would cut
   the session: abort unless `SB_NET_SKIP=1` (skip) + `SB_NET_FORCE=1`
   (accept the drop) — mirroring the Module 1 firewall guard.
4. **Render → install → apply** the template
   (`configs/etc/netplan/99-securebank.yaml` or
   `configs/etc/systemd/network/10-securebank-lab.network`; placeholders
   `@VAR@` filled from `lab.env`, exactly like the firewall). Netplan file
   mode 0600 (netplan refuses looser modes). On cloud-init images, the
   empty opt-out `/etc/cloud/cloud.cfg.d/99-securebank-network.cfg` stops
   cloud-init from overwriting the static config on boot.
5. **Confirm effective state** — `ip addr` must show both static addresses
   before setup continues (golden rule 6).

**Failure modes worth knowing:**

- **NIC renamed** (e.g. cloned VM): detection re-runs, backend re-renders —
  but netplan/netplan-like match names change, so re-run `setup.sh`, then
  `module1-verify.sh`.
- **Wrong NIC detected**: means the lab address ended up on the NAT NIC —
  fix the VM's NIC attachments, never the script.
- **`netplan apply` drops your session** despite the guard: only possible
  with the explicit force flag — reconnect to `SB_SRV_IP`.

**Peer VMs (Kali, analyzer):** ready-to-paste snippets are rendered by
`scripts/render-peer-configs.sh` into git-ignored `outputs/peer-configs/`
(NetworkManager + netplan for Kali; netplan/networkd for the analyzer) plus
`.example` copies of the server's backend templates. Apply them manually —
they are not Stage 2 hosts and are never touched by `setup.sh`.

**Cloud-init:** the opt-out is installed only when `cloud-init` exists on
the image; without it, a cloud image would reapply DHCP over the static
addresses at boot.

## 8. Logical planes (design now, enforced as modules land)

One server VM hosts all planes today; the planes are separated by **firewall
rules and bind addresses**, not by extra VMs (a VM split is a Stage 4/7
decision, taken only when a stage needs it). Every service added in Module 3+
declares its plane in `docs/services.md` before install (golden rule 8), and
Module 4's firewall extension turns this table into nftables rules.

| Plane | Access rule | Binding | Firewall posture |
|---|---|---|---|
| **Management** | SSH only from Kali / admin sources (lab subnet now; an admin allowlist if the lab grows) | sshd: all lab-NIC addresses, port 22 | Explicit allow (current C-08 rule) |
| **Application** | 80/443 from the lab segment (Stage 4 VulnBank's only exposure) | nginx: lab NIC only — never the NAT NIC | Allow once Stage 4 exists; nothing else |
| **Database** | Local processes only — **never exposed to the lab segment by default** | 3306/5432 bound to `127.0.0.1` (or a private interface if a later stage demands it) | No inbound allow rule exists or gets added without a register row |
| **Monitoring** | Stage 7 receives telemetry **only** — it never gets admin access or a shell path back into the server | forwarder egress to the SIEM collector | Outbound syslog allow when Module 5 ships; no inbound ever |

Rationale: a compromise of the vulnerable app (Stage 4) must not hand an
attacker the database's network listener, and a compromised SIEM pipeline
must not become an admin path back into the server.
