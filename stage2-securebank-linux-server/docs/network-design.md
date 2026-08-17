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
(`configs/etc/hosts`). It must never be registered in public DNS.

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

- **Now:** `/etc/hosts` on every lab VM, sourced from `configs/etc/hosts` (one source of truth).
- **Later (optional):** dnsmasq or BIND on the server for real DNS. Names chosen
  now remain valid, so adding DNS later is non-breaking.

## 5. Stage 1 observation points

Stage 1 captures the **host-only segment** (`10.10.10.0/24`) in promiscuous mode
or via a mirrored port. Because capture is passive, the server's firewall (Module 4)
never blocks the analyzer — this is why Stage 1 can monitor the server without
requiring any agent on it.

Traffic Stage 1 should observe once services exist: SSH (22), HTTP/HTTPS (80/443),
DNS (53, if added), database (3306/5432).

## 6. Adding VMs later

Follow the same conventions so the ecosystem stays coherent:

1. One host per role, FQDN `<role>.securebank.lab`.
2. Next free IP in `10.10.10.0/24`.
3. One line added to `configs/etc/hosts`, then re-run `scripts/setup.sh` on each
   VM (hosts merge is idempotent).
