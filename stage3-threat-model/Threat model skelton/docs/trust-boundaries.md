# Trust Boundaries

A **trust boundary** is a line where the trust level changes — crossing it is
exactly where spoofing, tampering, and elevation happen. This document lists
the lab's boundaries, the **controls that enforce each one** (from the
hardening register C-01…C-15), and what remains open.

## 1. Trust zones

```
 Zone A  Trusted lab admin plane        Kali (10.10.10.20), the admin user,
                                        the repo/contract files (A-11, A-12)
 Zone B  Managed lab hosts              securebank-srv (10.10.10.10),
                                        traffic analyzer (10.10.10.30)
 Zone C  Untrusted                      NAT NIC / upstream (updates, NTP)
 Zone D  (future) Application zone      VulnBank app + DB (Stage 4) — semi-trusted:
                                        public-facing inside the lab, no admin rights
 Zone E  (future) Monitoring plane      SIEM + IR (Stages 7-8) — read-only consumers
```

## 2. Boundaries

| ID | Boundary | Crossed by | Controls enforcing it | Open items |
|---|---|---|---|---|
| TB-1 | Lab segment ⇄ NAT/upstream | outbound updates/NTP; inbound anything | C-08 (default-deny, both families), C-09 (rp_filter) | none — inbound is drop; outbound only |
| TB-2 | Segment ⇄ server (host ingress) | SSH (22), DHCP (68), ICMP, ICMPv6-ND | C-08 (SSH from 10.10.10.0/24 + fe80::/10 only; `SB-DROP` logging), C-07 (MaxStartups, LoginGraceTime) | fail2ban/rate-limit deferred (see host-auditing.md) |
| TB-3 | Untrusted user ⇄ admin account | SSH authentication | C-01 (no root SSH), C-02 (admin + sudo), C-03 (minimal packages), C-06 (AllowUsers), C-07 (MaxAuthTries), C-04 (password auth TEMPORARY), C-12 (keys), C-13 (patching) | C-04 removal in Module 4 (flip both switches, T-15) |
| TB-4 | Admin account ⇄ root (privilege elevation) | `sudo` | C-02 (sudo group membership, explicit elevation) | sudoers review when Stage 3 services land |
| TB-5 | Host ⇄ its own processes (kernel/network) | any process sending/receiving | C-08 (firewall), C-09 (sysctl anti-spoofing), C-14 (AppArmor where shipped), C-06/C-07 (SSH surface) | AppArmor profiles for future services (Module 4) |
| TB-6 | Segment ⇄ analyzer capture point | passive sniffing | metadata-only design (no payload storage), A-15 schema (metadata only) | PCAP capture (headers+payloads) must be authorized + handled as evidence |
| TB-7 | Repo ⇄ running systems (config supply) | `setup.sh` renders `lab.env` + configs onto hosts | C-05 (UTC), T-03 (setup audit + hashes), drift detection in `module1-verify.sh` | no signed/CI-enforced config yet → Stage 9 |
| TB-8 | (future) Server ⇄ SIEM/IR | syslog RFC 5424 (514/10514), reports | reserved in INTEGRATION.md §3/§5 | forwarder + schema validation → Module 5 / Stage 7 |
| TB-9 | (future) App ⇄ DB | SQL (3306/5432) | reserved port; least-privilege DB user required (Module 3 gate) | design arrives with Stage 4 |

## 3. Reading this table

- A boundary with **no open items** is considered *enforced by config* in the
  current lab.
- An **open item** must become a control (C-number) or a named module task —
  it is exactly what the risk register (R-rows) tracks.
- Boundaries TB-8/TB-9 are *reservations*: the seam exists on paper so Stages
  4 and 7 don't invent incompatible ones. That is the same pattern as the
  reserved ports in `INTEGRATION.md` §3.
