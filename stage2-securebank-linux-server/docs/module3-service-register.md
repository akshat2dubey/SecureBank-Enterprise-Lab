# Module 3 Pre-Install Service Register (T-18 gate — executed ahead of build)

> **Status:** 🟡 DRAFT — register complete, **nothing installed yet**. This
> document exists so Module 3 can start the moment the VM baseline
> (Modules 1–2) is verified, without breaking the "document before install"
> gate (T-18, `docs/services.md`).
>
> **Decisions that remain yours (owner sign-off required before install):**
> 1. **DB engine** — MariaDB is the default below (lighter, common in
>    banking-adjacent labs, ships in the Debian/Ubuntu repos). PostgreSQL is
>    the alternative; every row below works unchanged except the engine name.
> 2. **TLS strategy for 443** — self-signed lab certificate generated on the
>    server (fast) vs. a lab-local CA on Kali (mirrors real PKI, feeds Stage 6
>    MITM exercises). Default assumed below: self-signed; revisit in Stage 6.
> 3. **Account names** — `securebank-app` (web runtime) and `vulnbank-db`
>    (database login). Change them now if you want different names; they
>    propagate into configs, firewall rules, and the threat model.

## 1. Planned service rows (promote into `docs/services.md` → "Installed" at install)

| Service | Port | Bind | Dedicated user | Purpose | Security notes | Logs |
|---|---|---|---|---|---|---|
| nginx | 80/tcp, 443/tcp | lab NIC (10.10.10.10) only | `securebank-app` (system user) | Web front for the VulnBank app (Stage 4) | No root workers; `server_tokens off`; default vhost removed; TLS on 443 (cert strategy above); only 80/443 opened in nftables, from `SB_LAB_SUBNET` only (C-08 extension) | `/var/log/nginx/access.log`, `/var/log/nginx/error.log` |
| MariaDB (default) | 3306/tcp | **127.0.0.1 only** — co-located app pattern; never exposed to the segment | system: `mysql`; app login: `vulnbank-db` (one schema, minimal grants) | SecureBank application database (Stage 4 data model) | No remote root, no anonymous accounts (`mysql_secure_installation` baseline); per-service credentials, no shared admin; because the bind is loopback, **no firewall rule for 3306 exists or is needed** | `journalctl -u mariadb`, MariaDB error log |
| sshd | 22/tcp | unchanged | unchanged | admin plane stays Module 1/4 scope | no change in Module 3 | unchanged |

## 2. Planned controls (add to `docs/security-hardening.md` as C-17…C-19 at install)

### C-17 — Web tier isolation (Module 3) 🟡 planned
- **Purpose:** the only segment-facing service runs unprivileged; the blast
  radius of a web compromise stays inside `/var/www` and the app user.
- **Threat:** R-10 / R-14 in the Stage 3 risk register (web app → host
  elevation, web app → database).
- **Configuration:** `securebank-app` system user (nologin shell, not in
  `sudo`); systemd unit sandboxing (`NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `PrivateTmp=yes`); nginx `user` directive matches;
  nftables extension opens **only** 80/443 from `SB_LAB_SUBNET` (rendered
  from the repo template — never hand-edit the box copy).
- **Verification:** `id securebank-app` shows nologin + no sudo; `ss -tlnp`
  shows nginx bound to the lab address, not `0.0.0.0` beyond plan; `nft list
  ruleset` shows exactly two new accepts (80, 443) scoped to the subnet.

### C-18 — Database least privilege + loopback-only bind (Module 3) 🟡 planned
- **Purpose:** the database has no network presence at all; only the local
  app process can reach it, and only for one schema.
- **Threat:** R-10 / R-14; credential reuse across services; segment-wide DB
  exposure (the classic banking-lab mistake).
- **Configuration:** `bind-address = 127.0.0.1`; app login `vulnbank-db`
  grants limited to SELECT/INSERT/UPDATE on the single application schema;
  `mysql_secure_installation` baseline applied; DB credentials created
  interactively on the VM (never stored in the repo — same rule as T-13).
- **Verification:** `ss -tlnp | grep 3306` shows `127.0.0.1:3306` and **no**
  lab-IP binding; `SHOW GRANTS FOR 'vulnbank-db'@'localhost` audited on the
  VM; any network-visible 3306 line = FAIL.

### C-19 — Listening-socket allow-list enforced in the verify suite (Module 3) 🟡 planned
- **Purpose:** turn the T-18 minimalism gate into a mechanical check — no new
  listening socket can appear without a register row.
- **Threat:** silent service sprawl undoing the minimal-surface posture (C-03).
- **Configuration:** a new "Module 3" section in `tests/module1-verify.sh`
  asserting the exact expected socket set: `:22` (sshd), `:80` + `:443`
  (nginx), `127.0.0.1:3306` (MariaDB) — nothing else.
- **Verification:** `ss -tln` output compared against the allow-list; any
  extra listener fails the suite.

## 3. Firewall delta (extends C-08; applied via the repo template at install)

```nft
# add to the input chain in configs/etc/nftables.conf (rendered from the
# repo template — never hand-edit the box copy):
tcp dport { 80, 443 } ip saddr @lab_subnet accept   # nginx — Module 3
# 3306: intentionally NOT opened — MariaDB binds 127.0.0.1 only (C-18)
```

## 4. Install order (when Module 3 starts)

1. Promote the rows in §1 into `docs/services.md` ("Installed") — T-18 gate
   satisfied on paper and in the authoritative table.
2. Add C-17…C-19 to `docs/security-hardening.md`; Stage 3 asset/register
   updates for the planned services are already in place (this change).
3. Install nginx + the chosen DB with `--no-install-recommends`; render all
   configs from repo templates (`lab.env` values only — no hardcoded IPs).
4. Extend `configs/etc/nftables.conf` per §3; re-run `scripts/setup.sh`
   (idempotent); run `tests/module1-verify.sh` plus the new Module 3 section.
5. Update the Stage 3 register: R-10/R-14 flip to in-scope; re-rate with the
   running services; findings feed Stage 6/7 planning.

## 5. What this register deliberately does NOT decide (Stage 4 scope)

- **The VulnBank application itself** (language/framework) — that decision
  belongs to Stage 4; it only changes the runtime behind nginx, not these rows.
- **nginx ↔ app transport** (unix socket vs. localhost port) — decided with
  the app; both fit inside C-17's sandboxing.
