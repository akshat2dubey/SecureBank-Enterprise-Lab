# SecureBank Linux Server — Services

Only services SecureBank actually needs. Every entry records: **service, port,
purpose, security notes, logs**. This table is the input to the Stage 3 threat
model and the target list for Stage 5/6.

## Installed

| Service | Port | Purpose | Security notes | Logs |
|---|---|---|---|---|
| sshd (openssh-server) | 22/tcp | Admin remote access | Root login disabled (C-01); password auth **temporary** (C-04, revoked in Module 4) | `/var/log/auth.log`, `journalctl -u ssh` |

## Reserved (planned, NOT installed)

| Service | Port | Purpose | Security notes |
|---|---|---|---|
| nginx | 80/443 | Web front for the VulnBank app (Stage 4) | Separate vhost + dedicated app user, no root |
| MariaDB / PostgreSQL | 3306 / 5432 | SecureBank application database | Bind to lab interface only; app-scoped DB user |
| dnsmasq / BIND (optional) | 53 | Lab DNS | Only if a real DNS server is wanted; names already fixed in `configs/etc/hosts` |
| Log forwarder | 514/udp or 10514/tcp | Feed for the Stage 7 SIEM | Decided **with** Stage 7 — not locked in now |

Nothing is installed before it is documented here (minimalism principle).

## Log locations (formalized in Module 5)

| Source | Location |
|---|---|
| SSH / authentication | `/var/log/auth.log`, `journalctl -u ssh` |
| System | `journalctl`, `/var/log/syslog` |
| Package / update activity | `/var/log/dpkg.log`, `/var/log/apt/` |
| Firewall (after Module 4) | to be defined (nftables/UFW) |
