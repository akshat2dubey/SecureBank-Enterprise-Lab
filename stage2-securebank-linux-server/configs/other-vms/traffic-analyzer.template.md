# Traffic Analyzer — ready-to-paste static network configuration (generated from lab.env)
# ========================================================================================
# Rendered by scripts/render-peer-configs.sh from lab.env at the repo root.
# Do not edit by hand — change lab.env and re-run the renderer.
# See stage2-securebank-linux-server/docs/network-design.md §7.

- Host:      @SB_ANALYZER_HOSTNAME@ (@SB_ANALYZER_HOSTNAME@.@SB_DOMAIN@)
  IPv4:      @SB_ANALYZER_IP@/@SB_LAB_PREFIX@   (lab segment)
  IPv6 ULA:  @SB_ANALYZER_IPV6@/@SB_IPV6_PREFIX@ (mirrors the v4 plan, §4b)
  Link-local IPv6 configures itself; the analyzer is passive and needs no
  inbound allow rules — the SecureBank firewall never blocks capture.
  Lab interface on the analyzer = the one already holding an address in the
  lab subnet (@SB_LAB_SUBNET@). Find it with:  ip -4 -o addr show
  (substitute the detected name for IFACE below — do not guess).

## Option A — netplan (Ubuntu cloud/server images)

`/etc/netplan/99-securebank-lab.yaml` (chmod 600):

```yaml
network:
  version: 2
  ethernets:
    IFACE:
      addresses:
        - "@SB_ANALYZER_IP@/@SB_LAB_PREFIX@"
        - "@SB_ANALYZER_IPV6@/@SB_IPV6_PREFIX@"
```

If the file you add is the only netplan file, add
`renderer: networkd` under `network:`. Leave any NAT NIC's existing
(DHCP) configuration alone so updates keep working; then `netplan apply`.
If a cloud-init-managed network config keeps overriding yours, drop the
same opt-out the SecureBank server uses (empty
`/etc/cloud/cloud.cfg.d/99-securebank-network.cfg`) — rendered copies of
the server's templates are in the same outputs directory.

## Option B — systemd-networkd (Debian images)

`/etc/systemd/network/10-securebank-lab.network`:

```ini
[Match]
Name=IFACE

[Network]
DHCP=no
IPv6AcceptRA=no
Address=@SB_ANALYZER_IP@/@SB_LAB_PREFIX@
Address=@SB_ANALYZER_IPV6@/@SB_IPV6_PREFIX@

[Link]
RequiredForOnline=no
```

Then `systemctl restart systemd-networkd`.

## Sanity checks (on the analyzer)

```bash
ping -c3 @SB_SRV_IP@        # server reachable
ping -c3 @SB_KALI_IP@       # Kali reachable
ip -6 addr show IFACE       # ULA + link-local both present
```

Then run the Stage 1 analyzer against IFACE as usual — its BPF filters and
report patterns stay valid because the address plan did not change.
