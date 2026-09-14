# Kali — ready-to-paste static network configuration (generated from lab.env)
# ==========================================================================
# Rendered by scripts/render-peer-configs.sh from lab.env at the repo root.
# Do not edit by hand — change lab.env and re-run the renderer.
# See stage2-securebank-linux-server/docs/network-design.md §7.

- Host:      @SB_KALI_HOSTNAME@ (@SB_KALI_HOSTNAME@.@SB_DOMAIN@)
  IPv4:      @SB_KALI_IP@/@SB_LAB_PREFIX@   (lab segment)
  IPv6 ULA:  @SB_KALI_IPV6@/@SB_IPV6_PREFIX@ (mirrors the v4 plan, §4b)
  Link-local IPv6 configures itself; SSH to the server over fe80::/10 keeps working.
  Lab interface on Kali = the one already holding an address in the lab
  subnet (@SB_LAB_SUBNET@). Find it with:  ip -4 -o addr show
  (substitute the detected name for IFACE below — do not guess).

## Option A — NetworkManager (Kali default)

```bash
nmcli con mod "IFACE" \
  ipv4.method manual ipv4.addresses @SB_KALI_IP@/@SB_LAB_PREFIX@ \
  ipv6.method manual ipv6.addresses @SB_KALI_IPV6@/@SB_IPV6_PREFIX@
nmcli con up "IFACE"
```

`"IFACE"` is the connection name from `nmcli con show` (often = interface
name). Keep the IPv4 gateway/DNS entries the connection already has (NAT
NIC handles internet); the lab segment itself has no gateway — routing to
the internet stays on the NAT NIC.

## Option B — netplan (Kali with netplan installed)

`/etc/netplan/99-securebank-lab.yaml` (chmod 600):

```yaml
network:
  version: 2
  ethernets:
    IFACE:
      addresses:
        - "@SB_KALI_IP@/@SB_LAB_PREFIX@"
        - "@SB_KALI_IPV6@/@SB_IPV6_PREFIX@"
```

Leave the rest of the config as it is (other interfaces keep DHCP for
updates); then `netplan apply`.

## Sanity checks (on Kali)

```bash
ping -c3 @SB_SRV_IP@        # server reachable
ping -c3 @SB_SRV_IPV6@      # server reachable over the ULA
getent hosts @SB_SRV_HOSTNAME_FQDN@   # after /etc/hosts sync (below)
```

## /etc/hosts (if you want names on Kali too)

The SecureBank server's `setup.sh` already maintains its own managed block.
On Kali, add (or update) the same three lab lines manually, or copy them
from the server's `/etc/hosts` block — they are generated from `lab.env`
and must match it exactly.
