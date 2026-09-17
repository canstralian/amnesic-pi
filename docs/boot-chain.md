# Boot Chain and Ordering

The critical property is that IP forwarding is not enabled before the nftables deny policy exists.

`amnesic-pi-firewall.service` is ordered:

- after local filesystems are available;
- before `systemd-sysctl.service`;
- before `network-pre.target`;
- before Tor.

The nftables loader builds one transactional candidate batch. If the Amnesic Pi table already exists, the batch deletes only that table and recreates it; on first boot it simply creates it. The complete transaction is checked with `nft -c` before application. Unrelated firewall tables are never flushed.

`/etc/sysctl.d/99-amnesic-pi.conf` enables IPv4 forwarding only after the firewall unit has run, and disables IPv6.

This ordering should be validated on each supported Raspberry Pi OS release because init/network stack changes can alter boot sequencing.
