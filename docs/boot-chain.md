# Boot Chain and Ordering

The critical property is that network authority cannot come up before the nftables deny policy exists.

Stage 1 does not require kernel IPv4 forwarding. Downstream TCP and DNS are redirected in nftables prerouting to local Tor listeners, so `net.ipv4.ip_forward` remains `0`. Removing that unnecessary capability closes the ordinary routed client path even if another boot dependency regresses.

`amnesic-pi-firewall.service` is ordered:

- after local filesystems are available;
- before `systemd-sysctl.service`;
- before `network-pre.target`;
- before `NetworkManager.service`;
- before Tor.

The unit also declares `RequiredBy=NetworkManager.service` in its `[Install]` section. When the operator enables the firewall after manual validation, systemd creates a hard NetworkManager requirement. Combined with the explicit ordering, a firewall activation failure prevents NetworkManager from starting instead of merely recording a failed firewall unit while networking continues.

Tor independently declares `Requires=amnesic-pi-firewall.service` and `After=amnesic-pi-firewall.service`.

The nftables loader builds one transactional candidate batch. If the Amnesic Pi table already exists, the batch deletes only that table and recreates it; on first boot it simply creates it. The complete transaction is checked with `nft -c` before application. Unrelated firewall tables are never flushed.

`/etc/sysctl.d/99-amnesic-pi.conf` keeps IPv4 forwarding disabled, disables redirects and source-route acceptance, and disables IPv6 for Stage 1.

This dependency graph still requires validation on each supported Raspberry Pi OS release. The repository test proves the declared systemd contract; only a real boot-failure injection on target hardware proves that the installed operating system honors the intended fail-closed transition.
