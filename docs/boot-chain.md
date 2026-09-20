# Boot Chain and Ordering

The critical property is that network authority cannot come up before the Amnesic Pi nftables deny policy exists and has been checked from the live kernel state.

## Security boundary

Stage 1 permits `net.ipv4.ip_forward=1`. IPv4 forwarding is not the clearnet-denial control.

The routed-traffic control is the `inet amnesic_pi` base chain attached to the `forward` hook:

- chain type `filter`;
- hook `forward`;
- policy `drop`;
- zero rules.

Because a nftables `drop` verdict is terminal, another base chain cannot turn a packet accepted elsewhere into a successful routed path after the Amnesic Pi forward chain drops it. The live verifier therefore checks both the base-chain shape and that the forward chain contains no rules.

IPv6 remains disabled and `net.ipv6.conf.all.forwarding=0` is asserted separately.

## Startup transaction

`amnesic-pi-firewall.service` is ordered:

- after local filesystems are available;
- before `systemd-sysctl.service`;
- before `network-pre.target`;
- before `NetworkManager.service`;
- before Tor.

The service runs two startup steps:

1. `ExecStart=/usr/local/sbin/amnesic-pi-firewall` installs the transactional nftables candidate.
2. `ExecStartPost=/usr/local/bin/amnesic-pi verify-firewall` reads the live nftables JSON state and rejects any missing/malformed base chain, non-DROP base policy, or rule in the forward chain.

systemd does not consider the service startup complete for `Before=/After=` ordering until `ExecStartPost=` finishes. A failed post-check therefore fails the firewall unit before ordered networking dependents are released.

## Enforced mode is an installed state

`RequiredBy=NetworkManager.service` is an `[Install]` directive. It does not create a runtime dependency merely because it is present in the repository.

After the operator runs `systemctl enable amnesic-pi-firewall.service`, systemd creates:

`/etc/systemd/system/NetworkManager.service.requires/amnesic-pi-firewall.service`

That installed symlink gives NetworkManager an effective `Requires=amnesic-pi-firewall.service` dependency. The explicit `Before=NetworkManager.service` supplies the separate ordering edge.

Run:

`sudo amnesic-pi verify-enforced-mode`

to prove the enabled state, the `.requires` link, the effective `Requires` and `After` relationships, the absence of a `Condition*=` skip path in the effective firewall unit, and `RefuseManualStop=yes`.

The `network-pre.target` ordering remains as the network-manager-independent synchronization point for firewall-before-interface configuration.

## Lifetime and recovery policy

`Requires=` propagates explicit stop/restart operations from the firewall to NetworkManager. To avoid an administrator accidentally destroying a remote management session, the firewall unit sets `RefuseManualStop=yes`.

Stage 1 deliberately does not add `BindsTo=`. The remaining extra behavior it would provide is primarily relevant to unexpected self-deactivation and condition-skipped activation. This firewall is a `Type=oneshot` unit with `RemainAfterExit=yes`, and enforced mode rejects any `Condition*=` directive. Adding a condition later is therefore a security-boundary change and must update the gate and tests first.

If firewall startup or its post-check fails:

- NetworkManager remains blocked in enforced mode;
- `amnesic-pi-firewall-failure.service` writes a message to the journal and console;
- repair is local-console-only.

After correcting the root cause, recover with:

`sudo systemctl reset-failed amnesic-pi-firewall.service && sudo systemctl start amnesic-pi-firewall.service NetworkManager.service`

Do not weaken the dependency or remove a verifier assertion to recover networking.

## Evidence boundary

Repository tests prove the declared source contract. `amnesic-pi verify-enforced-mode` proves the effective installed dependency state. Neither proves Raspberry Pi boot behavior.

A release still requires target-hardware failure injection showing that a failed firewall or failed post-check prevents NetworkManager activation, plus the downstream Tor, DNS, UDP/QUIC, IPv6, and reboot-amnesia gates.
