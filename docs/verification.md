# Verification

## Local checks

`amnesic-pi verify` checks:

- effective configuration parses;
- nftables table `inet amnesic_pi` exists;
- input/forward/output base policies are DROP;
- IPv4 forwarding is enabled only in the running secured state;
- IPv6 is disabled;
- Tor listeners are reachable locally.

These checks are necessary but not sufficient.

## Hardware adversarial checks

Before a release, use a downstream test client and prove:

1. normal TCP exits through Tor;
2. public IP differs from the uplink's clearnet address;
3. DNS requests do not appear at the uplink resolver;
4. `systemctl stop tor@default` causes loss of client Internet;
5. downstream UDP/443 does not leave directly;
6. IPv6 has no usable path;
7. adding a second unclassified interface does not create forwarding authority;
8. a marker written to root disappears after reboot with OverlayFS enabled.

Do not convert absence of an observed leak into a broad anonymity claim.
