# Architecture

## State machine

```text
BOOT
  |
  v
TOPOLOGY                      both role interfaces enumerated (bounded retry)
  |
  v
MAC_RANDOMIZE                 os.urandom address, locally administered, unicast
  |
  v
MAC_READBACK_VERIFY           kernel reports our address, not the burned-in one
  |
  v
ZERO_IP_POSTURE               no configured address before the network starts
  |
  v
FIREWALL_APPLY                forwarding off for the whole transaction
  |
  v
FIREWALL_VERIFY               live kernel state matches the intended posture
  |
  v
FORWARDING_ENABLE             the only place forwarding authority is granted
  |
  v
NETWORK_MANAGER               BindsTo the firewall unit
  |
  v
TOR_START                     BindsTo the firewall unit
  |
  v
TOR_PATH_VERIFY               bootstrap, SOCKS circuit, Tor DNS
  |
  v
READY

Any failure before READY -> lockdown -> DENY / NOT READY
```

There is intentionally no transition from a Tor failure state to ordinary
routing, and no transition from a firewall failure state to a running network
manager.

## Authority model

The appliance separates **intent** from **authority**:

- an application can intend to reach the network;
- nftables decides whether that process/interface has authority;
- client packets are not granted forwarding authority;
- client TCP is redirected locally into Tor;
- the Tor service account is granted outbound TCP authority on the uplink.

Authority is also separated from **ordering**. A unit ordered `Before=` another
has said nothing about whether that other unit may run if it fails. The
appliance's consumers -- the network manager, Tor, the posture verifier -- are
`BindsTo=` the firewall unit, which is a lifetime relationship rather than a
sequencing hint. See [boot-chain.md](boot-chain.md).

Forwarding authority is transactional: it is created inside
`amnesic-pi-firewall apply` after policy verification, and destroyed by
`lockdown` before anything else on every failure and teardown path. No
configuration file grants it.

What this does **not** cover is stated in
[THREAT-MODEL.md](../THREAT-MODEL.md): `BindsTo=` tracks systemd unit state, not
nftables kernel state, so an out-of-band `nft flush ruleset` is not detected.

## Data path

```text
client TCP
  -> nft prerouting on CLIENT_IF
  -> redirect :9040
  -> Tor TransPort
  -> Tor circuit
  -> Internet

client UDP/53
  -> nft prerouting on CLIENT_IF
  -> redirect :5353
  -> Tor DNSPort

client other UDP
  -> DROP
```

The forward chain remains DROP. The design does not depend on masquerading/NATing downstream traffic to the uplink.

## Host egress

Output is DROP by default. Allowed Stage 1 egress:

- loopback;
- established/related replies;
- Tor daemon TCP on the uplink;
- DHCP client traffic required to acquire an IPv4 uplink lease.

No general host DNS exception is provided.

## Amnesia

Amnesia relies on Raspberry Pi OS's supported OverlayFS mode rather than a bespoke initramfs implementation in Stage 1. This reduces custom boot-chain code while the network boundary is being validated.
