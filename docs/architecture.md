# Architecture

## State machine

```text
BOOT
  |
  v
FIREWALL_APPLY
  | success
  v
FORWARDING_ENABLE
  |
  v
TOR_START
  |
  v
VERIFY_LOCAL
  | success
  v
READY

Any failure -> DENY / NOT READY
```

There is intentionally no transition from a Tor failure state to ordinary routing.

## Authority model

The appliance separates **intent** from **authority**:

- an application can intend to reach the network;
- nftables decides whether that process/interface has authority;
- client packets are not granted forwarding authority;
- client TCP is redirected locally into Tor;
- the Tor service account is granted outbound TCP authority on the uplink.

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
