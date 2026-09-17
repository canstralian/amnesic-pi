# Threat Model

## Objective

Amnesic Pi is intended to reduce two classes of failure on a Raspberry Pi gateway:

1. client traffic accidentally leaving through a non-Tor path; and
2. runtime state being unintentionally retained across reboots.

It is an engineering experiment, not an anonymity guarantee.

## Protected properties

### P1. No transparent clearnet fallback

If Tor is unavailable, misconfigured, stopped, or not yet ready, client traffic must fail rather than use ordinary forwarding/NAT.

### P2. Least-authority egress

In normal mode, only the Tor daemon receives outbound Internet TCP authority. DHCP required to acquire the uplink address is separately and narrowly permitted.

### P3. Ephemeral runtime

When Raspberry Pi OS OverlayFS is enabled, ordinary writes to the root filesystem should land in RAM and disappear at reboot.

### P4. Explicit persistence

Persistent data must live outside the ephemeral root and require an explicit design decision and mount path. Stage 1 does not auto-mount persistence.

## In-scope adversaries/failures

- application attempts direct TCP egress
- accidental UDP/QUIC use by clients
- DNS leakage from downstream clients
- Tor process failure
- service-ordering mistakes during boot
- an unexpected client interface trying ordinary forwarding
- accidental IPv6 leakage
- reboot after ordinary runtime writes

## Out of scope

- root/kernel compromise on the Pi
- compromised Raspberry Pi firmware or bootloader
- physical attacks against powered hardware
- global passive traffic correlation
- browser/device fingerprinting
- malicious Tor exits
- application-layer identity leaks
- hostile USB peripherals
- RF side channels
- compromise of a downstream client
- forensic recovery from RAM while powered

## Trust boundaries

```text
[downstream client]
       |
       | untrusted traffic
       v
[nftables policy]  <-- primary authority boundary
       |
       v
[Tor daemon]       <-- sole normal Internet TCP principal
       |
       v
[uplink network]   <-- untrusted
       |
       v
[Tor network / Internet]
```

The Linux kernel, nftables, Tor package, Raspberry Pi firmware, and base OS packages are trusted computing base components.

## Fail-closed interpretation

"Fail closed" in this project means **network authority is absent by default**. It does not mean the appliance is immune to arbitrary root modification. A root attacker can change firewall rules and is outside Stage 1's threat model.

## Security update rule

Kernel, Tor, nftables, NetworkManager/systemd, and Raspberry Pi OverlayFS changes can invalidate assumptions. Every such upgrade should be followed by:

1. static policy tests;
2. runtime `amnesic-pi verify`;
3. a Tor-stop fail-closed test; and
4. an amnesia/reboot persistence test.
