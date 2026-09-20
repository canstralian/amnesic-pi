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
- amnesic-pi-firewall.service failing to start, or stopping/crashing after boot
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
- network stacks other than NetworkManager and systemd-networkd (e.g., dhcpcd, wicd)
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

## Boot-time authority ordering

Sequencing alone (`Before=`/`After=`) does not stop a dependent unit from
starting if the unit it is ordered after fails; only `Requires=`/`BindsTo=`
does. Stage 1 relies on hard dependencies, not comments, for this:

- `NetworkManager.service` and `systemd-networkd.service` each carry a
  `BindsTo=amnesic-pi-firewall.service` drop-in. Neither can start unless the
  firewall started successfully, and a later firewall stop or crash stops
  whichever one is active. Both drop-ins ship unconditionally; a drop-in for
  a unit that is not installed on a given image is simply never loaded, so
  this does not require guessing which network stack is present.
- `net.ipv4.ip_forward` is not set by the unconditional boot-time sysctl
  file. It is enabled only by `amnesic-pi apply-firewall` itself, in the same
  process, immediately after its `nft -f` transaction is confirmed to have
  succeeded. There is no path that turns on forwarding without the
  forward-drop table already being live.

Other Stage 1 network stacks (dhcpcd, wicd, or anything else that does not
match one of the two units above) are out of scope: verify which network
manager an image actually runs before relying on this guarantee.

## Fail-closed interpretation

"Fail closed" in this project means **network authority is absent by default**. It does not mean the appliance is immune to arbitrary root modification. A root attacker can change firewall rules and is outside Stage 1's threat model.

## Security update rule

Kernel, Tor, nftables, NetworkManager/systemd, and Raspberry Pi OverlayFS changes can invalidate assumptions. Every such upgrade should be followed by:

1. static policy tests;
2. runtime `amnesic-pi verify`;
3. a Tor-stop fail-closed test; and
4. an amnesia/reboot persistence test.
