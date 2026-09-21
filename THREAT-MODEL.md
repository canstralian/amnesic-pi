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

### P2a0. Containment does not share a failure mode with what it contains

`amnesic-pi-firewall lockdown` reads no configuration. A malformed
`network.env` must not be able to break both the firewall unit and the
`OnFailure=` lockdown that exists to contain it.

Containment also comes before cleanup. The permissive policy table is removed
only once the deny posture is actually installed; if the deny posture fails to
load, the existing policy is **retained** and the failure is reported. The
alternative -- removing it anyway -- leaves no table at all, and the kernel's
own defaults then accept. Forwarding is off on both paths, but forwarding
governs the `forward` hook only: it says nothing about traffic local processes
originate, which the `output` hook governs.

### P2a. Forwarding authority is transactional

Forwarding does not exist until `amnesic-pi-firewall apply` has installed the nftables policy and verified it against the live kernel. No boot-time sysctl, and no other unit, can grant it. Every failure path within the transaction runs `lockdown`, which disables forwarding before it touches nftables. A configuration or template error is refused before the transaction begins, so nothing is torn down and nothing is contained; `apply` reports that state distinctly rather than claiming containment it did not perform.

### P2a1. Egress authority is verified as exclusive, not as present

`verify` accounts for every rule in the `output` chain against a named
exception, and for every rule in `prerouting` against the two client redirects.
Finding the Tor grant's terms somewhere in a chain does not establish that Tor
is the only egress principal: a second, UID-less accept rule leaves every term
in place while authorizing every local process. Each redirect must likewise
match as one whole rule, so that the interface, the protocol and the Tor port
belong to the same rule rather than merely to the same chain.

### P2b. Link-layer identity is randomized before the network exists

Each role interface receives a locally administered, unicast MAC derived from `os.urandom` before the network manager is allowed to start. The change is verified by reading the address back from the kernel and asserting it is neither the burned-in address nor the pre-change address.

This addresses passive observation of the appliance's link-layer identity on the uplink segment. It does not address an adversary who can correlate the appliance by timing, traffic shape, or any identifier above layer 2.

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
- a unit failing while the units depending on it start anyway
- a NIC or USB-Ethernet driver silently ignoring a MAC change
- a partially applied firewall policy
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
- out-of-band mutation of the nftables ruleset by root (see below)
- correlation of the appliance above layer 2 despite MAC randomization

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

## Known limitation: out-of-band nftables mutation

`BindsTo=` observes **systemd unit state**, not nftables **kernel state**.

If somebody runs:

```bash
nft flush ruleset
```

while `amnesic-pi-firewall.service` is still `active (exited)`, systemd sees no
change. The unit is active, so the units bound to it keep running, and the
policy that constrained them is gone.

Stage 1 therefore does **not** claim:

```text
policy loss => connectivity loss
```

What Stage 1 does claim is narrower and accurate:

```text
firewall unit becomes inactive => network manager and Tor become inactive
```

Detecting out-of-band ruleset mutation needs an integrity watcher -- an
nftables netlink monitor, or a periodic `amnesic-pi-firewall verify` that
triggers lockdown on mismatch. Neither is in Stage 1. A watchdog is a real
authority component with its own failure modes, and adding one casually would
create a new way for the appliance to lock itself out. It is tracked as
separate future work.

Two things reduce the practical exposure without closing the gap:

- `amnesic-pi-firewall verify` is read-only and can be run on demand or from a
  timer by an operator who wants periodic confirmation;
- flushing the ruleset requires root, which is already outside the threat model.

This limitation is stated here rather than papered over, because the difference
between "the unit is active" and "the policy is installed" is exactly the kind
of gap a fail-closed claim must not hide.

## Security update rule

Kernel, Tor, nftables, NetworkManager/systemd, and Raspberry Pi OverlayFS changes can invalidate assumptions. Every such upgrade should be followed by:

1. static policy tests;
2. the resolved systemd graph tests and `systemd-analyze verify`;
3. the namespace fail-closed suite (`pytest -m netns`);
4. runtime `amnesic-pi-firewall verify`;
5. runtime `amnesic-pi-anon verify-tor-path`;
6. a Tor-stop fail-closed test; and
7. an amnesia/reboot persistence test.

A systemd upgrade specifically can change how `BindsTo=` and `OnFailure=`
resolve, so step 2 is not optional after one.
