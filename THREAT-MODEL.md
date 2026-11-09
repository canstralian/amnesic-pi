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

`amnesic-pi-firewall lockdown` reads no configuration -- not from
`network.env`, and not from an `EnvironmentFile=` on the unit itself. A
malformed `network.env`, or one the containment unit cannot read, must not be
able to break both the firewall unit and the `OnFailure=` lockdown that
exists to contain it.

### P2a1. A sustained post-Tor posture failure also revokes authority

`amnesic-pi-posture.service` -- the last gate before the appliance declares
itself ready -- carries `OnFailure=amnesic-pi-lockdown.service`, the same as
the firewall and anonymity stages. Without this, a posture that never
verifies (Tor permanently unreachable, a bridge that never connects, a
listener that never comes up) left the appliance running indefinitely in an
"operational but unready" state: not leaking, because the installed policy
still only permits the Tor-redirected path, but not contained either.

This is safe only because `amnesic-pi-anon verify-tor-path` itself retries
within a bounded budget (`TOR_WAIT_SECONDS`, default 120s) before returning
nonzero -- see `torpath.wait_for_tor_path`. Listener, circuit and DNS startup
failures may retry. A failed firewall check or a positive leak signal is
terminal and returns immediately to systemd's containment path. Network probes
share an attempt budget (at most 45s), clamped to the remaining retry budget;
partial SOCKS reads and echo responses cannot renew that deadline. Kernel
commands have a separate 10s timeout, so this is not a hard real-time guarantee.

Operator consequence: a Tor outage that outlasts the retry budget locks the
appliance down and requires manual recovery. `amnesic-pi-posture.service` is
`BindsTo=amnesic-pi-firewall.service`, not the reverse: restarting the
firewall unit alone restores forwarding and the verified policy, but it does
not restart posture, and `amnesic-pi-posture.service` stays in its last
*failed* state -- the appliance can regain authority while still reporting
unready. Fix the cause, then restart both, and confirm posture actually
passed rather than assuming it did because forwarding came back:

```bash
sudo systemctl restart amnesic-pi-firewall.service
sudo systemctl restart amnesic-pi-posture.service
sudo systemctl is-active amnesic-pi-posture.service
```

This is the same trade already made for the firewall unit: connectivity loss
beats an appliance that stays "almost ready" forever. See
`docs/boot-chain.md`.

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

The forward chain must remain empty with a DROP default. A literal search for
`accept` is insufficient: `jump`, `goto` or a verdict map can delegate to a
regular chain that accepts. No forwarding control flow is admitted in Stage 1.

### P2a2. Interrupted activation revokes authority

Once the apply transaction begins, unexpected errors and cancellation run
configuration-free lockdown before returning. A failed or unreadable final CLI
recheck also revokes forwarding. SIGINT/SIGTERM during a mutating CLI command
attempt containment and return 130/143 respectively; cleanup temporarily ignores
repeated termination requests. Verification commands remain read-only, including
on interruption; their systemd `OnFailure=` relationship owns containment.

Failed cleanup is reported as unproven, never as successful lockdown. SIGKILL,
power loss, kernel failure and out-of-band policy mutation are not covered by
Python signal handling. There is no automatic clearnet recovery or retry that
regrants authority after containment; recovery remains an operator action.

### P2b. Link-layer identity is randomized before the network exists

Each role interface receives a locally administered, unicast MAC derived from `os.urandom` before the network manager is allowed to start. The change is verified by reading the address back from the kernel and asserting it is neither the burned-in address nor the pre-change address.

Readback succeeds while the link is down before it is raised, and is repeated
afterward. Entropy failure never falls back to a predictable address. If any
interface fails or the stage is cancelled, link-down is attempted for every
configured interface, including earlier successes. Loopback is rejected as
either a network role or a randomization target. Drivers can still refuse a
link-down request; forwarding/firewall containment remains a separate boundary.

This addresses passive observation of the appliance's link-layer identity on the uplink segment. It does not address an adversary who can correlate the appliance by timing, traffic shape, or any identifier above layer 2.

### P2c. Time comes from Tor, forward-only, with no time egress

Tor will not use a consensus whose validity window does not contain the system clock. A Pi without a battery-backed RTC, booting from a frozen OverlayFS image, starts in the past and would never bootstrap. No NTP principal exists: the Tor UID remains the only egress principal. Instead, `amnesic-pi-clock.service` reads the consensus Tor fetched this boot from Tor's data directory and, if the clock is more than an hour behind its `valid-after`, moves the clock forward to it and restarts Tor.

- **No new network authority.** The clock helper sends nothing. It reads a file.
- **Forward-only.** A clock ahead of the consensus is reported, never corrected. Moving the clock back would let a replayed, stale consensus look current.
- **This boot's consensus only.** `forget-consensus` runs as Tor starts and removes the cached consensus, because under OverlayFS the cache and the boot clock are frozen together and would agree while both being stale.
- **Trust added.** The clock now trusts a consensus document's timestamps before this code checks its signatures. Tor fetched it over TLS from directory caches it authenticates by identity key, but a malicious directory cache could serve a future-dated document. The worst outcome is a clock pushed forward, which makes Tor reject the real consensus: denial of service, not a clearnet path. A battery-backed RTC (Pi 5 J5 connector) removes this path, because the clock is already inside the window and nothing is changed.
- **Not a gate.** The helper has no `OnFailure=` lockdown. A clock it could not fix leaves Tor unbootstrapped, which the posture gate detects and locks down on.

### P2d. Package updates go through Tor, not around the firewall

Root has no uplink authority, so plain `apt` cannot reach a mirror. Provisioning rewrites every apt source to `tor+https://`, and apt-transport-tor carries those requests over Tor's loopback SOCKS listener. Loopback was already permitted, so the policy is unchanged and no maintenance window opens with the firewall down. The `https` upgrade means an exit relay sees a TLS session to the mirror, not which packages are being fetched. apt still verifies every index against the archive keyring.

A source added later as plain `http://` has no route: it times out rather than leaking. `amnesic-pi apt verify` reports it. Provisioning's first `apt-get install` is the appliance's one clearnet fetch, because it runs before the firewall exists.

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
- a boot clock frozen with the image, stalling Tor's bootstrap
- an update path that needs the firewall lowered

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
- a directory cache serving a future-dated consensus to push the clock forward (denial of service only; see P2c)
- precise time: the consensus-derived clock is accurate to roughly an hour

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
