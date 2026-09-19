---
name: overlay-amnesia-check
description: Verify OverlayFS actually discards runtime writes across reboot, and state precisely what amnesia does and does not cover. Use before signing PLATFORM_READY or when a persistence question comes up.
---

# overlay-amnesia-check (T3 · platform)

Bounded task: prove, or disprove, that ordinary root writes vanish on reboot.

## Procedure

Use `scripts/check-amnesia.sh`, which is a two-phase test:

1. `sudo ./scripts/check-amnesia.sh arm` — writes a marker
2. `sudo reboot`
3. `sudo ./scripts/check-amnesia.sh verify` — marker must be gone

A single-phase run proves nothing. If you did not reboot between the phases, the
result is "not performed".

## State the boundary precisely

Amnesia covers **ordinary runtime filesystem writes to the root filesystem,
after the overlay mounts**. It does not cover:

- the boot partition (`/boot`, `/boot/firmware`) — writable and persistent
- attached persistent storage, which is opt-in and outside Stage 1
- anything written before the overlay is active
- RAM contents while powered, or swap if any is enabled
- external state: DHCP leases on the router, Tor's view of the circuit, logs
  already shipped off-box

Read `docs/persistence.md` and keep your report consistent with it. If your
findings contradict it, that is a finding for `docs`, routed through T1.

## Also check

Whether the RAM-backed upper layer can fill. An appliance whose tmpfs upper
layer exhausts under sustained logging fails in a way that is not obviously
amnesia-related. Report the observed headroom.
