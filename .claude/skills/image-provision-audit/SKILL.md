---
name: image-provision-audit
description: Review image/provision.sh for idempotence, ordering, and OS-release assumptions. Use before signing PLATFORM_READY or whenever the provisioning script changes.
---

# image-provision-audit (T3 · platform)

Bounded task: audit provisioning for the three ways it breaks in the field.

## 1. Idempotence

Every step must survive being run twice. For each step ask: does re-running it
duplicate a line, overwrite an operator edit, or fail on "already exists"?
Config files written with `>` are a finding if the operator is expected to edit
them — `/etc/amnesic-pi/network.env` in particular must never be clobbered.

## 2. Ordering and failure

- `set -euo pipefail` present.
- The script never enables the firewall unit and reboots in one pass. The README
  requires manual console validation between apply and enable; provisioning that
  skips that step can brick remote access.
- A failure midway leaves the system in a state the operator can diagnose, not a
  half-configured one that boots into a broken firewall.

## 3. OS-release assumptions

Name every assumption about Raspberry Pi OS and state which release you verified
it on:

- package names (`tor`, `nftables`) and whether `debian-tor` is the user created
- `tor@default.service` being the right unit name and instance
- sysctl drop-in path and whether `sysctl --system` picks it up
- `raspi-config` menu path for OverlayFS — this moves between releases

## Output

Findings as `image/provision.sh:line — issue — failure mode`. Then a short list
of assumptions with the release each was checked against. An unverified
assumption is a finding.
