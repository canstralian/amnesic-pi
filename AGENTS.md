# Agent and Contributor Rules

This repository treats network policy as a security boundary.

## Non-negotiable invariants

- Default network policy remains deny.
- Do not add generic forwarding/NAT as a convenience fallback.
- Do not authorize outbound traffic by executable name alone.
- Any new egress principal must be explicit and documented.
- IPv6 remains disabled until equivalent tests exist.
- Tor failure must never create a clearnet route.
- A configuration parse failure must not flush a known-good firewall ruleset.
- Do not silently guess interface names during runtime activation.
- Security-sensitive configuration changes require tests.

## Change sequence

1. state the authority being added or changed;
2. update threat model if the boundary changes;
3. add or update a regression test;
4. implement the minimum code change;
5. run unit/static tests;
6. run root integration tests on Pi hardware before release.

## Review focus

Review policy changes for:

- unintended output-chain exceptions;
- IPv6 bypasses;
- DNS bypasses;
- service ordering races;
- interface hotplug behaviour;
- unsafe shell interpolation;
- failures that replace DROP with ACCEPT;
- assumptions that only hold on one Raspberry Pi OS release.
