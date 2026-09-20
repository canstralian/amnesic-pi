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
- Forwarding authority lives inside the firewall transaction. No configuration
  file, unit, or convenience script may grant it.
- `verify` is read-only. It must not mutate the system on any path, including
  failure paths.
- `lockdown` disables forwarding before it touches nftables, and stays
  idempotent and safe after a partial apply.
- Network consumers are `BindsTo=` the firewall unit. Do not downgrade one to
  `Before=`, `Wants=` or `After=`: ordering is not authority.
- Nothing in the pre-network stage may depend on Tor or the network. Nothing
  that depends on Tor may run before Tor.
- MAC randomization uses cryptographic OS entropy and verifies the change by
  readback, excluding the burned-in address explicitly.
- Do not make exit-IP rotation a security invariant; successive Tor circuits
  are not guaranteed to use distinct exits.
- Do not add an outer VPN/proxy/public-IP rotator to Stage 1. That is a
  separate stage with a different threat model.
- Do not weaken a dependency to accommodate slow USB enumeration. Raise the
  bounded retry budget instead.

## When availability and anonymity conflict

At a pre-ready security boundary, fail closed. Connectivity loss is preferable
to accidental clearnet forwarding. Do not weaken fail-closed behaviour to make
a test pass.

## Change sequence

1. state the authority being added or changed;
2. update threat model if the boundary changes;
3. add or update a regression test;
4. implement the minimum code change;
5. run unit/static tests, the resolved systemd graph tests, and the namespace
   fail-closed suite (`sudo pytest -m netns`);
6. run root integration tests on Pi hardware before release.

State which verification tier produced any claim you make. "Unit tested",
"namespace/kernel integration tested", "systemd graph verified" and "Raspberry
Pi hardware tested" are different things and must not be conflated. See
`docs/verification.md`.

## Review focus

Review policy changes for:

- unintended output-chain exceptions;
- IPv6 bypasses;
- DNS bypasses;
- service ordering races;
- interface hotplug behaviour;
- unsafe shell interpolation;
- failures that replace DROP with ACCEPT;
- assumptions that only hold on one Raspberry Pi OS release;
- a `BindsTo=` quietly becoming an ordering directive;
- a drop-in that lands on a unit it does not gate;
- a claim of hardware validation that was not performed.
