---
name: egress-authority-review
description: Verify a new or changed egress principal is explicit, UID-based, and documented. Use whenever a change adds an output-chain accept rule or grants a process outbound network access.
---

# egress-authority-review (T3 · policy)

Bounded task: one proposed egress grant in, an accept-or-refuse out.

## The rule being enforced

From `AGENTS.md`: *"Do not authorize outbound traffic by executable name alone.
Any new egress principal must be explicit and documented."* From the README:
*"An application wanting a socket does not grant it authority to reach the
Internet."*

## Accept only if all five hold

1. The principal is identified by **UID**, resolved at apply time from a
   validated username — not by comm name, cgroup, or port.
2. The grant names its protocol and direction explicitly.
3. The grant is scoped to the uplink interface.
4. A regression test exists that fails if the grant is widened.
5. The principal is documented in `docs/networking.md` or `THREAT-MODEL.md`.

## Refuse, and say which condition failed

Anything matched by executable name. Anything granted "temporarily". Any grant
whose test you cannot point at. A second principal added in the same change as
the first — review them separately.

## Note on the existing grant

Tor is currently the only normal process with outbound TCP authority, resolved
via `pwd.getpwnam(config.tor_user).pw_uid` in `src/amnesic_pi/firewall.py`.
That is the pattern. A second principal doubles the attack surface of the output
chain, so state that cost explicitly in your verdict.
