---
name: fail-closed-redteam
description: Adversarially hunt for a clearnet path around the Tor gateway. Use before signing FAIL_CLOSED_PASS, after any policy change, and whenever someone claims the appliance is leak-proof.
---

# fail-closed-redteam (T3 · verification)

Bounded task: try to find a path from the downstream client to the Internet that
does not traverse Tor. Report what you tried, not just what you found.

## Attack surface to work through

1. **Tor down.** Stop `tor@default.service`. Does the client still reach
   anything? Does routing fall back? Does a cached route persist?
2. **Tor crashing repeatedly.** Not the same as stopped — check restart windows.
3. **DNS.** Query a resolver directly. Try TCP/53, DoT (853), DoH (443 to a known
   resolver), and mDNS. Try a hardcoded nameserver in the client's config.
4. **UDP and QUIC.** UDP/443, plain UDP to arbitrary ports, and fragments.
5. **IPv6.** Link-local, SLAAC, RA acceptance, and a literal `ip6` destination.
   IPv6 is meant to be disabled, not merely unrouted — verify which it is.
6. **Interface games.** Unplug and replug `eth1`. Bring up a third interface.
   Spoof the client's MAC. Rename an interface to the uplink's name.
7. **Boot window.** Power-cycle and probe continuously from the client during
   boot. Is there a window before policy loads where forwarding works?
8. **Config failure.** Corrupt `network.env`. Does the appliance fail closed, or
   does the firewall unit fail and leave the prior state permissive?

## Reporting

For every item: what you ran, from where, and the observed result. An untried
item is reported as untried — not as a pass.

## The one thing that matters

`FAIL_CLOSED_PASS` is unwaivable. If you cannot run this from real hardware with
a real downstream client, the correct output is `passed: false` with evidence
stating that the test was not performed. Never infer the result.
