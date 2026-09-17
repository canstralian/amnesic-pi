---
name: systemd-order-audit
description: Verify firewall-before-network boot ordering and that unit failure denies rather than opens. Use before signing RUNTIME_SOUND, or whenever systemd/ or the boot chain changes.
---

# systemd-order-audit (T3 · runtime)

Bounded task: prove the boot order cannot produce a window where traffic flows
before policy is installed.

## The ordering being enforced

```
BOOT -> FIREWALL DENY -> TOR -> VERIFY -> TOR-ONLY CLIENT CONNECTIVITY
                     \-> any failure -> DENY
```

## Checklist

1. `amnesic-pi-firewall.service` orders **before** anything that brings up
   networking, and before `tor@default.service`. Check `Before=`, `After=`,
   `WantedBy=`, and `DefaultDependencies=`.
2. Failure behaviour: if the firewall unit fails, the boot must not proceed to a
   state where forwarding is possible. `OnFailure=` and the unit's exit handling
   both matter.
3. `tor-amnesic-pi.conf` drop-in does not weaken the ordering or add a
   `Restart=` that masks repeated Tor failure.
4. `amnesic-pi-verify.service` runs after Tor and its failure is visible — a
   verify unit whose failure is ignored is decoration.
5. Cross-check against `tests/test_systemd.py`. If the test does not assert the
   ordering you just read, that is a finding: the assertion is missing.

## Race conditions to look for specifically

Interface hotplug after policy load (`eth1` on a USB adapter arrives late), and
`systemd-networkd` or `dhcpcd` racing the firewall unit.

## Output

Per-check pass/fail with the unit file and directive cited. Name any assertion
`tests/test_systemd.py` should gain.
