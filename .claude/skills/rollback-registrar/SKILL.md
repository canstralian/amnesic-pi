---
name: rollback-registrar
description: Classify and record the rollback path for an artifact before it ships. Use before signing RELEASE_SIGNED — the gate cannot pass without a pre-registered rollback.
---

# rollback-registrar (T3 · release)

Bounded task: one artifact in, one recorded rollback out. Registered *before*
release, never after.

## Classes

| Class | Means | Target | Extra requirement |
|---|---|---|---|
| `reversible` | revert ruleset, disable unit, reflash prior image | < 5 min | tested at least once |
| `forward-fix` | needs a policy patch or reprovision | < 24 h | declare an incident |
| `destructive` | withdraw a release, breaking change | — | T1 + human authorization |

## What a registration must contain

1. The artifact, by path and content hash.
2. The class, and why it is that class rather than the next one down.
3. The exact commands to execute the rollback, runnable from a local console
   with no network.
4. What the operator loses by rolling back — configuration, persistent state,
   uptime.
5. Evidence the rollback was **tested**, for `reversible` claims. An untested
   reversible rollback is really a `forward-fix`; classify it that way.

## Specific to this appliance

A rollback the operator cannot perform from a keyboard and a display is not a
rollback. Default-DROP means you may have no network when you need it most.
If the appliance boots into a broken firewall, the recovery path is console-only
— state it in those terms.

## Refuse

Registering `reversible` without a test. Registering a rollback whose first step
requires SSH. Signing off with the rollback "to be written".
