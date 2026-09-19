---
name: release-gate-runner
description: Walk the ten-item release gate and produce a boolean plus evidence per item. Use before signing RELEASE_SIGNED. Never use to infer a result that was not observed.
---

# release-gate-runner (T3 · release)

Bounded task: ten items, ten booleans, ten pieces of evidence.

## The checklist

| # | Item | Can CI prove it? |
|---|---|---|
| 1 | unit/static tests | yes — `pytest -q`, `ruff check src tests` |
| 2 | nftables syntax validation | yes — `nft -c -f` on the rendered template |
| 3 | firewall boot-order validation | partly — unit asserts; ordering needs a boot |
| 4 | Tor bootstrap validation | no — hardware |
| 5 | Tor-stop denial test | no — hardware + downstream client |
| 6 | downstream clearnet-denial test | no — hardware + downstream client |
| 7 | DNS leak test | no — hardware + downstream client |
| 8 | UDP/QUIC leak test | no — hardware + downstream client |
| 9 | IPv6 leak test | no — hardware + downstream client |
| 10 | reboot-amnesia test | no — hardware + reboot |

**Eight of ten require a Raspberry Pi.** That is the single most important fact
about this gate.

## Output format, per item

```
[n] item            PASS|FAIL|NOT-RUN
    evidence:       <command run, where, observed output>
```

`NOT-RUN` is mandatory when you did not perform the item. It is not a failure of
this skill — it is the honest result, and it blocks `RELEASE_SIGNED`, which is
correct behaviour.

## Refuse

Recording PASS for any item 4–10 on the basis of CI output, code reading, or a
previous release. Aggregating to an overall PASS while any item is NOT-RUN.
