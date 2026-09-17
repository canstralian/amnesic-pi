---
name: leak-test-author
description: Write the regression test that proves a specific failure path stays closed. Use whenever a change broadens network authority, or when a gate failure needs a test that would have caught it.
---

# leak-test-author (T3 · verification)

Bounded task: one failure path in, one test out that fails if the path opens.

## The rule

From the README: *"Any change that broadens network authority must include a
regression test demonstrating that its corresponding failure path remains
closed."* You write that test. The test comes **before** the code change.

## Choose the right layer

| Layer | File | Can prove |
|---|---|---|
| Unit/static | `tests/test_*.py` | The rendered ruleset contains, or lacks, a construct |
| Root integration | `tests/integration/fail_closed.sh` | Local kernel-level behaviour with root |
| Hardware | manual, from a downstream client | Actual leak behaviour — the only real proof |

Be honest about which layer you are writing at. A unit test asserting a string
appears in a template is useful, but it is **not** evidence a packet was dropped.
Say so in the test's docstring.

## Pattern for a unit-level invariant test

Follow the existing style: render the real template through the real config, then
assert on the output. See `tests/test_firewall.py`. Assert the *negative* too —
that the permissive construct is absent — because a test that only checks the
deny rule exists will pass when an accept rule is added beside it.

## Refuse

Writing a test that asserts the implementation rather than the invariant.
Weakening an existing assertion. Marking a test `skip` or `xfail` to get green —
if it cannot pass, that is a finding, not a test change.
