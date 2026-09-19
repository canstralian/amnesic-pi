---
name: invariant-scribe
description: Reconcile documented invariants against the code that implements them. Use before signing SPEC_COMPLETE, after any policy or runtime change, and whenever the README's claims may have drifted from the implementation.
---

# invariant-scribe (T3 · docs)

Bounded task: for each documented invariant, find its implementation or report
it unimplemented.

## The ten invariants

Walk README "Security invariants" 1–10 in order. For each, produce one row:

| # | Claim | Implemented at | Tested at | Verdict |
|---|---|---|---|---|

Verdicts: `implemented+tested`, `implemented+untested`, `partial`,
`unimplemented`, `untestable-in-CI`.

## Rules

- A citation is `file:line`. "It's in the firewall" is not a citation.
- `untestable-in-CI` is a legitimate verdict and must be used honestly. Invariants
  8 and 9 — Tor-stop denial and reboot amnesia — cannot be proven by the unit
  suite. Marking them `implemented+tested` on the strength of `pytest` output is
  the specific error this skill exists to prevent.
- Also check `AGENTS.md` non-negotiables and `THREAT-MODEL.md` disclaimers for
  the same drift, in both directions: an undocumented control is also a finding,
  because operators cannot rely on what they are not told.

## Output

The table, then a short list of required doc edits. You may edit docs to match
the code. You may never edit code to match the docs — route that to the owning
team through T1.
