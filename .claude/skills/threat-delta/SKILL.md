---
name: threat-delta
description: Derive the THREAT-MODEL.md delta for a proposed change to Amnesic Pi. Use when a change adds, removes, or alters network authority, or when a reviewer asks "does this move the security boundary". Produces a memo, never an edit.
---

# threat-delta (T3 · threat-research)

Bounded task: given a proposed change, state what it does to the threat model.

## Procedure

1. Read `THREAT-MODEL.md` and the README's numbered invariants (1–10).
2. Identify which invariants the change touches. Name them by number.
3. Classify the delta as exactly one of:
   - **none** — the boundary is unchanged
   - **narrows** — a previously open path is now closed
   - **widens** — new authority exists; a regression test is now mandatory
   - **reclassifies** — the same authority, different principal or condition
4. If **widens**, name the new egress principal explicitly and state what test
   would prove its failure path stays closed.

## Output

A memo with: invariants touched, classification, new principal (if any),
required test (if any), and the team that must act. Nothing else.

## Refuse

Editing `THREAT-MODEL.md` yourself — that is `docs`. Certifying a control
works — that is `verification`. Declaring a delta "none" without naming the
invariants you checked.
