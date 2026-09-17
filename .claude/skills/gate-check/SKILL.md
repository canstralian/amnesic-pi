---
name: gate-check
description: T1 skill. Record a gate result for a dispatched task. Use when a team lead reports a gate outcome, or before any ship decision. Enforces that gate results are hard booleans from the owning team.
---

# gate-check (T1 · orchestrator)

A gate returns `true` or `false`. There is no partial credit, no soft pass, and
`pct_complete` is never an input.

## The seven gates

```bash
amnesic-orchestrator gates
```

| Gate | Owner | Waivable |
|---|---|---|
| `SPEC_COMPLETE` | docs | yes |
| `POLICY_CLEAN` | policy | yes |
| `RUNTIME_SOUND` | runtime | yes |
| `VERIFY_PASS` | verification | yes |
| `FAIL_CLOSED_PASS` | verification | **NEVER** |
| `PLATFORM_READY` | platform | yes |
| `RELEASE_SIGNED` | release | yes |

## Recording a result

```python
dispatcher.accept_gate(task_id, {
    "gate": "POLICY_CLEAN",
    "passed": False,
    "evidence": ["nft -c rejected rule at policy.nft.in:31"],
    "checked_by": "policy",
})
```

Four things are enforced and will raise rather than warn:

1. `passed` must be a real `bool`. `1`, `"true"`, and `0.99` are rejected —
   soft-pass is a bug.
2. `evidence` must be non-empty. An unevidenced pass is not a pass.
3. `checked_by` must be the gate's owning team. `release` cannot certify `policy`.
4. The gate must match the task's declared `exit_gate`.

A lead cannot self-report `gate_pass` through the status stream either; that
path raises. Gates advance only here.

## Waivers

`waive("SPEC_COMPLETE", approver=..., rationale=...)` returns a waiver record.
`waive("FAIL_CLOSED_PASS", ...)` raises `PolicyBreach` by construction. That is
not an obstacle to work around — it is the one rule with no exception. A release
that skipped it is an incident, not a waiver.

## Before shipping

```python
dispatcher.assert_shippable(graph_id)   # raises PolicyBreach naming ungated nodes
```
