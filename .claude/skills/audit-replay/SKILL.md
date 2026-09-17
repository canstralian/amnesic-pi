---
name: audit-replay
description: T1 skill. Verify the audit hash chain, check the mirror, and reconstruct orchestrator state by replay. Use on cold start, after any restart, and whenever orchestrator state looks wrong.
---

# audit-replay (T1 · orchestrator)

In-memory state is advisory. The log is the source of truth. Never trust
reconstructed state across a restart without replaying.

## Run it

```bash
amnesic-orchestrator coldstart        # the five section-10 checks, in order
amnesic-orchestrator audit-verify     # chain + mirror + state projection
```

Cold start runs: topology manifest → audit chain → audit mirror → key material →
node reconciliation. Any failure leaves the orchestrator in `READ_ONLY`: status
queries are served, no dispatch is issued, and an operator is paged. `dispatch`
refuses to run from `READ_ONLY` rather than proceeding unverified.

## Severity

| Finding | Severity | Response |
|---|---|---|
| `prev_hash` mismatch or sequence gap | SEV-2 | Halt dispatch. Forensic replay from the mirror. |
| Primary and mirror diverge | SEV-1 | Unauthorized write to a sink. Halt everything. |
| Mirror behind by n entries | SEV-1 if it does not converge | Re-check before acting. |

Both are operational incidents, not warnings. Every SEV produces a post-mortem
node in the work graph — post-mortems are T1 artifacts, not optional.

## Known property of the chain

A hash chain binds every entry **except the tail**, because no later entry
commits to the tail's hash yet. Tampering with the most recent entry is caught
by the mirror check, not by the chain check. Run both. Running only
`verify_chain` leaves a one-entry blind spot.

## What replay reconstructs

Dispatched tasks and their teams, gate results, reclaimed tasks, paused teams,
and the decision-memo count. Open tasks are those dispatched, not reclaimed, and
without a passing gate. Cold start reconciles those against the live topology and
refuses to open if an open task references a team or gate the manifest no longer
declares.
