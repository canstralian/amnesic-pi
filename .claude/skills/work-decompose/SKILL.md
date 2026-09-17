---
name: work-decompose
description: T1 skill. Turn a goal into a validated work graph where each node is owned by exactly one team, then dispatch the ready nodes. Use when starting any multi-team piece of work in this repository.
---

# work-decompose (T1 · orchestrator)

Produce a directed work graph, validate it, dispatch it. You are a router: if
you find yourself writing the deliverable, the decomposition failed — re-split.

## Heuristics

- A node needing two teams is a coordination bug. Split it. The schema makes
  this structural: `team` is a single value.
- Leaf nodes are bounded: one deliverable, **at most three** acceptance criteria.
  The validator rejects a fourth. That limit is the forcing function.
- Dependencies are explicit `depends_on` edges, never implied by node order.
- Every node names its `exit_gate`. A node with no gate cannot be done.
- The gate need not belong to the node's team. One team building and another
  gating is stronger than a team certifying itself — prefer it.

## Write the graph as JSON

```json
{
  "goal": "Close the downstream QUIC path",
  "invariants_touched": ["I3"],
  "nodes": [
    {
      "id": "quic-threat-delta",
      "title": "State the boundary delta for denying downstream QUIC",
      "team": "threat-research",
      "exit_gate": "SPEC_COMPLETE",
      "tier_max": "T3",
      "acceptance": ["invariants touched are named", "delta classified"],
      "deliverables": [{"kind": "report", "path": "docs/networking.md"}]
    },
    {
      "id": "quic-deny-rule",
      "title": "Deny non-53 downstream UDP explicitly",
      "team": "policy",
      "exit_gate": "POLICY_CLEAN",
      "tier_max": "T2",
      "depends_on": ["quic-threat-delta"],
      "acceptance": ["nft -c accepts", "udp/443 from client is dropped"],
      "deliverables": [{"kind": "ruleset", "path": "network/policy.nft.in"}]
    }
  ]
}
```

## Then run

```bash
amnesic-orchestrator validate-graph graph.json    # parse, validate, resolve teams
amnesic-orchestrator dispatch graph.json          # cold start, then dispatch ready nodes
```

`dispatch` holds any node whose dependencies have not passed their gates. That is
correct — sequence, do not share.

## Conflict resolution

Two teams claiming one artifact is refused by the validator. When two teams
genuinely disagree on a judgement call, write a `DecisionMemo`, log it, pick, and
move on. No consensus rounds. Never absorb the work to unblock — that is how a
router becomes a bottleneck.
