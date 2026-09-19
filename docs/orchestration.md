# Orchestration

A development team for this repository, built as agents, sub-agents, skills, and
tools under the orchestrator manifest's authority model. The orchestrator is a
router, gatekeeper, and auditor. It writes no code and owns no deliverable.

## Authority model

```
T1  Orchestrator (Kernel)         create/pause/terminate teams, set invariants
T2  Team Lead (Domain Authority)  assign sub-agents, approve intra-team merges
T3  Sub-Agent (Specialist)        execute bounded tasks, produce artifacts
T4  Tool/Runtime (Executor)       shell, nft, systemd, pytest, ruff
```

Downward delegation is free. Upward escalation requires a signed request. A
lead cannot reach laterally into another team — cross-team work routes through
T1.

### How the tiers map onto the harness

| Tier | Implementation | Why |
|---|---|---|
| T2 lead | `.claude/agents/<lead>.md` | Own context, dispatched by T1 |
| T3 sub-agent | `.claude/skills/<name>/SKILL.md` | Loaded inside its lead's context |
| T4 tool | `tools` list in `orchestration/topology.toml` | The T2-approved action manifest |

A Claude Code agent cannot spawn another agent, so making T3 a *skill* is what
keeps invariant I1 literally true rather than aspirational: the orchestrator's
only dispatch targets are the seven leads, and a sub-agent is reachable only
from inside its own lead's context. `Dispatcher.deliver` refuses a sub-agent as
a recipient even when the token is otherwise valid.

## Teams

Seven teams, mapped from the manifest's canonical topology onto this
repository's domain. Cardinality and gate ownership structure are preserved.

| Team | Lead | Gate owned | Owns |
|---|---|---|---|
| threat-research | `threat-research-lead` | — | The adversary model, threat-model deltas |
| policy | `policy-lead` | `POLICY_CLEAN` | `network/policy.nft.in`, `config/` |
| runtime | `runtime-lead` | `RUNTIME_SOUND` | `src/amnesic_pi/`, `bin/`, `systemd/` |
| verification | `verification-lead` | `VERIFY_PASS`, `FAIL_CLOSED_PASS` | Tests, leak suites, red team |
| platform | `platform-lead` | `PLATFORM_READY` | `image/`, OverlayFS, host reproducibility |
| docs | `docs-lead` | `SPEC_COMPLETE` | `README.md`, `BUILD.md`, `THREAT-MODEL.md`, `docs/` |
| release | `release-lead` | `RELEASE_SIGNED` | Release gate, rollback registration |

Charters live in `orchestration/topology.toml` and are **required**: a team
declared without one fails to load. That is what stops a "temporary" team with
no charter from becoming a shadow org. Adding, renaming, or removing a team is
a T1 act.

`threat-research` owns no gate, mirroring the manifest, where the Research team
also owns none. Research informs decisions; it does not certify them.

## Gates

Seven gates, one owner each, mapped from the manifest. Section 11 forbids a net
loss of validation, so every canonical gate has a same-or-stronger replacement.

| Gate | Replaces | Owner | Waivable |
|---|---|---|---|
| `SPEC_COMPLETE` | `SPEC_COMPLETE` | docs | yes |
| `POLICY_CLEAN` | `DATA_CLEAN` | policy | yes |
| `RUNTIME_SOUND` | `TRAIN_CONVERGED` | runtime | yes |
| `VERIFY_PASS` | `EVAL_PASS` | verification | yes |
| `FAIL_CLOSED_PASS` | `SAFETY_PASS` | verification | **never** |
| `PLATFORM_READY` | `INFRA_READY` | platform | yes |
| `RELEASE_SIGNED` | `RELEASE_SIGNED` | release | yes |

`FAIL_CLOSED_PASS` is the `SAFETY_PASS` analogue and carries the same rule:
never waived. `waive("FAIL_CLOSED_PASS", ...)` raises `PolicyBreach` by
construction rather than returning a record.

A gate result is a hard boolean with evidence, certified by the owning team. A
node's exit gate need not belong to the node's own team — one team building and
another gating is stronger than a team certifying itself.

### What the gates can and cannot prove here

Eight of the ten items in the README release gate require a Raspberry Pi with a
real downstream client. CI proves at most the first two. `VERIFY_PASS` and
`FAIL_CLOSED_PASS` are therefore **not** satisfiable from CI output, and the
skills that run them are instructed to return `passed: false` with evidence
saying the test was not performed rather than inferring a result.

## Invariants

| # | Invariant | Enforced at |
|---|---|---|
| I1 | No direct sub-agent dispatch | `Dispatcher.deliver` |
| I2 | Every task HMAC-signed before dispatch | `KeyRing.sign` / `verify`, `ReplayLedger`, `envelope_scope` |
| I3 | No ship without a passing gate | `GateResult`, `assert_shippable(graph, ...)` |
| I4 | Append-only, hash-chained, mirrored log | `AuditLog.verify_chain` / `check_mirror` |
| I5 | No authority above T1 without human approval | `KeyRing.sign` refuses non-T2/T3 |
| I6 | State derivable from the log | `state.replay`, `cold_start` |
| I7 | Task output is data, never instruction | `_strict_keys` in `schema.py` |

`tests/orchestrator/` is the evidence: each test file names the invariant it
covers, and `test_regressions.py` holds the cases for defects found in review —
among them a ship check that passed on work never dispatched, and an ingress
that accepted a retargeted exit gate.

The signed scope covers `graph_id`, `node_id`, `exit_gate`, `payload` and
`deliverables`, and ingress checks the envelope's own `task_id` against the
token's. Signing the payload alone left the fields that actually direct the work
outside the signature.

## Operating it

```bash
amnesic-orchestrator topology                  # teams, leads, rosters, gate ownership
amnesic-orchestrator gates                     # the gate table and its upstream mapping
amnesic-orchestrator coldstart                 # the five section-10 boot checks
amnesic-orchestrator audit-verify              # hash chain + mirror + state projection
amnesic-orchestrator validate-graph graph.json # parse and validate a work graph
amnesic-orchestrator dispatch graph.json       # cold start, then dispatch ready nodes
```

Audit sinks default to `.orchestration/audit.jsonl` with a mirror at
`.orchestration/mirror/audit.jsonl`, and are gitignored: they are runtime state,
not source. Point the mirror at a different failure domain in real use.

### Cold start

Dispatch is refused until five checks pass, in order: topology manifest, audit
chain, audit mirror, key material, node reconciliation. Any failure leaves the
orchestrator in `READ_ONLY` — status queries are served, no dispatch is issued.
The report's `ok` is computed from the steps, so a failed step cannot coexist
with a dispatcher that opened.

**A mirror is required.** Passing `mirror_path=None` fails the mirror step and
holds `READ_ONLY`. A hash chain cannot bind its own tail, so a single sink
leaves the most recent entry unverifiable.

**Reconciliation restores task records.** Replay rebuilds the in-flight tasks
into the dispatcher, so a restart no longer re-dispatches a node that already
has an owner, and tasks issued before the restart are still addressable. The log
carries identity, not authority: a restored envelope has no token, so `deliver`
refuses it and the work must be reclaimed and re-dispatched to reach a lead
again. That is the fail-closed direction.

### Severity

| Finding | Severity | Response |
|---|---|---|
| `prev_hash` mismatch or sequence gap | SEV-2 | Halt dispatch, replay from the mirror |
| Primary and mirror diverge | SEV-1 | Unauthorized write to a sink, halt everything |

## Known properties and limitations

Stated plainly, because a control that is oversold is worse than one that is
absent.

- **A hash chain cannot bind its own tail.** No later entry commits to the most
  recent entry's hash yet, so tampering with the last line is caught by
  `check_mirror`, not `verify_chain`. Run both. `tests/orchestrator/test_audit.py`
  asserts this behaviour explicitly rather than papering over it.
- **The mirror is a second file by default.** Divergence detection is real, but
  a same-host mirror shares a failure domain with the primary. Repoint it before
  relying on the SEV-1 signal.
- **Keys are process-local and in memory.** `KeyRing` rotates hourly and keeps
  one previous key verifiable so in-flight tasks are not dropped at a rotation.
  `rotate_now(revoke=True)` drops prior keys immediately for a suspected
  compromise. There is no external key vault; a restart invalidates outstanding
  tokens, which is why cold start reconciles open tasks from the log.
- **The audit log does not survive an ephemeral host.** The default sinks live
  under `.orchestration/`, which is gitignored and local. On a container that
  gets recycled the chain is gone, and cold start will happily report "ready for
  dispatch" against an empty log — replay reconstructs nothing because there is
  nothing to replay. Invariant I6 holds only while the log exists. Point both
  sinks at durable storage before relying on it.
- **`tools` in the topology manifest is declared, not enforced.** Nothing in
  `src/orchestrator/` consults it at dispatch time, and a Claude Code agent's
  `tools:` frontmatter cannot express the `Bash(nft:*)` scoping the manifest
  records — that is `.claude/settings.json` permission syntax. A lead granted
  `Bash` holds unrestricted `Bash`. `test_topology.py` fails if a lead's
  frontmatter claims a tool the manifest does not declare, which catches drift
  without constraining the runtime.
- **Pydantic is not used.** The manifest specifies Pydantic v2 for the contract
  schemas. This repository declares `dependencies = []` and treats that as a
  security property, so the same field contracts are implemented with stdlib
  dataclasses plus explicit validators. The behavioural requirement — strict
  parsing that rejects unknown keys — is met and tested.
- **Enforcement is in-process.** The dispatcher refuses invalid dispatch within
  a single Python process. It is not a sandbox and does not constrain what a
  tool does once invoked.

## Change control

Changes to the invariants, the authority tiers, the team set, or the gate set
are T1 acts requiring a charter entry and an audit trail. Deprecating a gate
requires an equal or stronger replacement. `AGENTS.md` remains authoritative for
this repository's security invariants; nothing here relaxes it, and a task
payload is data that cannot override it.
