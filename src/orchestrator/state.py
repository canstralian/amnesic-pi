"""Cold start: replay the log, verify integrity, then leave READ_ONLY.

Section 10 of the manifest: the orchestrator accepts no dispatch until the
audit chain is verified, the topology is loaded, key material is fresh, the
mirror is reachable and undiverged, and open nodes are reconciled with live
team state. If any step fails it stays in READ_ONLY and an operator is paged.

Invariant I6 is why this exists at all: in-memory state is advisory, so the
only trustworthy way to know what is in flight is to replay the log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .dispatch import Dispatcher
from .errors import AuditChainError, OrchestratorError
from .gates import GATES_BY_NAME
from .tokens import KeyRing
from .topology import Topology


@dataclass
class ReplayState:
    """A projection of the audit log. Never a source of truth on its own."""

    entries: int = 0
    dispatched: dict[str, dict[str, Any]] = field(default_factory=dict)
    gate_results: dict[str, bool] = field(default_factory=dict)
    reclaimed: set[str] = field(default_factory=set)
    paused_teams: set[str] = field(default_factory=set)
    decisions: int = 0

    def open_tasks(self) -> dict[str, dict[str, Any]]:
        return {
            task_id: meta
            for task_id, meta in self.dispatched.items()
            if task_id not in self.reclaimed and not self.gate_results.get(task_id, False)
        }


def replay(audit: AuditLog) -> ReplayState:
    """Reconstruct orchestrator state from the log, verifying the chain first."""
    state = ReplayState(entries=audit.verify_chain())
    for entry in audit.entries():
        fields = entry.fields
        task_id = fields.get("task_id")
        if entry.event == "dispatch" and task_id:
            state.dispatched[task_id] = {
                "team": fields.get("team"),
                "node_id": fields.get("node_id"),
                "graph_id": fields.get("graph_id"),
                "exit_gate": fields.get("exit_gate"),
                "tier_max": fields.get("tier_max"),
                "deliverables": fields.get("deliverables"),
                "seq": entry.seq,
            }
        elif entry.event == "gate_result" and task_id:
            state.gate_results[task_id] = bool(fields.get("passed"))
        elif entry.event == "reclaim" and task_id:
            state.reclaimed.add(task_id)
        elif entry.event == "team_paused":
            state.paused_teams.add(str(fields.get("team")))
        elif entry.event == "team_resumed":
            state.paused_teams.discard(str(fields.get("team")))
        elif entry.event == "decision_memo":
            state.decisions += 1
    return state


@dataclass
class ColdStartReport:
    ok: bool
    steps: tuple[tuple[str, bool, str], ...]
    state: ReplayState | None = None

    def render(self) -> str:
        width = max(len(name) for name, _, _ in self.steps)
        lines = []
        for name, passed, detail in self.steps:
            lines.append(f"{'PASS' if passed else 'FAIL':4}  {name:<{width}}  {detail}")
        verdict = "ready for dispatch" if self.ok else "READ_ONLY — operator required"
        lines.append(f"\ncold start: {verdict}")
        return "\n".join(lines)


def cold_start(
    *,
    manifest: Path | None = None,
    audit_path: Path,
    mirror_path: Path | None = None,
    keyring: KeyRing | None = None,
) -> tuple[Dispatcher | None, ColdStartReport]:
    """Run the five cold-start checks in order. Returns a dispatcher only if all pass."""
    steps: list[tuple[str, bool, str]] = []
    audit = AuditLog(audit_path, mirror_path)

    try:
        topology = Topology.load(manifest)
        steps.append(("topology manifest", True, f"{len(topology.teams)} teams, charters present"))
    except OrchestratorError as exc:
        steps.append(("topology manifest", False, str(exc)))
        return None, ColdStartReport(ok=False, steps=tuple(steps))

    try:
        state = replay(audit)
        steps.append(("audit chain", True, f"{state.entries} entries, chain intact"))
    except AuditChainError as exc:
        steps.append(("audit chain", False, f"SEV-2: {exc}"))
        return None, ColdStartReport(ok=False, steps=tuple(steps))

    if mirror_path is None:
        # Section 10 requires a reachable mirror. A hash chain cannot bind its
        # own tail, so without a second sink the most recent entry is
        # unverifiable — reporting FAIL here and opening anyway was the bug.
        steps.append(
            (
                "audit mirror",
                False,
                "no mirror configured; the tail of the chain cannot be verified",
            )
        )
        return None, ColdStartReport(ok=False, steps=tuple(steps), state=state)
    try:
        audit.check_mirror()
        steps.append(("audit mirror", True, "sinks agree"))
    except OrchestratorError as exc:
        steps.append(("audit mirror", False, f"SEV-1: {exc}"))
        return None, ColdStartReport(ok=False, steps=tuple(steps), state=state)

    keys = keyring or KeyRing()
    try:
        keys.current()
        steps.append(("key material", True, "fresh, rotation timer armed"))
    except OrchestratorError as exc:
        steps.append(("key material", False, str(exc)))
        return None, ColdStartReport(ok=False, steps=tuple(steps), state=state)

    open_tasks = state.open_tasks()
    unknown_teams = sorted(
        {
            str(meta["team"])
            for meta in open_tasks.values()
            if meta["team"] not in {team.name for team in topology.teams}
        }
    )
    unknown_gates = sorted(
        {
            str(meta["exit_gate"])
            for meta in open_tasks.values()
            if meta["exit_gate"] not in GATES_BY_NAME
        }
    )
    if unknown_teams or unknown_gates:
        detail = (
            f"open tasks reference teams {unknown_teams} and gates {unknown_gates} "
            "that this topology does not declare"
        )
        steps.append(("node reconciliation", False, detail))
        return None, ColdStartReport(ok=False, steps=tuple(steps), state=state)
    dispatcher = Dispatcher(topology, keys, audit, read_only=True)
    restored = dispatcher.restore_from(state)
    detail = f"{len(open_tasks)} open tasks, {restored} task records restored"
    if restored < len(open_tasks):
        detail += f" ({len(open_tasks) - restored} pre-date deliverable logging)"
    steps.append(("node reconciliation", True, detail))

    for team in sorted(state.paused_teams):
        dispatcher.pause_team(team, reason="restored from audit replay")
    dispatcher.open_for_dispatch()
    audit.append("orchestrator", "cold_start", entries_replayed=state.entries)
    report = ColdStartReport(ok=all(passed for _, passed, _ in steps), steps=tuple(steps), state=state)
    if not report.ok:
        return None, report
    return dispatcher, report
