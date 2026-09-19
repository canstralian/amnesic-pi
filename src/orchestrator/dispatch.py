"""The dispatch contract. This is where the invariants are actually enforced.

    plan -> sign(HMAC) -> enqueue(team_lead.inbox) -> await(status_stream)

One task, one owner. No round-robin, no broadcast. Dispatch is idempotent on
``task_id``, so a resubmitted token is a no-op rather than a duplicate job.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .audit import AuditEntry, AuditLog
from .errors import AuthorityError, DispatchRejected, PolicyBreach, ReadOnlyMode
from .gates import GateResult, gate
from .schema import (
    DISPATCHABLE_TIERS,
    ArtifactRef,
    DecisionMemo,
    StatusUpdate,
    TaskEnvelope,
    WorkGraph,
    WorkNode,
    envelope_scope,
    payload_digest,
    utcnow,
)
from .tokens import DEFAULT_TTL, HandoffToken, KeyRing, ReplayLedger, new_task_id
from .topology import Topology

ACK_SLO = timedelta(seconds=60)
ACTIVE_CADENCE = timedelta(minutes=5)
IDLE_CADENCE = timedelta(hours=1)

ACTOR = "orchestrator"


@dataclass
class TaskRecord:
    """The orchestrator's view of one dispatched task.

    Advisory only. Invariant I6 makes the audit log authoritative, so this is
    reconstructed by replay on cold start rather than trusted across restarts.
    """

    envelope: TaskEnvelope
    state: str = "dispatched"
    ack_deadline: datetime | None = None
    next_update_by: datetime | None = None
    gate_result: GateResult | None = None
    superseded_by: str | None = None
    pct_complete: int | None = None
    history: list[str] = field(default_factory=list)

    @property
    def task_id(self) -> str:
        return self.envelope.task_id

    @property
    def team(self) -> str:
        return self.envelope.team

    def is_terminal(self) -> bool:
        return self.state in {"gate_pass", "abandoned"}


class Dispatcher:
    """T1 routing surface. Creates, signs, routes, and audits work.

    Refuses to build anything itself: there is no code path here that produces
    a deliverable. If the orchestrator would have to, the decomposition failed
    and the correct response is to re-split the graph.
    """

    def __init__(
        self,
        topology: Topology,
        keyring: KeyRing,
        audit: AuditLog,
        *,
        ack_slo: timedelta = ACK_SLO,
        clock: Any = utcnow,
        read_only: bool = True,
    ) -> None:
        self._topology = topology
        self._keys = keyring
        self._audit = audit
        self._ack_slo = ack_slo
        self._clock = clock
        self._read_only = read_only
        self._replay = ReplayLedger()
        self._tasks: dict[str, TaskRecord] = {}
        self._by_node: dict[tuple[str, str], str] = {}
        self._paused: set[str] = set()

    # ---- lifecycle -----------------------------------------------------

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def topology(self) -> Topology:
        return self._topology

    def open_for_dispatch(self) -> None:
        """Leave READ_ONLY. Only ``coldstart`` should call this."""
        self._read_only = False

    def _require_writable(self) -> None:
        if self._read_only:
            raise ReadOnlyMode(
                "orchestrator is in READ_ONLY mode; cold start has not completed. "
                "Status queries are served, no new dispatch is issued."
            )

    def pause_team(self, team: str, *, reason: str) -> AuditEntry:
        """Freeze dispatch to a team. Pause, never terminate (section 5.6)."""
        self._topology.team(team)
        self._paused.add(team)
        return self._audit.append(ACTOR, "team_paused", team=team, reason=reason)

    def resume_team(self, team: str) -> AuditEntry:
        self._topology.team(team)
        self._paused.discard(team)
        return self._audit.append(ACTOR, "team_resumed", team=team)

    def is_paused(self, team: str) -> bool:
        return team in self._paused

    # ---- dispatch ------------------------------------------------------

    def dispatch(
        self,
        node: WorkNode,
        *,
        graph_id: str,
        payload: dict[str, Any] | None = None,
        task_id: str | None = None,
        ttl: timedelta = DEFAULT_TTL,
    ) -> TaskEnvelope:
        """Sign and enqueue one node to its team lead.

        Idempotent twice over: on ``task_id``, and on ``(graph_id, node_id)`` so
        the same node cannot be dispatched to two owners.
        """
        self._require_writable()
        node.validate()

        if task_id is not None and task_id in self._tasks:
            return self._tasks[task_id].envelope

        existing = self._by_node.get((graph_id, node.id))
        if existing is not None:
            return self._tasks[existing].envelope

        team = self._topology.team(node.team)
        # Resolve the exit gate so an unknown one is refused before signing. The
        # gate need not be owned by this node's team: a team certifying its own
        # work is weaker than one team building and another gating it, and
        # GateResult already pins the result to the gate's owning team.
        exit_gate = gate(node.exit_gate)
        self._topology.team_for_gate(exit_gate.name)
        if team.name in self._paused:
            raise DispatchRejected(
                f"team {team.name!r} is paused; dispatch is frozen pending incident review"
            )
        if node.tier_max not in DISPATCHABLE_TIERS:
            raise AuthorityError(
                f"node {node.id} requests tier_max={node.tier_max!r}; the orchestrator "
                f"grants only {DISPATCHABLE_TIERS} (invariant I5)"
            )

        resolved_payload = dict(payload or {})
        resolved_payload.setdefault("node_id", node.id)
        resolved_payload.setdefault("acceptance", list(node.acceptance))

        tid = task_id or new_task_id()
        scope = envelope_scope(
            graph_id=graph_id,
            node_id=node.id,
            exit_gate=node.exit_gate,
            payload=resolved_payload,
            deliverables=node.deliverables,
        )
        token = self._keys.sign(
            task_id=tid,
            team=team.name,
            tier_max=node.tier_max,
            payload=scope,
            ttl=ttl,
        )
        envelope = TaskEnvelope(
            task_id=tid,
            graph_id=graph_id,
            node_id=node.id,
            team=team.name,
            tier_max=node.tier_max,
            payload=resolved_payload,
            deliverables=node.deliverables,
            exit_gate=node.exit_gate,
            token=token,
            parent_audit_seq=self._audit.next_seq(),
            deadline=node.deadline,
        )
        envelope.validate()

        entry = self._audit.append(
            ACTOR,
            "dispatch",
            task_id=tid,
            graph_id=graph_id,
            node_id=node.id,
            team=team.name,
            lead=team.lead,
            tier_max=node.tier_max,
            exit_gate=node.exit_gate,
            token_hash=f"sha256:{payload_digest(token.to_dict())}",
            payload_hash=f"sha256:{payload_digest(resolved_payload)}",
            deliverables=[ref.to_dict() for ref in node.deliverables],
        )
        now = self._clock()
        self._tasks[tid] = TaskRecord(
            envelope=envelope,
            ack_deadline=now + self._ack_slo,
            history=[f"seq={entry.seq} dispatched to {team.lead}"],
        )
        self._by_node[(graph_id, node.id)] = tid
        return envelope

    def dispatch_graph(
        self, graph: WorkGraph, *, graph_id: str, ready_only: bool = True
    ) -> list[TaskEnvelope]:
        """Dispatch every node whose dependencies are already satisfied.

        Dependencies are explicit edges, so readiness is computed rather than
        inferred from node order.
        """
        graph.validate()
        satisfied = {
            tid.envelope.node_id
            for tid in self._tasks.values()
            if tid.state == "gate_pass" and tid.envelope.graph_id == graph_id
        }
        out: list[TaskEnvelope] = []
        for node in graph.nodes:
            if ready_only and not set(node.depends_on) <= satisfied:
                continue
            out.append(self.dispatch(node, graph_id=graph_id))
        return out

    # ---- ingress -------------------------------------------------------

    def deliver(self, envelope: TaskEnvelope, *, to_agent: str) -> None:
        """Team lead ingress. Rejects unsigned, tampered, or mis-tiered tasks.

        Invariant I1 lives here: the only acceptable recipient is the team's
        declared lead. A sub-agent named as recipient is refused even when the
        token is otherwise valid, because reaching T3 directly would collapse
        the span of control.
        """
        team = self._topology.team(envelope.team)
        token = envelope.token
        if not isinstance(token, HandoffToken):
            raise AuthorityError(
                f"task {envelope.task_id} arrived without a handoff token; "
                "unsigned tasks are dropped at ingress (invariant I2)"
            )
        if to_agent != team.lead:
            if self._topology.is_subagent(to_agent):
                raise AuthorityError(
                    f"refusing to deliver task {envelope.task_id} directly to sub-agent "
                    f"{to_agent!r}. All work flows through team lead {team.lead!r} "
                    "(invariant I1)."
                )
            raise AuthorityError(
                f"{to_agent!r} is not the lead of team {team.name!r}; "
                f"its declared lead is {team.lead!r}"
            )
        if envelope.task_id != token.task_id:
            raise AuthorityError(
                f"envelope task_id {envelope.task_id} does not match the task_id its token "
                f"was signed for ({token.task_id}); refusing substituted envelope"
            )
        self._keys.verify(
            token,
            payload=envelope_scope(
                graph_id=envelope.graph_id,
                node_id=envelope.node_id,
                exit_gate=envelope.exit_gate,
                payload=envelope.payload,
                deliverables=envelope.deliverables,
            ),
            team=envelope.team,
            required_tier=envelope.tier_max,
        )
        self._replay.consume(token)
        self._audit.append(
            ACTOR,
            "ingress_accepted",
            task_id=envelope.task_id,
            team=team.name,
            lead=team.lead,
        )

    def ingest_status(self, raw: dict[str, Any]) -> StatusUpdate:
        """Parse a lead's report through the strict schema.

        Invariant I7: this is data. Nothing in the payload is executed, and
        ``pct_complete`` is recorded but never consulted for advancement.
        """
        update = StatusUpdate.parse(raw)
        record = self._tasks.get(update.task_id)
        if record is None:
            raise DispatchRejected(f"status update for unknown task {update.task_id}")
        if update.state == "gate_pass":
            raise DispatchRejected(
                f"task {update.task_id} cannot self-report gate_pass; a gate advances only "
                "through accept_gate with an evidenced result (invariant I3)"
            )

        record.state = update.state
        record.pct_complete = update.pct_complete
        record.next_update_by = update.next_update_by
        # Any report from the lead is an acknowledgement. Requiring the literal
        # state "accepted" left a lead whose first report was "running" flagged
        # stuck forever, and eligible for a reclaim of work actively in hand.
        record.ack_deadline = None
        self._audit.append(
            ACTOR,
            "status",
            task_id=update.task_id,
            team=record.team,
            state=update.state,
            payload_hash=f"sha256:{payload_digest(update.to_dict())}",
        )
        return update

    # ---- gates ---------------------------------------------------------

    def accept_gate(self, task_id: str, raw_result: dict[str, Any]) -> GateResult:
        """Record a gate outcome. Only a hard pass advances the task."""
        record = self._tasks.get(task_id)
        if record is None:
            raise DispatchRejected(f"gate result for unknown task {task_id}")
        result = GateResult.parse(raw_result)
        if result.gate != record.envelope.exit_gate:
            raise DispatchRejected(
                f"task {task_id} declares exit gate {record.envelope.exit_gate} "
                f"but was handed a {result.gate} result"
            )
        record.gate_result = result
        record.state = "gate_pass" if result.passed else "gate_fail"
        self._audit.append(
            ACTOR,
            "gate_result",
            task_id=task_id,
            team=record.team,
            gate=result.gate,
            passed=result.passed,
            evidence_hash=f"sha256:{payload_digest(list(result.evidence))}",
        )
        return result

    def live_record(self, graph_id: str, node_id: str) -> TaskRecord | None:
        """The task currently owning a node, following any reclaim chain."""
        task_id = self._by_node.get((graph_id, node_id))
        return self._tasks.get(task_id) if task_id is not None else None

    def may_ship(self, graph: WorkGraph, *, graph_id: str) -> bool:
        try:
            self.assert_shippable(graph, graph_id=graph_id)
        except PolicyBreach:
            return False
        return True

    def assert_shippable(self, graph: WorkGraph, *, graph_id: str) -> None:
        """Refuse to ship unless every node in the graph has a live passing gate.

        The graph is the subject, not the dispatch table. Checking only tasks
        that happen to have been dispatched meant a node still held on its
        dependency was invisible, so a graph could report shippable with its
        unwaivable gate never issued — a fail-open on invariant I3. Only the
        live record counts, so the abandoned half of a reclaim no longer blocks
        a graph whose replacement passed.
        """
        never_dispatched: list[str] = []
        ungated: list[str] = []
        for node in graph.nodes:
            record = self.live_record(graph_id, node.id)
            if record is None:
                never_dispatched.append(node.id)
            elif record.state != "gate_pass":
                ungated.append(node.id)

        if never_dispatched or ungated:
            parts = []
            if never_dispatched:
                parts.append(f"never dispatched: {', '.join(never_dispatched)}")
            if ungated:
                parts.append(f"no passing gate: {', '.join(ungated)}")
            raise PolicyBreach(
                f"graph {graph_id} is not shippable ({'; '.join(parts)}). "
                "Invariant I3: no ship action proceeds without a passing gate."
            )

    # ---- SLO and reclaim -----------------------------------------------

    def stuck_tasks(self, now: datetime | None = None) -> list[TaskRecord]:
        """Tasks past their ack SLO or past their promised next update."""
        moment = now or self._clock()
        out: list[TaskRecord] = []
        for record in self._tasks.values():
            if record.is_terminal() or record.superseded_by is not None:
                continue
            if record.ack_deadline is not None and moment > record.ack_deadline:
                out.append(record)
            elif record.next_update_by is not None and moment > record.next_update_by:
                out.append(record)
        return out

    def reclaim(self, task_id: str, *, reason: str, graph: WorkGraph) -> TaskEnvelope:
        """Reclaim a presumed-stuck task and reassign it under a fresh token.

        The original task is marked abandoned and linked to its replacement, so
        replay shows one owner at a time rather than two live claims.
        """
        self._require_writable()
        record = self._tasks.get(task_id)
        if record is None:
            raise DispatchRejected(f"cannot reclaim unknown task {task_id}")
        if record.state == "gate_pass":
            raise DispatchRejected(f"task {task_id} already passed its gate; nothing to reclaim")
        if record.superseded_by is not None:
            raise DispatchRejected(
                f"task {task_id} was already reclaimed; its work is owned by "
                f"{record.superseded_by}. Reclaim that task instead."
            )

        record.state = "abandoned"
        self._audit.append(
            ACTOR,
            "reclaim",
            task_id=task_id,
            team=record.team,
            reason=reason,
        )
        node = graph.node(record.envelope.node_id)
        del self._by_node[(record.envelope.graph_id, node.id)]
        replacement = self.dispatch(node, graph_id=record.envelope.graph_id)
        record.superseded_by = replacement.task_id
        return replacement

    # ---- conflict resolution -------------------------------------------

    def record_decision(self, memo: DecisionMemo) -> AuditEntry:
        """Log a T1 judgement call. Written down, then closed. No consensus rounds."""
        memo.validate()
        return self._audit.append(
            ACTOR,
            "decision_memo",
            teams=list(memo.teams),
            chosen=memo.chosen,
            payload_hash=f"sha256:{payload_digest(memo.to_dict())}",
        )

    # ---- restore -------------------------------------------------------

    def restore_from(self, state: Any) -> int:
        """Rebuild in-flight task records from a replayed audit log.

        Invariant I6 says state is derivable from the log. It was not: cold
        start replayed the log, used it for name checks, and threw it away, so
        a restart re-dispatched nodes that already had an owner and answered
        "unknown task" for anything issued before it.

        The log carries identity, not authority. A restored envelope has no
        token, so ``deliver`` refuses it and the work must be reclaimed and
        re-dispatched to reach a lead again. That is the fail-closed direction.
        """
        restored = 0
        for task_id, meta in state.dispatched.items():
            if task_id in self._tasks:
                continue
            raw_deliverables = meta.get("deliverables") or ()
            deliverables = tuple(
                ArtifactRef.parse(ref, "restored deliverable") for ref in raw_deliverables
            )
            if not deliverables:
                # Pre-dates deliverable logging; identity alone is not enough to
                # rebuild a usable record, so leave it out rather than fake one.
                continue
            envelope = TaskEnvelope(
                task_id=task_id,
                graph_id=str(meta["graph_id"]),
                node_id=str(meta["node_id"]),
                team=str(meta["team"]),
                tier_max=str(meta.get("tier_max") or "T3"),
                payload={},
                deliverables=deliverables,
                exit_gate=str(meta["exit_gate"]),
                token=None,
                parent_audit_seq=int(meta["seq"]),
            )
            passed = state.gate_results.get(task_id)
            if task_id in state.reclaimed:
                task_state = "abandoned"
            elif passed is True:
                task_state = "gate_pass"
            elif passed is False:
                task_state = "gate_fail"
            else:
                task_state = "dispatched"

            self._tasks[task_id] = TaskRecord(
                envelope=envelope,
                state=task_state,
                ack_deadline=None,
                history=[f"restored from audit seq={meta['seq']}"],
            )
            if task_state != "abandoned":
                self._by_node[(envelope.graph_id, envelope.node_id)] = task_id
            restored += 1
        return restored

    # ---- projection ----------------------------------------------------

    def task(self, task_id: str) -> TaskRecord:
        record = self._tasks.get(task_id)
        if record is None:
            raise DispatchRejected(f"unknown task {task_id}")
        return record

    def tasks(self) -> tuple[TaskRecord, ...]:
        return tuple(self._tasks.values())

    def queue_depth(self) -> dict[str, int]:
        depth = {team.name: 0 for team in self._topology.teams}
        for record in self._tasks.values():
            if not record.is_terminal() and record.superseded_by is None:
                depth[record.team] += 1
        return depth
