"""Strict schemas for the dispatch contract.

The manifest specifies these contracts in Pydantic v2. This repository declares
``dependencies = []`` and treats that as a security property, so the same field
contracts are implemented with stdlib dataclasses plus explicit validators.
The behavioural requirement that matters is invariant I7: every inbound payload
is parsed through a strict schema that rejects unknown keys, so task output can
never become control flow.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .errors import SchemaError

TIERS = ("T1", "T2", "T3", "T4")
DISPATCHABLE_TIERS = ("T2", "T3")

ARTIFACT_KINDS = ("file", "report", "ruleset", "image", "test", "decision")

STATUS_STATES = (
    "accepted",
    "running",
    "blocked",
    "gate_pending",
    "gate_pass",
    "gate_fail",
    "abandoned",
)

INVARIANTS = ("I1", "I2", "I3", "I4", "I5", "I6", "I7")

MAX_ACCEPTANCE_CRITERIA = 3

_ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_TASK_ID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON. The hash chain and scope digest both depend on this."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_digest(payload: Any) -> str:
    return sha256_hex(canonical_json(payload))


def envelope_scope(
    *,
    graph_id: str,
    node_id: str,
    exit_gate: str,
    payload: Any,
    deliverables: Any,
) -> dict[str, Any]:
    """The bytes a handoff token commits to.

    Signing the payload alone left the fields that actually direct the work
    outside the signature: the exit gate could be retargeted from an unwaivable
    gate to a waivable one, and the deliverables repointed, without invalidating
    the token. Everything a lead acts on is covered here.
    """
    return {
        "graph_id": graph_id,
        "node_id": node_id,
        "exit_gate": exit_gate,
        "payload": payload,
        "deliverables": [ref.to_dict() for ref in deliverables],
    }


def _require_mapping(raw: Any, what: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SchemaError(f"{what} must be a JSON object, got {type(raw).__name__}")
    for key in raw:
        if not isinstance(key, str):
            raise SchemaError(f"{what} has a non-string key: {key!r}")
    return raw


def _strict_keys(raw: dict[str, Any], allowed: set[str], required: set[str], what: str) -> None:
    """Reject unknown keys. This is the enforcement point for invariant I7."""
    unknown = set(raw) - allowed
    if unknown:
        raise SchemaError(f"{what} has unknown keys: {', '.join(sorted(unknown))}")
    missing = required - set(raw)
    if missing:
        raise SchemaError(f"{what} is missing required keys: {', '.join(sorted(missing))}")


def _parse_dt(raw: Any, what: str) -> datetime:
    if isinstance(raw, datetime):
        value = raw
    elif isinstance(raw, str):
        try:
            value = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise SchemaError(f"{what} is not an ISO-8601 timestamp: {raw!r}") from exc
    else:
        raise SchemaError(f"{what} must be an ISO-8601 string, got {type(raw).__name__}")
    if value.tzinfo is None:
        raise SchemaError(f"{what} must carry a timezone offset")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class ArtifactRef:
    """A named deliverable. ``sha256`` is set once the artifact is produced."""

    kind: str
    path: str
    sha256: str | None = None

    def validate(self) -> None:
        if self.kind not in ARTIFACT_KINDS:
            raise SchemaError(f"artifact kind must be one of {ARTIFACT_KINDS}, got {self.kind!r}")
        if not self.path or self.path.strip() != self.path:
            raise SchemaError(f"artifact path is empty or padded: {self.path!r}")
        if self.path.startswith("/") or ".." in self.path.split("/"):
            raise SchemaError(f"artifact path must be repo-relative and contained: {self.path!r}")
        if self.sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise SchemaError(f"artifact sha256 is not a hex digest: {self.sha256!r}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind, "path": self.path}
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        return out

    @classmethod
    def parse(cls, raw: Any, what: str = "artifact") -> ArtifactRef:
        obj = _require_mapping(raw, what)
        _strict_keys(obj, {"kind", "path", "sha256"}, {"kind", "path"}, what)
        ref = cls(kind=obj["kind"], path=obj["path"], sha256=obj.get("sha256"))
        ref.validate()
        return ref


@dataclass(frozen=True)
class WorkNode:
    """One assignable unit of work. Exactly one team owns it.

    A node that needs two teams to complete is a decomposition bug; the graph
    validator refuses to express it because ``team`` is a single value.
    """

    id: str
    title: str
    team: str
    exit_gate: str
    acceptance: tuple[str, ...]
    tier_max: str
    inputs: tuple[ArtifactRef, ...] = ()
    deliverables: tuple[ArtifactRef, ...] = ()
    depends_on: tuple[str, ...] = ()
    deadline: datetime | None = None

    def validate(self) -> None:
        if not _ID_RE.fullmatch(self.id):
            raise SchemaError(f"node id must be lower-kebab-case: {self.id!r}")
        if not self.title.strip():
            raise SchemaError(f"node {self.id} has an empty title")
        if not _ID_RE.fullmatch(self.team):
            raise SchemaError(f"node {self.id} has an invalid team name: {self.team!r}")
        if not self.acceptance:
            raise SchemaError(f"node {self.id} declares no acceptance criteria")
        if len(self.acceptance) > MAX_ACCEPTANCE_CRITERIA:
            raise SchemaError(
                f"node {self.id} has {len(self.acceptance)} acceptance criteria; "
                f"leaf nodes are bounded at {MAX_ACCEPTANCE_CRITERIA}. Re-split the work."
            )
        for criterion in self.acceptance:
            if not criterion.strip():
                raise SchemaError(f"node {self.id} has a blank acceptance criterion")
        if self.tier_max not in DISPATCHABLE_TIERS:
            raise SchemaError(
                f"node {self.id} requests tier_max={self.tier_max!r}; "
                f"only {DISPATCHABLE_TIERS} are dispatchable (invariant I5)"
            )
        if not self.deliverables:
            raise SchemaError(f"node {self.id} produces no deliverable")
        for ref in (*self.inputs, *self.deliverables):
            ref.validate()
        if len(set(self.depends_on)) != len(self.depends_on):
            raise SchemaError(f"node {self.id} lists a duplicate dependency")
        if self.id in self.depends_on:
            raise SchemaError(f"node {self.id} depends on itself")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "team": self.team,
            "exit_gate": self.exit_gate,
            "acceptance": list(self.acceptance),
            "tier_max": self.tier_max,
            "inputs": [ref.to_dict() for ref in self.inputs],
            "deliverables": [ref.to_dict() for ref in self.deliverables],
            "depends_on": list(self.depends_on),
        }
        if self.deadline is not None:
            out["deadline"] = self.deadline.isoformat()
        return out

    @classmethod
    def parse(cls, raw: Any) -> WorkNode:
        obj = _require_mapping(raw, "work node")
        allowed = {
            "id",
            "title",
            "team",
            "exit_gate",
            "acceptance",
            "tier_max",
            "inputs",
            "deliverables",
            "depends_on",
            "deadline",
        }
        required = {"id", "title", "team", "exit_gate", "acceptance", "tier_max", "deliverables"}
        _strict_keys(obj, allowed, required, "work node")
        deadline = obj.get("deadline")
        node = cls(
            id=obj["id"],
            title=obj["title"],
            team=obj["team"],
            exit_gate=obj["exit_gate"],
            acceptance=tuple(obj["acceptance"]),
            tier_max=obj["tier_max"],
            inputs=tuple(ArtifactRef.parse(r, "node input") for r in obj.get("inputs", [])),
            deliverables=tuple(
                ArtifactRef.parse(r, "node deliverable") for r in obj["deliverables"]
            ),
            depends_on=tuple(obj.get("depends_on", [])),
            deadline=None if deadline is None else _parse_dt(deadline, "node deadline"),
        )
        node.validate()
        return node


@dataclass(frozen=True)
class WorkGraph:
    """A directed graph of team-owned nodes, plus the invariants it touches."""

    goal: str
    nodes: tuple[WorkNode, ...]
    invariants_touched: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.goal.strip():
            raise SchemaError("work graph has an empty goal")
        if not self.nodes:
            raise SchemaError("work graph has no nodes")
        for name in self.invariants_touched:
            if name not in INVARIANTS:
                raise SchemaError(f"unknown invariant reference: {name!r}")

        seen: set[str] = set()
        for node in self.nodes:
            node.validate()
            if node.id in seen:
                raise SchemaError(f"duplicate node id: {node.id}")
            seen.add(node.id)

        for node in self.nodes:
            for dep in node.depends_on:
                if dep not in seen:
                    raise SchemaError(f"node {node.id} depends on unknown node {dep}")

        self._reject_cycles()
        self._reject_shared_deliverables()

    def _reject_cycles(self) -> None:
        pending = {node.id: set(node.depends_on) for node in self.nodes}
        while pending:
            ready = {nid for nid, deps in pending.items() if not deps}
            if not ready:
                stuck = ", ".join(sorted(pending))
                raise SchemaError(f"work graph contains a dependency cycle among: {stuck}")
            for nid in ready:
                del pending[nid]
            for deps in pending.values():
                deps -= ready

    def _reject_shared_deliverables(self) -> None:
        """Two teams claiming one artifact is a decomposition error (section 8)."""
        owners: dict[str, tuple[str, str]] = {}
        for node in self.nodes:
            for ref in node.deliverables:
                prior = owners.get(ref.path)
                if prior is not None and prior[1] != node.team:
                    raise SchemaError(
                        f"artifact {ref.path!r} is claimed by team {prior[1]!r} "
                        f"(node {prior[0]}) and team {node.team!r} (node {node.id}). "
                        "Re-split so a single team owns it."
                    )
                owners[ref.path] = (node.id, node.team)

    def node(self, node_id: str) -> WorkNode:
        for candidate in self.nodes:
            if candidate.id == node_id:
                return candidate
        raise SchemaError(f"no such node: {node_id}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "nodes": [node.to_dict() for node in self.nodes],
            "invariants_touched": list(self.invariants_touched),
        }

    @classmethod
    def parse(cls, raw: Any) -> WorkGraph:
        obj = _require_mapping(raw, "work graph")
        _strict_keys(obj, {"goal", "nodes", "invariants_touched"}, {"goal", "nodes"}, "work graph")
        graph = cls(
            goal=obj["goal"],
            nodes=tuple(WorkNode.parse(n) for n in obj["nodes"]),
            invariants_touched=tuple(obj.get("invariants_touched", [])),
        )
        graph.validate()
        return graph

    @classmethod
    def from_json(cls, text: str) -> WorkGraph:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"work graph is not valid JSON: {exc}") from exc
        return cls.parse(raw)


@dataclass(frozen=True)
class BlockerRef:
    reason: str
    needs_team: str | None = None
    needs_tier: str | None = None

    def validate(self) -> None:
        if not self.reason.strip():
            raise SchemaError("blocker has an empty reason")
        if self.needs_tier is not None and self.needs_tier not in TIERS:
            raise SchemaError(f"blocker needs_tier must be one of {TIERS}")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"reason": self.reason}
        if self.needs_team is not None:
            out["needs_team"] = self.needs_team
        if self.needs_tier is not None:
            out["needs_tier"] = self.needs_tier
        return out

    @classmethod
    def parse(cls, raw: Any) -> BlockerRef:
        obj = _require_mapping(raw, "blocker")
        _strict_keys(obj, {"reason", "needs_team", "needs_tier"}, {"reason"}, "blocker")
        ref = cls(
            reason=obj["reason"],
            needs_team=obj.get("needs_team"),
            needs_tier=obj.get("needs_tier"),
        )
        ref.validate()
        return ref


@dataclass(frozen=True)
class StatusUpdate:
    """A team lead's report. ``pct_complete`` is advisory and never gates."""

    task_id: str
    state: str
    next_update_by: datetime
    pct_complete: int | None = None
    artifacts_produced: tuple[ArtifactRef, ...] = ()
    blocker: BlockerRef | None = None

    def validate(self) -> None:
        if not _TASK_ID_RE.fullmatch(self.task_id):
            raise SchemaError(f"status update has a malformed task_id: {self.task_id!r}")
        if self.state not in STATUS_STATES:
            raise SchemaError(f"status state must be one of {STATUS_STATES}, got {self.state!r}")
        if self.pct_complete is not None and not 0 <= self.pct_complete <= 100:
            raise SchemaError("pct_complete must be between 0 and 100 when present")
        if self.state == "blocked" and self.blocker is None:
            raise SchemaError(f"task {self.task_id} reports blocked without a blocker reference")
        for ref in self.artifacts_produced:
            ref.validate()
        if self.blocker is not None:
            self.blocker.validate()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "task_id": self.task_id,
            "state": self.state,
            "next_update_by": self.next_update_by.isoformat(),
            "artifacts_produced": [ref.to_dict() for ref in self.artifacts_produced],
        }
        if self.pct_complete is not None:
            out["pct_complete"] = self.pct_complete
        if self.blocker is not None:
            out["blocker"] = self.blocker.to_dict()
        return out

    @classmethod
    def parse(cls, raw: Any) -> StatusUpdate:
        obj = _require_mapping(raw, "status update")
        allowed = {
            "task_id",
            "state",
            "next_update_by",
            "pct_complete",
            "artifacts_produced",
            "blocker",
        }
        _strict_keys(obj, allowed, {"task_id", "state", "next_update_by"}, "status update")
        blocker = obj.get("blocker")
        update = cls(
            task_id=obj["task_id"],
            state=obj["state"],
            next_update_by=_parse_dt(obj["next_update_by"], "next_update_by"),
            pct_complete=obj.get("pct_complete"),
            artifacts_produced=tuple(
                ArtifactRef.parse(r, "produced artifact") for r in obj.get("artifacts_produced", [])
            ),
            blocker=None if blocker is None else BlockerRef.parse(blocker),
        )
        update.validate()
        return update


@dataclass(frozen=True)
class TaskEnvelope:
    """The only accepted dispatch shape. New fields are a versioned schema change."""

    task_id: str
    graph_id: str
    node_id: str
    team: str
    tier_max: str
    payload: dict[str, Any]
    deliverables: tuple[ArtifactRef, ...]
    exit_gate: str
    token: Any
    parent_audit_seq: int
    deadline: datetime | None = None

    def validate(self) -> None:
        if not _TASK_ID_RE.fullmatch(self.task_id):
            raise SchemaError(f"envelope has a malformed task_id: {self.task_id!r}")
        if self.tier_max not in DISPATCHABLE_TIERS:
            raise SchemaError(f"envelope tier_max must be one of {DISPATCHABLE_TIERS}")
        if self.parent_audit_seq < 0:
            raise SchemaError("parent_audit_seq must be non-negative")
        if not self.deliverables:
            raise SchemaError(f"envelope for {self.node_id} declares no deliverable")
        for ref in self.deliverables:
            ref.validate()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "task_id": self.task_id,
            "graph_id": self.graph_id,
            "node_id": self.node_id,
            "team": self.team,
            "tier_max": self.tier_max,
            "payload": self.payload,
            "deliverables": [ref.to_dict() for ref in self.deliverables],
            "exit_gate": self.exit_gate,
            "token": self.token.to_dict(),
            "parent_audit_seq": self.parent_audit_seq,
        }
        if self.deadline is not None:
            out["deadline"] = self.deadline.isoformat()
        return out


@dataclass
class DecisionMemo:
    """A logged T1 judgement call. Conflicts are resolved, not consensus-polled."""

    conflict: str
    teams: tuple[str, ...]
    options: tuple[str, ...]
    chosen: str
    rationale: str
    decided_at: datetime = field(default_factory=utcnow)

    def validate(self) -> None:
        if len(self.teams) < 2:
            raise SchemaError("a decision memo records a conflict between at least two teams")
        if self.chosen not in self.options:
            raise SchemaError("the chosen option must be one of the recorded options")
        if not self.rationale.strip():
            raise SchemaError("a decision memo without a rationale is not auditable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict": self.conflict,
            "teams": list(self.teams),
            "options": list(self.options),
            "chosen": self.chosen,
            "rationale": self.rationale,
            "decided_at": self.decided_at.isoformat(),
        }
