"""Orchestration control plane: a router, gatekeeper, and auditor.

The orchestrator owns nothing downstream of its own dispatch contract. It does
not write code, run tests, or make trade-offs inside a team's domain. If it
finds itself doing any of those, the decomposition failed and the work is
re-split rather than absorbed.

Entry points:

    Topology.load()   read and validate the team manifest
    cold_start()      section 10 boot sequence; returns a Dispatcher or None
    Dispatcher        sign, route, audit, and gate work
"""

from __future__ import annotations

from .audit import AuditEntry, AuditLog
from .dispatch import Dispatcher, TaskRecord
from .errors import (
    AuditChainError,
    AuditDivergenceError,
    AuthorityError,
    DispatchRejected,
    OrchestratorError,
    PolicyBreach,
    ReadOnlyMode,
    ReplayError,
    SchemaError,
    TokenError,
    TopologyError,
)
from .gates import GATES, GATES_BY_NAME, UNWAIVABLE, Gate, GateResult, waive
from .schema import ArtifactRef, DecisionMemo, StatusUpdate, TaskEnvelope, WorkGraph, WorkNode
from .state import ColdStartReport, ReplayState, cold_start, replay
from .tokens import HandoffToken, KeyRing, ReplayLedger, new_task_id
from .topology import Team, Topology

__all__ = [
    "GATES",
    "GATES_BY_NAME",
    "UNWAIVABLE",
    "ArtifactRef",
    "AuditChainError",
    "AuditDivergenceError",
    "AuditEntry",
    "AuditLog",
    "AuthorityError",
    "ColdStartReport",
    "DecisionMemo",
    "DispatchRejected",
    "Dispatcher",
    "Gate",
    "GateResult",
    "HandoffToken",
    "KeyRing",
    "OrchestratorError",
    "PolicyBreach",
    "ReadOnlyMode",
    "ReplayError",
    "ReplayLedger",
    "ReplayState",
    "SchemaError",
    "StatusUpdate",
    "TaskEnvelope",
    "TaskRecord",
    "Team",
    "TokenError",
    "Topology",
    "TopologyError",
    "WorkGraph",
    "WorkNode",
    "cold_start",
    "new_task_id",
    "replay",
    "waive",
]
