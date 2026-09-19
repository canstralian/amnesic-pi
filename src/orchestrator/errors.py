"""Error hierarchy for the orchestration control plane.

Every error here is a refusal, not a warning. The orchestrator has no soft
failure mode: a rejected dispatch, an unverifiable token, or a broken audit
chain halts the operation rather than degrading it.
"""

from __future__ import annotations


class OrchestratorError(Exception):
    """Base class for every control-plane refusal."""


class SchemaError(OrchestratorError, ValueError):
    """A payload did not parse under its strict schema (invariant I7)."""


class TokenError(OrchestratorError):
    """A handoff token was absent, expired, out of scope, or tampered with."""


class ReplayError(TokenError):
    """A single-use token was presented twice."""


class AuditChainError(OrchestratorError):
    """The append-only log is not a valid hash chain (invariant I4). SEV-2."""


class AuditDivergenceError(AuditChainError):
    """Primary and mirror audit sinks disagree (invariant I4). SEV-1."""


class DispatchRejected(OrchestratorError):
    """The dispatch contract refused a task before it reached a team."""


class AuthorityError(DispatchRejected):
    """A task requested authority above its permitted tier (invariant I5)."""


class TopologyError(OrchestratorError):
    """The topology manifest is missing a charter, a gate owner, or a lead."""


class PolicyBreach(OrchestratorError):
    """An unwaivable gate was waived. Triggers incident response (I3)."""


class ReadOnlyMode(OrchestratorError):
    """Cold start did not complete; no new dispatch is permitted (section 10)."""
