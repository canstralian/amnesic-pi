"""Validation gates. Boolean, owned, and never advisory.

Invariant I3: no merge, ship, or release action proceeds without a passing
gate. A gate returns ``True`` or ``False``. There is no partial credit, and
``pct_complete`` is explicitly not an input, because a metric that can be
gamed is not a gate.

The manifest's seven gates are defined for AI/ML delivery. This repository
ships a fail-closed network appliance, so each gate is mapped to the equivalent
or stronger validation in this domain. The mapping is recorded here and in
docs/orchestration.md; section 11 forbids a net loss of validation, so the
count and the ownership structure are preserved exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .errors import PolicyBreach, SchemaError
from .schema import utcnow


@dataclass(frozen=True)
class Gate:
    """A named validation owned by exactly one team."""

    name: str
    owner_team: str
    passes_when: str
    upstream: str
    waivable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "owner_team": self.owner_team,
            "passes_when": self.passes_when,
            "upstream": self.upstream,
            "waivable": self.waivable,
        }


#: The seven gates, mapped from the manifest's canonical set onto this repo's
#: security boundary. ``upstream`` names the manifest gate each one replaces.
GATES: tuple[Gate, ...] = (
    Gate(
        name="SPEC_COMPLETE",
        owner_team="docs",
        upstream="SPEC_COMPLETE",
        passes_when=(
            "the authority being added or changed is stated, the threat-model delta is "
            "written, and a rollback path exists"
        ),
    ),
    Gate(
        name="POLICY_CLEAN",
        owner_team="policy",
        upstream="DATA_CLEAN",
        passes_when=(
            "nft -c accepts the rendered ruleset, input/forward/output remain default DROP, "
            "no IPv6 path exists, and every egress principal is explicit and documented"
        ),
    ),
    Gate(
        name="RUNTIME_SOUND",
        owner_team="runtime",
        upstream="TRAIN_CONVERGED",
        passes_when=(
            "ruff and pytest pass, no shell interpolation is unquoted, and a config parse "
            "failure provably leaves a known-good ruleset installed"
        ),
    ),
    Gate(
        name="VERIFY_PASS",
        owner_team="verification",
        upstream="EVAL_PASS",
        passes_when=(
            "DNS, UDP/QUIC, and IPv6 leak tests fail closed from a downstream client and "
            "no regression test has been skipped or weakened"
        ),
    ),
    Gate(
        name="FAIL_CLOSED_PASS",
        owner_team="verification",
        upstream="SAFETY_PASS",
        waivable=False,
        passes_when=(
            "stopping or crashing Tor removes downstream connectivity rather than exposing "
            "clearnet, confirmed on target hardware from a real client"
        ),
    ),
    Gate(
        name="PLATFORM_READY",
        owner_team="platform",
        upstream="INFRA_READY",
        passes_when=(
            "provisioning is reproducible on Raspberry Pi OS Lite ARM64, OverlayFS amnesia "
            "is confirmed across reboot, and the maintenance-mode transition is tested"
        ),
    ),
    Gate(
        name="RELEASE_SIGNED",
        owner_team="release",
        upstream="RELEASE_SIGNED",
        passes_when=(
            "every item in the README release gate passed on target hardware and a "
            "pre-registered rollback class is recorded"
        ),
    ),
)

GATES_BY_NAME: dict[str, Gate] = {gate.name: gate for gate in GATES}

#: Unwaivable under all circumstances. Waiving this is a T1 policy breach.
UNWAIVABLE = tuple(gate.name for gate in GATES if not gate.waivable)


def gate(name: str) -> Gate:
    try:
        return GATES_BY_NAME[name]
    except KeyError as exc:
        known = ", ".join(sorted(GATES_BY_NAME))
        raise SchemaError(f"unknown gate {name!r}; known gates are: {known}") from exc


@dataclass(frozen=True)
class GateResult:
    """The outcome of one gate evaluation. ``passed`` is a hard boolean."""

    gate: str
    passed: bool
    evidence: tuple[str, ...]
    checked_by: str
    checked_at: datetime = field(default_factory=utcnow)

    def validate(self) -> None:
        resolved = gate(self.gate)
        if type(self.passed) is not bool:
            raise SchemaError(
                f"gate {self.gate} returned {self.passed!r} of type "
                f"{type(self.passed).__name__}; a gate result is a hard boolean. "
                "Soft-pass is a bug."
            )
        if not self.evidence:
            raise SchemaError(f"gate {self.gate} returned no evidence; an unevidenced pass is not a pass")
        if self.checked_by != resolved.owner_team:
            raise SchemaError(
                f"gate {self.gate} is owned by team {resolved.owner_team!r} "
                f"but was checked by {self.checked_by!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "passed": self.passed,
            "evidence": list(self.evidence),
            "checked_by": self.checked_by,
            "checked_at": self.checked_at.isoformat(),
        }

    @classmethod
    def parse(cls, raw: Any) -> GateResult:
        if not isinstance(raw, dict):
            raise SchemaError("gate result must be a JSON object")
        allowed = {"gate", "passed", "evidence", "checked_by", "checked_at"}
        unknown = set(raw) - allowed
        if unknown:
            raise SchemaError(f"gate result has unknown keys: {', '.join(sorted(unknown))}")
        missing = {"gate", "passed", "evidence", "checked_by"} - set(raw)
        if missing:
            raise SchemaError(f"gate result is missing keys: {', '.join(sorted(missing))}")
        evidence = raw["evidence"]
        # A bare string is iterable, so tuple() used to split "looks fine" into
        # ten characters, which then satisfied the non-empty evidence rule.
        if isinstance(evidence, str) or not isinstance(evidence, (list, tuple)):
            raise SchemaError(
                f"gate {raw['gate']} evidence must be a list of strings, got "
                f"{type(evidence).__name__}"
            )
        if not all(isinstance(item, str) for item in evidence):
            raise SchemaError(f"gate {raw['gate']} evidence must be a list of strings")

        checked_at = raw.get("checked_at")
        if checked_at is None:
            parsed_at = utcnow()
        else:
            try:
                parsed_at = datetime.fromisoformat(checked_at)
            except (TypeError, ValueError) as exc:
                raise SchemaError(
                    f"gate {raw['gate']} checked_at is not an ISO-8601 timestamp: "
                    f"{checked_at!r}"
                ) from exc

        result = cls(
            gate=raw["gate"],
            passed=raw["passed"],
            evidence=tuple(evidence),
            checked_by=raw["checked_by"],
            checked_at=parsed_at,
        )
        result.validate()
        return result


def waive(gate_name: str, *, approver: str, rationale: str) -> dict[str, Any]:
    """Record a gate waiver, or refuse when the gate is unwaivable.

    ``FAIL_CLOSED_PASS`` is the analogue of the manifest's ``SAFETY_PASS`` and
    carries the same rule: never waived, no exceptions, not once. Calling this
    on it raises rather than returning a waiver record.
    """
    resolved = gate(gate_name)
    if not resolved.waivable:
        raise PolicyBreach(
            f"gate {gate_name} is unwaivable. Shipping without it is a T1 policy breach "
            "and triggers incident response, not a waiver record."
        )
    if not rationale.strip():
        raise SchemaError("a waiver without a rationale is not auditable")
    return {
        "gate": gate_name,
        "waived_by": approver,
        "rationale": rationale,
        "waived_at": utcnow().isoformat(),
    }
