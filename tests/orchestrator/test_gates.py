"""Invariant I3: gates are hard booleans, owned, evidenced, and one is unwaivable."""

from __future__ import annotations

import pytest

from orchestrator.errors import PolicyBreach, SchemaError
from orchestrator.gates import GATES, GATES_BY_NAME, UNWAIVABLE, GateResult, gate, waive


def test_seven_gates_are_preserved_from_the_manifest():
    """Section 11 forbids a net loss of validation: seven in, seven out."""
    assert len(GATES) == 7
    upstream = {entry.upstream for entry in GATES}
    assert upstream == {
        "SPEC_COMPLETE",
        "DATA_CLEAN",
        "TRAIN_CONVERGED",
        "EVAL_PASS",
        "SAFETY_PASS",
        "INFRA_READY",
        "RELEASE_SIGNED",
    }


def test_the_safety_analogue_is_the_only_unwaivable_gate():
    assert UNWAIVABLE == ("FAIL_CLOSED_PASS",)
    assert GATES_BY_NAME["FAIL_CLOSED_PASS"].upstream == "SAFETY_PASS"


def test_unknown_gate_is_refused():
    with pytest.raises(SchemaError, match="unknown gate"):
        gate("SHIP_IT")


def test_a_passing_result_needs_evidence():
    with pytest.raises(SchemaError, match="unevidenced pass"):
        GateResult(gate="POLICY_CLEAN", passed=True, evidence=(), checked_by="policy").validate()


@pytest.mark.parametrize("truthy", [1, "true", 0.99, [1]])
def test_soft_pass_is_refused(truthy):
    """A gate result is a hard boolean. Anything merely truthy is a bug."""
    with pytest.raises(SchemaError, match="hard boolean"):
        GateResult(
            gate="POLICY_CLEAN", passed=truthy, evidence=("nft -c ok",), checked_by="policy"
        ).validate()


def test_only_the_owning_team_may_certify_a_gate():
    with pytest.raises(SchemaError, match="owned by team"):
        GateResult(
            gate="POLICY_CLEAN", passed=True, evidence=("looks fine",), checked_by="release"
        ).validate()


def test_percent_complete_is_not_a_gate_input():
    with pytest.raises(SchemaError, match="unknown keys"):
        GateResult.parse(
            {
                "gate": "POLICY_CLEAN",
                "passed": True,
                "evidence": ["nft -c ok"],
                "checked_by": "policy",
                "pct_complete": 100,
            }
        )


def test_waiving_the_unwaivable_gate_is_a_policy_breach():
    with pytest.raises(PolicyBreach, match="unwaivable"):
        waive("FAIL_CLOSED_PASS", approver="t1", rationale="shipping today")


def test_a_waivable_gate_records_a_rationale():
    record = waive("SPEC_COMPLETE", approver="t1", rationale="docs land in the follow-up PR")
    assert record["gate"] == "SPEC_COMPLETE"
    assert record["rationale"]


def test_a_waiver_without_a_rationale_is_refused():
    with pytest.raises(SchemaError, match="not auditable"):
        waive("SPEC_COMPLETE", approver="t1", rationale="   ")


def test_verification_owns_both_evaluation_gates():
    """Mirrors the manifest, where the Evals team owns EVAL_PASS and SAFETY_PASS."""
    owned = [entry.name for entry in GATES if entry.owner_team == "verification"]
    assert sorted(owned) == ["FAIL_CLOSED_PASS", "VERIFY_PASS"]
