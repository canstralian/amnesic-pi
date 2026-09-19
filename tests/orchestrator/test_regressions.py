"""Regression tests for defects found by review of the initial control plane.

Each test names the invariant it protects and fails against the code as first
written. They are grouped by the failure mode rather than by module, because
the two that matter most — a ship check that passes on work never dispatched,
and an ingress that accepts a retargeted gate — are both fail-open.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta
from pathlib import Path

import pytest

from orchestrator.audit import AuditLog
from orchestrator.errors import (
    AuditChainError,
    AuthorityError,
    DispatchRejected,
    PolicyBreach,
    SchemaError,
    TokenError,
)
from orchestrator.gates import GateResult
from orchestrator.schema import ArtifactRef, utcnow
from orchestrator.state import cold_start
from orchestrator.tokens import KeyRing, new_task_id


def _status(task_id: str, state: str, hours: int = 2) -> dict:
    return {
        "task_id": task_id,
        "state": state,
        "next_update_by": (utcnow() + timedelta(hours=hours)).isoformat(),
    }


# --- I3: a ship check must see the whole graph, not just what was dispatched ---


def test_ship_is_blocked_when_a_node_was_never_dispatched(dispatcher, make_node, make_graph):
    """The original check only looked at dispatched tasks, so a graph whose
    unwaivable gate node was still held on its dependency reported shippable.
    """
    upstream = make_node("spec", team="docs", exit_gate="SPEC_COMPLETE", path="docs/networking.md")
    downstream = make_node(
        "fail-closed",
        team="verification",
        exit_gate="FAIL_CLOSED_PASS",
        depends_on=("spec",),
        path="tests/test_firewall.py",
    )
    graph = make_graph(upstream, downstream)

    wave = dispatcher.dispatch_graph(graph, graph_id="G")
    assert [e.node_id for e in wave] == ["spec"]
    dispatcher.accept_gate(
        wave[0].task_id,
        {"gate": "SPEC_COMPLETE", "passed": True, "evidence": ["delta written"], "checked_by": "docs"},
    )

    assert not dispatcher.may_ship(graph, graph_id="G")
    with pytest.raises(PolicyBreach, match="never dispatched"):
        dispatcher.assert_shippable(graph, graph_id="G")


def test_ship_is_permitted_once_every_node_passes(dispatcher, make_node, make_graph):
    upstream = make_node("spec", team="docs", exit_gate="SPEC_COMPLETE", path="docs/networking.md")
    downstream = make_node("deny-quic", depends_on=("spec",))
    graph = make_graph(upstream, downstream)

    first = dispatcher.dispatch_graph(graph, graph_id="G")
    dispatcher.accept_gate(
        first[0].task_id,
        {"gate": "SPEC_COMPLETE", "passed": True, "evidence": ["ok"], "checked_by": "docs"},
    )
    second = dispatcher.dispatch_graph(graph, graph_id="G")
    tail = [e for e in second if e.node_id == "deny-quic"][0]
    dispatcher.accept_gate(
        tail.task_id,
        {"gate": "POLICY_CLEAN", "passed": True, "evidence": ["nft -c ok"], "checked_by": "policy"},
    )

    assert dispatcher.may_ship(graph, graph_id="G")
    dispatcher.assert_shippable(graph, graph_id="G")


def test_a_reclaimed_graph_can_still_ship(dispatcher, make_node, make_graph):
    """The abandoned record left by a reclaim must not block the graph forever."""
    node = make_node()
    graph = make_graph(node)
    original = dispatcher.dispatch(node, graph_id="G")
    replacement = dispatcher.reclaim(original.task_id, reason="ack SLO missed", graph=graph)
    dispatcher.accept_gate(
        replacement.task_id,
        {"gate": "POLICY_CLEAN", "passed": True, "evidence": ["nft -c ok"], "checked_by": "policy"},
    )

    dispatcher.assert_shippable(graph, graph_id="G")


# --- I2: the signed scope must cover what the envelope actually directs ---


def test_retargeting_the_exit_gate_is_refused_at_ingress(dispatcher, make_node):
    """Swapping FAIL_CLOSED_PASS for a waivable gate must invalidate the token."""
    envelope = dispatcher.dispatch(
        make_node("fail-closed", team="verification", exit_gate="FAIL_CLOSED_PASS"),
        graph_id="G",
    )
    tampered = dataclasses.replace(envelope, exit_gate="SPEC_COMPLETE")
    with pytest.raises(TokenError, match="signed scope"):
        dispatcher.deliver(tampered, to_agent="verification-lead")


def test_swapping_a_deliverable_is_refused_at_ingress(dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G")
    tampered = dataclasses.replace(
        envelope, deliverables=(ArtifactRef(kind="file", path="etc/passwd"),)
    )
    with pytest.raises(TokenError, match="signed scope"):
        dispatcher.deliver(tampered, to_agent="policy-lead")


def test_substituting_the_task_id_is_refused_at_ingress(dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G")
    tampered = dataclasses.replace(envelope, task_id=new_task_id())
    with pytest.raises(AuthorityError, match="does not match the task_id"):
        dispatcher.deliver(tampered, to_agent="policy-lead")


def test_retargeting_the_node_is_refused_at_ingress(dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G")
    tampered = dataclasses.replace(envelope, node_id="some-other-node")
    with pytest.raises(TokenError, match="signed scope"):
        dispatcher.deliver(tampered, to_agent="policy-lead")


# --- one live owner per node ---


def test_reclaiming_a_reclaimed_task_is_refused(dispatcher, make_node, make_graph):
    """A second reclaim of the same id used to orphan the live replacement."""
    node = make_node()
    graph = make_graph(node)
    original = dispatcher.dispatch(node, graph_id="G")
    dispatcher.reclaim(original.task_id, reason="first", graph=graph)

    with pytest.raises(DispatchRejected, match="already reclaimed"):
        dispatcher.reclaim(original.task_id, reason="second", graph=graph)
    assert dispatcher.queue_depth()["policy"] == 1


# --- I6: state is derivable from the log, so a restart must rebuild it ---


def test_cold_start_restores_open_tasks(manifest_path: Path, tmp_path: Path, make_node):
    """A restart used to re-dispatch the same node and disown the original."""
    first, _ = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert first is not None
    node = make_node()
    original = first.dispatch(node, graph_id="G")

    second, report = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert second is not None and report.ok
    assert len(second.tasks()) == 1, "the open task must come back"
    assert second.task(original.task_id).envelope.node_id == "deny-quic"
    assert second.dispatch(node, graph_id="G").task_id == original.task_id


def test_restored_tasks_carry_their_gate_outcome(manifest_path: Path, tmp_path: Path, make_node):
    first, _ = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert first is not None
    envelope = first.dispatch(make_node(), graph_id="G")
    first.accept_gate(
        envelope.task_id,
        {"gate": "POLICY_CLEAN", "passed": True, "evidence": ["nft -c ok"], "checked_by": "policy"},
    )

    second, _ = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert second is not None
    assert second.task(envelope.task_id).state == "gate_pass"


def test_a_restored_task_cannot_be_delivered_without_a_fresh_token(
    manifest_path: Path, tmp_path: Path, make_node
):
    """Replay rebuilds identity, not authority: the token is not in the log."""
    first, _ = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert first is not None
    envelope = first.dispatch(make_node(), graph_id="G")

    second, _ = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert second is not None
    restored = second.task(envelope.task_id).envelope
    with pytest.raises(Exception, match="invariant I2"):
        second.deliver(restored, to_agent="policy-lead")


# --- cold start must not open on a failed step ---


def test_missing_mirror_holds_read_only(manifest_path: Path, tmp_path: Path):
    """The report used to print FAIL for the mirror and open for dispatch anyway."""
    dispatcher, report = cold_start(
        manifest=manifest_path, audit_path=tmp_path / "audit.jsonl", mirror_path=None
    )
    assert dispatcher is None
    assert not report.ok
    mirror_step = [s for s in report.steps if s[0] == "audit mirror"][0]
    assert not mirror_step[1]


def test_every_failed_step_implies_not_ok(manifest_path: Path, tmp_path: Path):
    _, report = cold_start(
        manifest=manifest_path, audit_path=tmp_path / "audit.jsonl", mirror_path=None
    )
    assert report.ok == all(passed for _, passed, _ in report.steps)


# --- a corrupt log is an audit incident, not a traceback ---


def test_corrupt_timestamp_is_an_audit_chain_error(tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    log.append("orchestrator", "dispatch", task_id="T1")
    entry = json.loads(log.path.read_text(encoding="utf-8").splitlines()[0])
    entry["ts"] = "not-a-timestamp"
    log.path.write_text(
        json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    with pytest.raises(AuditChainError, match="timestamp"):
        log.verify_chain()


def test_corrupt_timestamp_holds_cold_start_read_only(manifest_path: Path, tmp_path: Path):
    log = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    log.append("orchestrator", "dispatch", task_id="T1")
    entry = json.loads(log.path.read_text(encoding="utf-8").splitlines()[0])
    entry["ts"] = "not-a-timestamp"
    log.path.write_text(
        json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )

    dispatcher, report = cold_start(
        manifest=manifest_path,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )
    assert dispatcher is None and not report.ok


# --- gate results are parsed, not coerced ---


def test_string_evidence_is_refused_not_split_into_characters():
    """'looks fine' used to satisfy the non-empty evidence rule as 10 characters."""
    with pytest.raises(SchemaError, match="list of strings"):
        GateResult.parse(
            {
                "gate": "POLICY_CLEAN",
                "passed": True,
                "evidence": "looks fine",
                "checked_by": "policy",
            }
        )


def test_malformed_checked_at_is_a_schema_error():
    with pytest.raises(SchemaError):
        GateResult.parse(
            {
                "gate": "POLICY_CLEAN",
                "passed": True,
                "evidence": ["nft -c ok"],
                "checked_by": "policy",
                "checked_at": 12345,
            }
        )


def test_non_string_evidence_entries_are_refused():
    with pytest.raises(SchemaError, match="list of strings"):
        GateResult.parse(
            {
                "gate": "POLICY_CLEAN",
                "passed": True,
                "evidence": [{"looks": "structured"}],
                "checked_by": "policy",
            }
        )


# --- a lead that reported is not stuck ---


def test_any_status_report_clears_the_ack_deadline(dispatcher, make_node):
    """Only 'accepted' used to count, so a lead reporting 'running' stayed stuck."""
    envelope = dispatcher.dispatch(make_node(), graph_id="G")
    dispatcher.ingest_status(_status(envelope.task_id, "running"))
    assert dispatcher.stuck_tasks(utcnow() + timedelta(minutes=5)) == []


def test_a_lead_past_its_promised_update_is_still_stuck(dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G")
    dispatcher.ingest_status(
        {
            "task_id": envelope.task_id,
            "state": "running",
            "next_update_by": (utcnow() + timedelta(minutes=5)).isoformat(),
        }
    )
    stuck = dispatcher.stuck_tasks(utcnow() + timedelta(minutes=10))
    assert [r.task_id for r in stuck] == [envelope.task_id]


# --- key revocation actually revokes ---


def test_revoking_drops_the_previous_key_immediately():
    ring = KeyRing(seed=b"\x05" * 32)
    payload = {"node_id": "n"}
    token = ring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=payload)
    ring.rotate_now(revoke=True)
    with pytest.raises(TokenError, match="unknown or retired key"):
        ring.verify(token, payload=payload)


def test_plain_rotation_still_honours_in_flight_tokens():
    ring = KeyRing(seed=b"\x06" * 32)
    payload = {"node_id": "n"}
    token = ring.sign(task_id=new_task_id(), team="policy", tier_max="T2", payload=payload)
    ring.rotate_now()
    ring.verify(token, payload=payload)
