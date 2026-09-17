"""Invariant I1: all work flows through team leads. No direct sub-agent dispatch.

Also covers dispatch idempotence, the ack SLO and reclaim, READ_ONLY refusal,
and the rule that a lead cannot advance its own gate.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from orchestrator.dispatch import Dispatcher
from orchestrator.errors import (
    AuthorityError,
    DispatchRejected,
    PolicyBreach,
    ReadOnlyMode,
    ReplayError,
)
from orchestrator.schema import DecisionMemo, TaskEnvelope, utcnow


def _status(task_id: str, state: str, minutes: int = 5) -> dict:
    return {
        "task_id": task_id,
        "state": state,
        "next_update_by": (utcnow() + timedelta(minutes=minutes)).isoformat(),
    }


def test_dispatch_routes_to_the_declared_lead(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    dispatcher.deliver(envelope, to_agent="policy-lead")


def test_direct_subagent_dispatch_is_refused(dispatcher: Dispatcher, make_node):
    """Invariant I1. The token is valid; the recipient is not."""
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    with pytest.raises(AuthorityError, match="invariant I1"):
        dispatcher.deliver(envelope, to_agent="nft-policy-audit")


def test_delivery_to_another_teams_lead_is_refused(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    with pytest.raises(AuthorityError, match="not the lead of team"):
        dispatcher.deliver(envelope, to_agent="release-lead")


def test_unsigned_task_is_dropped_at_ingress(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    unsigned = TaskEnvelope(**{**envelope.__dict__, "token": {"mac": "forged"}})
    with pytest.raises(AuthorityError, match="invariant I2"):
        dispatcher.deliver(unsigned, to_agent="policy-lead")


def test_ingress_consumes_the_token_once(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    dispatcher.deliver(envelope, to_agent="policy-lead")
    with pytest.raises(ReplayError, match="already consumed"):
        dispatcher.deliver(envelope, to_agent="policy-lead")


def test_dispatch_is_idempotent_on_task_id(dispatcher: Dispatcher, make_node):
    node = make_node()
    first = dispatcher.dispatch(node, graph_id="G1")
    again = dispatcher.dispatch(node, graph_id="G1", task_id=first.task_id)
    assert again.task_id == first.task_id
    assert len(dispatcher.tasks()) == 1


def test_a_node_cannot_be_dispatched_to_two_owners(dispatcher: Dispatcher, make_node):
    node = make_node()
    first = dispatcher.dispatch(node, graph_id="G1")
    second = dispatcher.dispatch(node, graph_id="G1")
    assert second.task_id == first.task_id, "one task, one owner"


def test_unknown_team_is_refused(dispatcher: Dispatcher, make_node):
    from orchestrator.errors import TopologyError

    with pytest.raises(TopologyError, match="unknown team"):
        dispatcher.dispatch(make_node(team="growth"), graph_id="G1")


def test_read_only_mode_refuses_dispatch(topology, keyring, audit, make_node):
    locked = Dispatcher(topology, keyring, audit, read_only=True)
    with pytest.raises(ReadOnlyMode, match="READ_ONLY"):
        locked.dispatch(make_node(), graph_id="G1")


def test_paused_team_refuses_dispatch(dispatcher: Dispatcher, make_node):
    dispatcher.pause_team("policy", reason="rollback in progress")
    with pytest.raises(DispatchRejected, match="is paused"):
        dispatcher.dispatch(make_node(), graph_id="G1")
    dispatcher.resume_team("policy")
    assert dispatcher.dispatch(make_node(), graph_id="G1")


def test_a_lead_cannot_self_report_a_gate_pass(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    with pytest.raises(DispatchRejected, match="invariant I3"):
        dispatcher.ingest_status(_status(envelope.task_id, "gate_pass"))


def test_blocked_status_requires_a_blocker(dispatcher: Dispatcher, make_node):
    from orchestrator.errors import SchemaError

    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    with pytest.raises(SchemaError, match="without a blocker"):
        dispatcher.ingest_status(_status(envelope.task_id, "blocked"))


def test_percent_complete_never_advances_a_task(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    dispatcher.ingest_status({**_status(envelope.task_id, "running"), "pct_complete": 100})
    assert dispatcher.task(envelope.task_id).state == "running"
    assert not dispatcher.may_ship("G1")


def test_ship_is_blocked_until_every_gate_passes(dispatcher: Dispatcher, make_node):
    first = dispatcher.dispatch(make_node("deny-quic"), graph_id="G1")
    dispatcher.dispatch(make_node("doc-the-delta", team="docs", exit_gate="SPEC_COMPLETE",
                                  path="docs/networking.md"), graph_id="G1")
    dispatcher.accept_gate(first.task_id, {
        "gate": "POLICY_CLEAN", "passed": True,
        "evidence": ["nft -c ok"], "checked_by": "policy",
    })
    with pytest.raises(PolicyBreach, match="without a passing gate"):
        dispatcher.assert_shippable("G1")


def test_wrong_gate_for_the_task_is_refused(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    with pytest.raises(DispatchRejected, match="was handed a"):
        dispatcher.accept_gate(envelope.task_id, {
            "gate": "RELEASE_SIGNED", "passed": True,
            "evidence": ["all green"], "checked_by": "release",
        })


def test_dependencies_hold_nodes_until_their_gate_passes(dispatcher: Dispatcher, make_node, make_graph):
    upstream = make_node("doc-the-delta", team="docs", exit_gate="SPEC_COMPLETE",
                         path="docs/networking.md")
    downstream = make_node("deny-quic", depends_on=("doc-the-delta",))
    graph = make_graph(upstream, downstream)

    first_wave = dispatcher.dispatch_graph(graph, graph_id="G1")
    assert [e.node_id for e in first_wave] == ["doc-the-delta"]

    dispatcher.accept_gate(first_wave[0].task_id, {
        "gate": "SPEC_COMPLETE", "passed": True,
        "evidence": ["delta written"], "checked_by": "docs",
    })
    second_wave = dispatcher.dispatch_graph(graph, graph_id="G1")
    assert [e.node_id for e in second_wave] == ["doc-the-delta", "deny-quic"]


def test_stuck_task_is_reclaimed_and_reassigned(dispatcher: Dispatcher, make_node, make_graph):
    node = make_node()
    graph = make_graph(node)
    envelope = dispatcher.dispatch(node, graph_id="G1")

    later = utcnow() + timedelta(minutes=2)
    assert [r.task_id for r in dispatcher.stuck_tasks(later)] == [envelope.task_id]

    replacement = dispatcher.reclaim(envelope.task_id, reason="ack SLO missed", graph=graph)
    assert replacement.task_id != envelope.task_id
    assert dispatcher.task(envelope.task_id).state == "abandoned"
    assert dispatcher.task(envelope.task_id).superseded_by == replacement.task_id
    assert dispatcher.queue_depth()["policy"] == 1, "one live owner at a time"


def test_acknowledged_task_is_not_stuck(dispatcher: Dispatcher, make_node):
    envelope = dispatcher.dispatch(make_node(), graph_id="G1")
    dispatcher.ingest_status(_status(envelope.task_id, "accepted", minutes=30))
    assert dispatcher.stuck_tasks(utcnow() + timedelta(minutes=2)) == []


def test_a_passed_task_cannot_be_reclaimed(dispatcher: Dispatcher, make_node, make_graph):
    node = make_node()
    envelope = dispatcher.dispatch(node, graph_id="G1")
    dispatcher.accept_gate(envelope.task_id, {
        "gate": "POLICY_CLEAN", "passed": True,
        "evidence": ["nft -c ok"], "checked_by": "policy",
    })
    with pytest.raises(DispatchRejected, match="already passed"):
        dispatcher.reclaim(envelope.task_id, reason="stale", graph=make_graph(node))


def test_decision_memo_is_logged_with_a_rationale(dispatcher: Dispatcher):
    memo = DecisionMemo(
        conflict="verification calls the QUIC drop a regression; policy calls it noise",
        teams=("verification", "policy"),
        options=("hold the release", "ship with the drop"),
        chosen="hold the release",
        rationale="FAIL_CLOSED_PASS is unwaivable; a disputed leak path resolves as a hold",
    )
    entry = dispatcher.record_decision(memo)
    assert entry.event == "decision_memo"


def test_every_dispatch_is_audited(dispatcher: Dispatcher, make_node, audit):
    dispatcher.dispatch(make_node(), graph_id="G1")
    events = [entry.event for entry in audit.entries()]
    assert events == ["dispatch"]
    assert audit.verify_chain() == 1
    audit.check_mirror()
