"""Invariant I4: the log is append-only and hash-chained, and mirrored.

Invariant I6: orchestrator state is derivable from the log by replay.
"""

from __future__ import annotations

import json

import pytest

from orchestrator.audit import GENESIS_HASH, AuditLog
from orchestrator.errors import AuditChainError, AuditDivergenceError
from orchestrator.state import replay


def _write(audit: AuditLog, count: int = 3) -> None:
    for index in range(count):
        audit.append("orchestrator", "dispatch", task_id=f"TASK{index}", team="policy")


def test_first_entry_chains_to_genesis(audit: AuditLog):
    entry = audit.append("orchestrator", "cold_start", entries_replayed=0)
    assert entry.seq == 0
    assert entry.prev_hash == GENESIS_HASH


def test_each_entry_commits_to_its_predecessor(audit: AuditLog):
    _write(audit, 4)
    entries = list(audit.entries())
    for earlier, later in zip(entries, entries[1:]):
        assert later.prev_hash == earlier.entry_hash()
        assert later.seq == earlier.seq + 1
    assert audit.verify_chain() == 4


def test_core_fields_cannot_be_overridden(audit: AuditLog):
    with pytest.raises(AuditChainError, match="core audit field"):
        audit.append("orchestrator", "dispatch", seq=999)


def test_mid_chain_tamper_breaks_the_chain(audit: AuditLog):
    _write(audit, 3)
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["team"] = "release"
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditChainError, match="chain break"):
        audit.verify_chain()


def test_deleted_entry_is_detected_as_a_sequence_gap(audit: AuditLog):
    _write(audit, 3)
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    audit.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    with pytest.raises(AuditChainError, match="sequence gap"):
        audit.verify_chain()


def test_tail_tamper_is_caught_by_the_mirror_not_the_chain(audit: AuditLog):
    """A hash chain cannot bind its own tail. The mirror is what covers it."""
    _write(audit, 3)
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    last["team"] = "release"
    lines[-1] = json.dumps(last, sort_keys=True, separators=(",", ":"))
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit.verify_chain()  # the chain alone does not see it
    with pytest.raises(AuditDivergenceError, match="diverge"):
        audit.check_mirror()


def test_unauthorized_write_to_the_mirror_is_detected(audit: AuditLog):
    _write(audit, 2)
    assert audit.mirror_path is not None
    with audit.mirror_path.open("a", encoding="utf-8") as fh:
        fh.write('{"ts":"2026-09-17T00:00:00+00:00","seq":9,"actor":"x","event":"y","prev_hash":"0"}\n')
    with pytest.raises(AuditDivergenceError, match="the primary does not"):
        audit.check_mirror()


def test_mirror_receives_identical_lines(audit: AuditLog):
    _write(audit, 3)
    assert audit.mirror_path is not None
    assert audit.path.read_text(encoding="utf-8") == audit.mirror_path.read_text(encoding="utf-8")
    audit.check_mirror()


def test_state_is_reconstructed_by_replay(audit: AuditLog):
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy", exit_gate="POLICY_CLEAN")
    audit.append("orchestrator", "dispatch", task_id="T2", team="docs", exit_gate="SPEC_COMPLETE")
    audit.append("orchestrator", "gate_result", task_id="T1", gate="POLICY_CLEAN", passed=True)
    audit.append("orchestrator", "team_paused", team="release", reason="incident")

    state = replay(audit)
    assert state.entries == 4
    assert set(state.dispatched) == {"T1", "T2"}
    assert state.gate_results == {"T1": True}
    assert state.paused_teams == {"release"}
    assert set(state.open_tasks()) == {"T2"}


def test_reclaimed_tasks_leave_the_open_set(audit: AuditLog):
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy", exit_gate="POLICY_CLEAN")
    audit.append("orchestrator", "reclaim", task_id="T1", reason="ack SLO missed")
    assert replay(audit).open_tasks() == {}
