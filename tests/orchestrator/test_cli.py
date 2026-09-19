"""Operator CLI coverage.

The CLI is the T4 surface an operator actually touches, so its exit codes are
part of the contract: a failed cold start must exit non-zero, and `dispatch`
must refuse to run from READ_ONLY rather than proceeding unverified.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Callable

import pytest

from orchestrator.audit import AuditLog
from orchestrator.cli import build_parser, main
from orchestrator.errors import TopologyError

GOOD_GRAPH = {
    "goal": "Close the downstream QUIC path",
    "invariants_touched": ["I3"],
    "nodes": [
        {
            "id": "quic-threat-delta",
            "title": "State the boundary delta for denying downstream QUIC",
            "team": "threat-research",
            "exit_gate": "SPEC_COMPLETE",
            "tier_max": "T3",
            "acceptance": ["invariants touched are named"],
            "deliverables": [{"kind": "report", "path": "docs/networking.md"}],
        },
        {
            "id": "quic-deny-rule",
            "title": "Deny non-53 downstream UDP explicitly",
            "team": "policy",
            "exit_gate": "POLICY_CLEAN",
            "tier_max": "T2",
            "depends_on": ["quic-threat-delta"],
            "acceptance": ["nft -c accepts"],
            "deliverables": [{"kind": "ruleset", "path": "network/policy.nft.in"}],
        },
    ],
}


@pytest.fixture
def run_cli(manifest_path: Path, tmp_path: Path) -> Callable[..., tuple[int, str]]:
    """Invoke a subcommand with all paths pinned to tmp_path. Returns (code, stdout)."""

    def _run(*argv: str) -> tuple[int, str]:
        args = build_parser().parse_args(
            [
                "--manifest",
                str(manifest_path),
                "--audit",
                str(tmp_path / "audit.jsonl"),
                "--mirror",
                str(tmp_path / "mirror" / "audit.jsonl"),
                *argv,
            ]
        )
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = args.func(args)
        return code, buffer.getvalue()

    return _run


@pytest.fixture
def graph_file(tmp_path: Path) -> Callable[[dict], Path]:
    def _write(graph: dict) -> Path:
        path = tmp_path / "graph.json"
        path.write_text(json.dumps(graph), encoding="utf-8")
        return path

    return _write


def test_topology_lists_every_team_with_its_lead(run_cli, topology):
    code, out = run_cli("topology")
    assert code == 0
    for team in topology.teams:
        assert team.name in out
        assert team.lead in out
        for sub in team.subagents:
            assert sub in out


def test_gates_marks_the_unwaivable_gate(run_cli):
    code, out = run_cli("gates")
    assert code == 0
    assert "FAIL_CLOSED_PASS" in out
    assert "NEVER" in out
    assert "SAFETY_PASS" in out, "the upstream mapping is part of the readout"


def test_validate_graph_accepts_a_good_graph(run_cli, graph_file):
    code, out = run_cli("validate-graph", str(graph_file(GOOD_GRAPH)))
    assert code == 0
    assert "work graph OK" in out
    assert "after quic-threat-delta" in out, "dependency edges are shown to the operator"


def test_validate_graph_rejects_an_undeclared_team(run_cli, graph_file):
    graph = json.loads(json.dumps(GOOD_GRAPH))
    graph["nodes"][0]["team"] = "growth"
    with pytest.raises(TopologyError, match="unknown team"):
        run_cli("validate-graph", str(graph_file(graph)))


def test_coldstart_reports_all_five_checks(run_cli):
    code, out = run_cli("coldstart")
    assert code == 0
    assert "ready for dispatch" in out
    assert out.count("PASS") == 5


def test_coldstart_exits_nonzero_on_a_broken_chain(run_cli, tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy")
    audit.append("orchestrator", "dispatch", task_id="T2", team="policy")
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["team"] = "release"
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code, out = run_cli("coldstart")
    assert code == 1
    assert "READ_ONLY" in out
    assert "SEV-2" in out


def test_dispatch_holds_nodes_whose_dependencies_have_not_passed(run_cli, graph_file):
    code, out = run_cli("dispatch", str(graph_file(GOOD_GRAPH)), "--graph-id", "G1")
    assert code == 0
    assert "dispatched 1 of 2 nodes" in out
    assert "quic-threat-delta" in out
    assert "threat-research-lead" in out, "the readout names the lead, never a sub-agent"
    assert "1 node(s) held" in out
    assert "quic-deny-rule" not in out


def test_dispatch_refuses_to_run_from_read_only(run_cli, graph_file, tmp_path: Path, capsys):
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy")
    assert audit.mirror_path is not None
    audit.mirror_path.write_text("", encoding="utf-8")

    code, _ = run_cli("dispatch", str(graph_file(GOOD_GRAPH)))
    assert code == 1
    assert "refusing to dispatch from READ_ONLY mode" in capsys.readouterr().err


def test_audit_verify_projects_state_from_the_log(run_cli):
    run_cli("coldstart")
    code, out = run_cli("audit-verify")
    assert code == 0
    assert "audit chain intact" in out
    assert "open tasks" in out


def test_main_exits_two_on_a_control_plane_error(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(
        "sys.argv",
        ["amnesic-orchestrator", "--manifest", str(tmp_path / "absent.toml"), "topology"],
    )
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 2


def test_main_exits_zero_on_a_clean_readout(monkeypatch, manifest_path: Path):
    monkeypatch.setattr(
        "sys.argv", ["amnesic-orchestrator", "--manifest", str(manifest_path), "gates"]
    )
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert excinfo.value.code == 0
