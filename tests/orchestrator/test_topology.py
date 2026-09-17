"""The topology manifest is T1-controlled: no charter, no team."""

from __future__ import annotations

from pathlib import Path

import pytest

from orchestrator.errors import TopologyError
from orchestrator.gates import GATES_BY_NAME
from orchestrator.topology import Topology


def test_shipped_manifest_is_valid(topology: Topology):
    assert len(topology.teams) == 7
    assert len(set(topology.lead_names())) == 7


def test_every_gate_has_exactly_one_owning_team(topology: Topology):
    for gate_name, gate in GATES_BY_NAME.items():
        assert topology.team_for_gate(gate_name).name == gate.owner_team
    claimed = [name for team in topology.teams for name in team.gates_owned]
    assert sorted(claimed) == sorted(GATES_BY_NAME)


def test_team_without_a_charter_is_refused(single_team_manifest):
    with pytest.raises(TopologyError, match="no usable charter"):
        Topology.parse(single_team_manifest(charter="temporary"))


def test_team_without_a_roster_is_refused(single_team_manifest):
    with pytest.raises(TopologyError, match="no sub-agents"):
        Topology.parse(single_team_manifest(subagents=[]))


def test_unowned_gate_blocks_the_topology(single_team_manifest):
    with pytest.raises(TopologyError, match="no team owns these gates"):
        Topology.parse(single_team_manifest())


def test_team_cannot_claim_another_teams_gate(single_team_manifest):
    with pytest.raises(TopologyError, match="gate registry assigns"):
        Topology.parse(single_team_manifest(gates_owned=["RELEASE_SIGNED"]))


def test_unknown_manifest_key_is_refused(single_team_manifest):
    with pytest.raises(TopologyError, match="unknown keys"):
        Topology.parse(single_team_manifest(escalate_to="T1"))


def test_a_subagent_has_exactly_one_lead(topology: Topology):
    raw = topology.to_dict()
    raw["team"] = raw.pop("teams")
    raw["team"][1]["subagents"] = [*raw["team"][1]["subagents"], "release-gate-runner"]
    with pytest.raises(TopologyError, match="rostered to both"):
        Topology.parse(raw)


def test_every_declared_subagent_has_a_skill_file(topology: Topology, repo_root: Path):
    """A roster entry with no skill file is a team that cannot do its work."""
    missing = [
        sub
        for team in topology.teams
        for sub in team.subagents
        if not (repo_root / ".claude" / "skills" / sub / "SKILL.md").is_file()
    ]
    assert not missing, f"rostered sub-agents without a skill file: {missing}"


def test_every_lead_has_an_agent_file(topology: Topology, repo_root: Path):
    missing = [
        team.lead
        for team in topology.teams
        if not (repo_root / ".claude" / "agents" / f"{team.lead}.md").is_file()
    ]
    assert not missing, f"team leads without an agent definition: {missing}"
