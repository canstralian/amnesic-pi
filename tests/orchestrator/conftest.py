"""Fixtures for the orchestration tests.

Everything shared is exposed as a fixture rather than as a module-level import.
``tests/orchestrator/`` deliberately has no ``__init__.py``: adding one would
make pytest import this directory as a package named ``orchestrator``, which
would shadow the real ``src/orchestrator`` package under test.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Callable

import pytest

from orchestrator.audit import AuditLog
from orchestrator.dispatch import Dispatcher
from orchestrator.schema import ArtifactRef, WorkGraph, WorkNode
from orchestrator.tokens import KeyRing
from orchestrator.topology import Topology


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def manifest_path(repo_root: Path) -> Path:
    return repo_root / "orchestration" / "topology.toml"


@pytest.fixture
def topology(manifest_path: Path) -> Topology:
    return Topology.load(manifest_path)


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(rotation=timedelta(hours=1), seed=b"\x01" * 32)


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")


@pytest.fixture
def dispatcher(topology: Topology, keyring: KeyRing, audit: AuditLog) -> Dispatcher:
    return Dispatcher(topology, keyring, audit, read_only=False)


@pytest.fixture
def make_node() -> Callable[..., WorkNode]:
    def _make(
        node_id: str = "deny-quic",
        *,
        team: str = "policy",
        exit_gate: str = "POLICY_CLEAN",
        tier_max: str = "T2",
        depends_on: tuple[str, ...] = (),
        path: str = "network/policy.nft.in",
        acceptance: tuple[str, ...] = ("nft -c accepts the rendered ruleset",),
    ) -> WorkNode:
        return WorkNode(
            id=node_id,
            title=f"work item {node_id}",
            team=team,
            exit_gate=exit_gate,
            acceptance=acceptance,
            tier_max=tier_max,
            depends_on=depends_on,
            deliverables=(ArtifactRef(kind="ruleset", path=path),),
        )

    return _make


@pytest.fixture
def make_graph() -> Callable[..., WorkGraph]:
    def _make(*nodes: WorkNode, goal: str = "keep the boundary closed") -> WorkGraph:
        return WorkGraph(goal=goal, nodes=nodes)

    return _make


@pytest.fixture
def single_team_manifest() -> Callable[..., dict]:
    def _make(**overrides) -> dict:
        team = {
            "name": "policy",
            "lead": "policy-lead",
            "charter": "Owns the security boundary and every rule granting network authority.",
            "gates_owned": ["POLICY_CLEAN"],
            "subagents": ["nft-policy-audit"],
        }
        team.update(overrides)
        return {"version": 1, "team": [team]}

    return _make
