"""The topology manifest: teams, leads, sub-agent rosters, and gate ownership.

Section 4 of the manifest makes adding a team a T1 act requiring a charter. A
charter is therefore a required field here, not a comment: a team declared
without one fails to load, so a shadow org cannot form by drive-by creation.

Section 4 also states the orchestrator knows leads by name and that sub-agent
rosters are the lead's problem. That is enforced structurally: ``Dispatcher``
resolves targets against ``Team.lead`` only, and never against ``subagents``.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import TopologyError
from .gates import GATES_BY_NAME

MIN_CHARTER_CHARS = 40

DEFAULT_MANIFEST = Path("orchestration/topology.toml")


@dataclass(frozen=True)
class Team:
    """One team: a single T2 lead, a T3 roster, and the gates it owns."""

    name: str
    lead: str
    charter: str
    gates_owned: tuple[str, ...]
    subagents: tuple[str, ...]
    tools: tuple[str, ...]

    def validate(self) -> None:
        if len(self.charter.strip()) < MIN_CHARTER_CHARS:
            raise TopologyError(
                f"team {self.name!r} has no usable charter "
                f"(needs at least {MIN_CHARTER_CHARS} characters). No charter, no team."
            )
        if not self.lead:
            raise TopologyError(f"team {self.name!r} declares no lead")
        if not self.subagents:
            raise TopologyError(
                f"team {self.name!r} declares no sub-agents; a lead with no roster is a "
                "specialist, not a team"
            )
        for gate_name in self.gates_owned:
            if gate_name not in GATES_BY_NAME:
                raise TopologyError(f"team {self.name!r} claims unknown gate {gate_name!r}")
            owner = GATES_BY_NAME[gate_name].owner_team
            if owner != self.name:
                raise TopologyError(
                    f"team {self.name!r} claims gate {gate_name!r}, which the gate "
                    f"registry assigns to {owner!r}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "lead": self.lead,
            "charter": self.charter,
            "gates_owned": list(self.gates_owned),
            "subagents": list(self.subagents),
            "tools": list(self.tools),
        }


@dataclass(frozen=True)
class Topology:
    version: int
    teams: tuple[Team, ...]

    def validate(self) -> None:
        if self.version != 1:
            raise TopologyError(f"unsupported topology manifest version: {self.version}")
        if not self.teams:
            raise TopologyError("topology declares no teams")

        names: set[str] = set()
        leads: set[str] = set()
        roster: dict[str, str] = {}
        for team in self.teams:
            team.validate()
            if team.name in names:
                raise TopologyError(f"duplicate team name: {team.name}")
            names.add(team.name)
            if team.lead in leads:
                raise TopologyError(f"lead {team.lead!r} is assigned to more than one team")
            leads.add(team.lead)
            for sub in team.subagents:
                prior = roster.get(sub)
                if prior is not None:
                    raise TopologyError(
                        f"sub-agent {sub!r} is rostered to both {prior!r} and {team.name!r}; "
                        "a sub-agent has exactly one lead"
                    )
                roster[sub] = team.name

        self._validate_gate_coverage()

    def _validate_gate_coverage(self) -> None:
        """Every gate has exactly one owning team present in the topology."""
        claimed: dict[str, str] = {}
        for team in self.teams:
            for gate_name in team.gates_owned:
                if gate_name in claimed:
                    raise TopologyError(
                        f"gate {gate_name!r} is claimed by both {claimed[gate_name]!r} "
                        f"and {team.name!r}"
                    )
                claimed[gate_name] = team.name
        unowned = sorted(set(GATES_BY_NAME) - set(claimed))
        if unowned:
            raise TopologyError(
                f"no team owns these gates: {', '.join(unowned)}. "
                "An unowned gate cannot pass, which blocks every release."
            )

    def team(self, name: str) -> Team:
        for candidate in self.teams:
            if candidate.name == name:
                return candidate
        known = ", ".join(sorted(t.name for t in self.teams))
        raise TopologyError(f"unknown team {name!r}; topology declares: {known}")

    def team_for_gate(self, gate_name: str) -> Team:
        for candidate in self.teams:
            if gate_name in candidate.gates_owned:
                return candidate
        raise TopologyError(f"no team in this topology owns gate {gate_name!r}")

    def lead_names(self) -> tuple[str, ...]:
        return tuple(team.lead for team in self.teams)

    def is_lead(self, agent: str) -> bool:
        return agent in self.lead_names()

    def is_subagent(self, agent: str) -> bool:
        return any(agent in team.subagents for team in self.teams)

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "teams": [team.to_dict() for team in self.teams]}

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Topology:
        allowed = {"version", "team"}
        unknown = set(raw) - allowed
        if unknown:
            raise TopologyError(f"topology has unknown top-level keys: {', '.join(sorted(unknown))}")
        if "version" not in raw:
            raise TopologyError("topology manifest must declare a version")
        entries = raw.get("team", [])
        if not isinstance(entries, list):
            raise TopologyError("topology 'team' must be an array of tables")

        teams: list[Team] = []
        for entry in entries:
            team_allowed = {"name", "lead", "charter", "gates_owned", "subagents", "tools"}
            unknown_keys = set(entry) - team_allowed
            if unknown_keys:
                raise TopologyError(
                    f"team entry has unknown keys: {', '.join(sorted(unknown_keys))}"
                )
            missing = {"name", "lead", "charter", "subagents"} - set(entry)
            if missing:
                raise TopologyError(f"team entry is missing keys: {', '.join(sorted(missing))}")
            teams.append(
                Team(
                    name=entry["name"],
                    lead=entry["lead"],
                    charter=entry["charter"],
                    gates_owned=tuple(entry.get("gates_owned", [])),
                    subagents=tuple(entry["subagents"]),
                    tools=tuple(entry.get("tools", [])),
                )
            )

        topology = cls(version=raw["version"], teams=tuple(teams))
        topology.validate()
        return topology

    @classmethod
    def load(cls, path: Path | None = None) -> Topology:
        target = Path(path) if path is not None else DEFAULT_MANIFEST
        try:
            raw = tomllib.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise TopologyError(f"topology manifest not found: {target}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise TopologyError(f"{target}: invalid TOML: {exc}") from exc
        return cls.parse(raw)
