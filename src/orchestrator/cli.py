"""Operator surface for the orchestration control plane (T4 executor).

Read-only by default. The two commands that mutate state — ``coldstart`` and
``dispatch`` — write to the audit log, which is append-only, so neither can
rewrite history.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import AuditLog
from .errors import OrchestratorError
from .gates import GATES
from .schema import WorkGraph
from .state import cold_start, replay
from .tokens import new_task_id
from .topology import DEFAULT_MANIFEST, Topology

DEFAULT_AUDIT = Path(".orchestration/audit.jsonl")
DEFAULT_MIRROR = Path(".orchestration/mirror/audit.jsonl")


def cmd_topology(args: argparse.Namespace) -> int:
    topology = Topology.load(args.manifest)
    print(f"topology v{topology.version} — {len(topology.teams)} teams\n")
    for team in topology.teams:
        gates = ", ".join(team.gates_owned) or "(owns no gate)"
        print(f"  {team.name}")
        print(f"    T2 lead     {team.lead}")
        print(f"    gates       {gates}")
        print(f"    T3 roster   {', '.join(team.subagents)}")
        print(f"    T4 tools    {', '.join(team.tools)}")
        print(f"    charter     {' '.join(team.charter.split())[:88]}...")
        print()
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    del args
    print(f"{'GATE':18} {'OWNER':14} {'WAIVABLE':9} UPSTREAM")
    for entry in GATES:
        waivable = "yes" if entry.waivable else "NEVER"
        print(f"{entry.name:18} {entry.owner_team:14} {waivable:9} {entry.upstream}")
    print("\nA gate result is a hard boolean. pct_complete is advisory and never gates.")
    return 0


def cmd_validate_graph(args: argparse.Namespace) -> int:
    topology = Topology.load(args.manifest)
    graph = WorkGraph.from_json(args.graph.read_text(encoding="utf-8"))
    for node in graph.nodes:
        topology.team(node.team)
    print(f"work graph OK — {len(graph.nodes)} nodes, goal: {graph.goal}")
    for node in graph.nodes:
        deps = f" after {', '.join(node.depends_on)}" if node.depends_on else ""
        print(f"  {node.id:28} {node.team:16} {node.exit_gate:18} {node.tier_max}{deps}")
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    audit = AuditLog(args.audit, args.mirror)
    count = audit.verify_chain()
    audit.check_mirror()
    state = replay(audit)
    print(f"audit chain intact — {count} entries")
    print(f"open tasks        {len(state.open_tasks())}")
    print(f"gate results      {len(state.gate_results)}")
    print(f"decision memos    {state.decisions}")
    if state.paused_teams:
        print(f"paused teams      {', '.join(sorted(state.paused_teams))}")
    return 0


def cmd_coldstart(args: argparse.Namespace) -> int:
    _, report = cold_start(
        manifest=args.manifest,
        audit_path=args.audit,
        mirror_path=args.mirror,
    )
    print(report.render())
    return 0 if report.ok else 1


def cmd_dispatch(args: argparse.Namespace) -> int:
    dispatcher, report = cold_start(
        manifest=args.manifest,
        audit_path=args.audit,
        mirror_path=args.mirror,
    )
    if dispatcher is None:
        print(report.render(), file=sys.stderr)
        print("\nrefusing to dispatch from READ_ONLY mode", file=sys.stderr)
        return 1
    graph = WorkGraph.from_json(args.graph.read_text(encoding="utf-8"))
    graph_id = args.graph_id or new_task_id()
    envelopes = dispatcher.dispatch_graph(graph, graph_id=graph_id)
    print(f"graph {graph_id} — dispatched {len(envelopes)} of {len(graph.nodes)} nodes")
    for envelope in envelopes:
        lead = dispatcher.topology.team(envelope.team).lead
        print(f"  {envelope.task_id}  {envelope.node_id:28} -> {lead}")
    blocked = len(graph.nodes) - len(envelopes)
    if blocked:
        print(f"\n{blocked} node(s) held: dependencies have not passed their gates yet")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amnesic-orchestrator",
        description="T1 control plane: route work to team leads with a verifiable trail.",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--mirror", type=Path, default=DEFAULT_MIRROR)
    sub = parser.add_subparsers(dest="command", required=True)

    show = sub.add_parser("topology", help="print teams, leads, rosters, and gate ownership")
    show.set_defaults(func=cmd_topology)

    gates = sub.add_parser("gates", help="print the gate table and its upstream mapping")
    gates.set_defaults(func=cmd_gates)

    validate = sub.add_parser("validate-graph", help="parse and validate a work graph JSON file")
    validate.add_argument("graph", type=Path)
    validate.set_defaults(func=cmd_validate_graph)

    verify = sub.add_parser("audit-verify", help="verify the hash chain and the mirror")
    verify.set_defaults(func=cmd_audit_verify)

    boot = sub.add_parser("coldstart", help="run the section 10 cold-start checks")
    boot.set_defaults(func=cmd_coldstart)

    dispatch = sub.add_parser("dispatch", help="cold start, then dispatch every ready node")
    dispatch.add_argument("graph", type=Path)
    dispatch.add_argument("--graph-id")
    dispatch.set_defaults(func=cmd_dispatch)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        raise SystemExit(args.func(args))
    except OrchestratorError as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except BrokenPipeError:
        # Piping a readout into head/less is normal operator behaviour.
        raise SystemExit(0) from None
    except OSError as exc:
        print(f"io error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
