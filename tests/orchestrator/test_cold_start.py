"""Section 10: no dispatch until the log, the mirror, the keys, and the
topology all check out. Any failure leaves the orchestrator in READ_ONLY.
"""

from __future__ import annotations

import json
from pathlib import Path

from orchestrator.audit import AuditLog
from orchestrator.state import cold_start


def _boot(manifest: Path, tmp_path: Path):
    return cold_start(
        manifest=manifest,
        audit_path=tmp_path / "audit.jsonl",
        mirror_path=tmp_path / "mirror" / "audit.jsonl",
    )


def test_clean_cold_start_opens_for_dispatch(manifest_path: Path, tmp_path: Path):
    dispatcher, report = _boot(manifest_path, tmp_path)
    assert report.ok
    assert dispatcher is not None
    assert not dispatcher.read_only
    assert [name for name, _, _ in report.steps] == [
        "topology manifest",
        "audit chain",
        "audit mirror",
        "key material",
        "node reconciliation",
    ]


def test_cold_start_is_recorded_in_the_log(manifest_path: Path, tmp_path: Path):
    _boot(manifest_path, tmp_path)
    events = [entry.event for entry in AuditLog(tmp_path / "audit.jsonl").entries()]
    assert events == ["cold_start"]


def test_a_broken_chain_holds_the_orchestrator_in_read_only(manifest_path: Path, tmp_path: Path):
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy")
    audit.append("orchestrator", "dispatch", task_id="T2", team="policy")
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["team"] = "release"
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    dispatcher, report = _boot(manifest_path, tmp_path)
    assert dispatcher is None
    assert not report.ok
    assert any("SEV-2" in detail for _, passed, detail in report.steps if not passed)


def test_a_diverged_mirror_holds_the_orchestrator_in_read_only(
    manifest_path: Path, tmp_path: Path
):
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    audit.append("orchestrator", "dispatch", task_id="T1", team="policy")
    assert audit.mirror_path is not None
    audit.mirror_path.write_text("", encoding="utf-8")

    dispatcher, report = _boot(manifest_path, tmp_path)
    assert dispatcher is None
    assert any("SEV-1" in detail for _, passed, detail in report.steps if not passed)


def test_a_missing_manifest_holds_the_orchestrator_in_read_only(tmp_path: Path):
    dispatcher, report = _boot(tmp_path / "absent.toml", tmp_path)
    assert dispatcher is None
    assert report.steps[0][0] == "topology manifest"
    assert not report.steps[0][1]


def test_open_task_for_a_retired_team_blocks_reconciliation(
    manifest_path: Path, tmp_path: Path
):
    """An open task naming a team the manifest no longer declares must not be lost."""
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "mirror" / "audit.jsonl")
    audit.append(
        "orchestrator",
        "dispatch",
        task_id="T1",
        team="growth",
        node_id="n1",
        graph_id="G1",
        exit_gate="POLICY_CLEAN",
    )
    dispatcher, report = _boot(manifest_path, tmp_path)
    assert dispatcher is None
    assert report.steps[-1][0] == "node reconciliation"
    assert "growth" in report.steps[-1][2]


def test_paused_teams_survive_a_restart(manifest_path: Path, tmp_path: Path):
    dispatcher, _ = _boot(manifest_path, tmp_path)
    assert dispatcher is not None
    dispatcher.pause_team("release", reason="rollback in progress")

    restarted, report = _boot(manifest_path, tmp_path)
    assert report.ok
    assert restarted is not None
    assert restarted.is_paused("release"), "state is a projection of the log (invariant I6)"
