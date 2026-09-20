import argparse
import os
import subprocess
from pathlib import Path

import amnesic_pi.cli as cli
from amnesic_pi.config import Config
from amnesic_pi.verify import Check


def _args(tmp_path: Path) -> argparse.Namespace:
    return argparse.Namespace(
        config=tmp_path / "network.env",
        template=tmp_path / "policy.nft.in",
    )


def test_apply_firewall_refuses_non_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    assert cli.cmd_apply(_args(tmp_path)) == 2


def test_apply_firewall_validates_before_apply(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_load", lambda _path: Config("eth0", "eth1"))
    monkeypatch.setattr(cli, "tor_uid", lambda _config: 123)
    monkeypatch.setattr(cli, "render_file", lambda *_args: "table inet amnesic_pi {}\n")

    calls: list[tuple[str, ...]] = []

    def fake_run(args, **_kwargs):
        command = tuple(str(item) for item in args)
        calls.append(command)
        if command[:5] == ("nft", "list", "table", "inet", "amnesic_pi"):
            return subprocess.CompletedProcess(args, 1)
        if command[:3] == ("nft", "-c", "-f"):
            candidate = Path(command[3]).read_text()
            assert candidate == "table inet amnesic_pi {}\n"
            return subprocess.CompletedProcess(args, 0)
        if command[:2] == ("nft", "-f"):
            return subprocess.CompletedProcess(args, 0)
        raise AssertionError(f"unexpected command: {command!r}")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.cmd_apply(_args(tmp_path)) == 0
    assert [call[:2] for call in calls[-2:]] == [("nft", "-c"), ("nft", "-f")]


def test_apply_firewall_does_not_apply_invalid_candidate(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_load", lambda _path: Config("eth0", "eth1"))
    monkeypatch.setattr(cli, "tor_uid", lambda _config: 123)
    monkeypatch.setattr(cli, "render_file", lambda *_args: "broken\n")

    calls: list[tuple[str, ...]] = []

    def fake_run(args, **_kwargs):
        command = tuple(str(item) for item in args)
        calls.append(command)
        if command[:5] == ("nft", "list", "table", "inet", "amnesic_pi"):
            return subprocess.CompletedProcess(args, 1)
        if command[:3] == ("nft", "-c", "-f"):
            return subprocess.CompletedProcess(args, 1)
        raise AssertionError(f"candidate failure must stop execution: {command!r}")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.cmd_apply(_args(tmp_path)) == 1
    assert not any(call[:2] == ("nft", "-f") for call in calls)


def test_apply_firewall_replaces_only_existing_amnesic_table(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_load", lambda _path: Config("eth0", "eth1"))
    monkeypatch.setattr(cli, "tor_uid", lambda _config: 123)
    monkeypatch.setattr(cli, "render_file", lambda *_args: "table inet amnesic_pi {}\n")

    def fake_run(args, **_kwargs):
        command = tuple(str(item) for item in args)
        if command[:5] == ("nft", "list", "table", "inet", "amnesic_pi"):
            return subprocess.CompletedProcess(args, 0)
        if command[:3] == ("nft", "-c", "-f"):
            candidate = Path(command[3]).read_text()
            assert candidate.startswith("delete table inet amnesic_pi\n")
            assert "flush ruleset" not in candidate
            return subprocess.CompletedProcess(args, 0)
        if command[:2] == ("nft", "-f"):
            return subprocess.CompletedProcess(args, 0)
        raise AssertionError(f"unexpected command: {command!r}")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.cmd_apply(_args(tmp_path)) == 0


def test_verify_firewall_command_returns_failure(monkeypatch):
    monkeypatch.setattr(
        cli,
        "verify_firewall",
        lambda: [Check("forward chain has no rules", False, "1 rule(s)")],
    )

    assert cli.cmd_verify_firewall(argparse.Namespace()) == 1


def test_verify_enforced_mode_command_returns_success(monkeypatch):
    monkeypatch.setattr(
        cli,
        "verify_enforced_mode",
        lambda: [Check("firewall enabled", True, "enabled")],
    )

    assert cli.cmd_verify_enforced_mode(argparse.Namespace()) == 0


def test_parser_exposes_security_verification_commands():
    parser = cli.build_parser()

    assert parser.parse_args(["verify-firewall"]).command == "verify-firewall"
    assert parser.parse_args(["verify-enforced-mode"]).command == "verify-enforced-mode"
