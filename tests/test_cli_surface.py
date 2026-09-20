"""The command surface the systemd units and the runbook depend on.

A rename here silently breaks a unit file or a documented operator step, so the
surface itself is asserted.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fakes import FakeKernel, FakeNft, FakeNic, FakeSysctl

from amnesic_pi import anon, cli, fw
from amnesic_pi.authority import Authority
from amnesic_pi.clihelp import report
from amnesic_pi.config import Config

TEMPLATE = Path("network/policy.nft.in")


def subcommands(parser) -> set[str]:
    found: set[str] = set()
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices:
            found.update(action.choices)
    return found


def test_firewall_command_exposes_apply_verify_lockdown():
    assert {"apply", "verify", "lockdown"} <= subcommands(fw.build_parser())


def test_anon_command_exposes_the_three_stages():
    assert {"randomize-mac", "verify-zero-ip", "verify-tor-path"} <= subcommands(
        anon.build_parser()
    )


def test_umbrella_keeps_the_previous_spellings_working():
    """`apply-firewall` and `verify` are documented; they must keep working."""
    parser = cli.build_parser()
    assert {"render-firewall", "apply-firewall", "verify", "firewall", "anon"} <= subcommands(
        parser
    )
    assert parser.parse_args(["apply-firewall"]).func is fw.cmd_apply


def test_legacy_verify_covers_firewall_posture_and_tor_listeners():
    """The old `amnesic-pi verify` meaning is preserved, not quietly narrowed."""
    parser = cli.build_parser()
    assert parser.parse_args(["verify"]).func is cli.cmd_verify_all
    assert parser.parse_args(["firewall", "verify"]).func is fw.cmd_verify


def test_verify_commands_do_not_require_root():
    """A read-only check must be usable without escalating."""
    parser = cli.build_parser()
    for argv in (["verify"], ["firewall", "verify"], ["anon", "verify-zero-ip"]):
        assert parser.parse_args(argv).func is not None


@pytest.mark.parametrize("argv", [["firewall", "apply"], ["firewall", "lockdown"]])
def test_mutating_commands_refuse_to_run_unprivileged(argv, monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    env = tmp_path / "network.env"
    env.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\n", encoding="utf-8")
    args = cli.build_parser().parse_args(["--config", str(env), *argv])
    assert args.func(args) == 2


def test_report_treats_observations_as_non_blocking(capsys):
    """WARN must not become FAIL, or an echo outage would block the boot."""

    class Observation:
        name, ok, detail, blocking = "echo", False, "unreachable", False

    class HardFailure:
        name, ok, detail, blocking = "nft table", False, "missing", True

    assert report([Observation()]) is True
    assert report([HardFailure()]) is False
    output = capsys.readouterr().out
    assert "WARN" in output and "FAIL" in output


def test_render_firewall_does_not_touch_the_kernel(tmp_path, capsys):
    """Reviewing the policy must be safe before any authority exists."""
    env = tmp_path / "network.env"
    env.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\n", encoding="utf-8")
    args = cli.build_parser().parse_args(
        ["--config", str(env), "--template", str(TEMPLATE), "render-firewall", "--tor-uid", "4242"]
    )
    assert args.func(args) == 0
    rendered = capsys.readouterr().out
    assert "skuid 4242" in rendered
    assert "@UPLINK_IF@" not in rendered


def test_verify_module_reports_firewall_and_listener_checks(tmp_path, monkeypatch):
    from amnesic_pi import verify as verify_module

    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={"eth0": FakeNic(address="02:00:00:00:00:01"),
              "eth1": FakeNic(address="02:00:00:00:00:02")},
    )
    authority = Authority(
        config=Config("eth0", "eth1", iface_wait_seconds=1),
        nft=FakeNft().interface(),
        sysctl=FakeSysctl.build(tmp_path / "proc"),
        interfaces=kernel.interfaces(),
        template=TEMPLATE,
        uid=4242,
    )
    monkeypatch.setattr(verify_module, "_port_open", lambda port: False)
    checks = verify_module.verify(Config("eth0", "eth1"), authority=authority)
    names = {check.name for check in checks}
    assert "nft table" in names
    assert "Tor TransPort" in names
    assert "Tor DNSPort" in names
