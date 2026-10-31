"""Negative properties for interrupted and partially verified activation."""

from __future__ import annotations

import argparse
import signal
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from fakes import FakeKernel, FakeNic
from test_authority import build

from amnesic_pi import anon, cli, clihelp, fw, netif, torpath
from amnesic_pi.authority import AuthorityError, Check
from amnesic_pi.config import Config, ConfigError
from amnesic_pi.mac import MacError, randomize_interface
from amnesic_pi.nft import Nft
from amnesic_pi.sysctl import (
    IPV4_FORWARD,
    IPV6_DISABLE_ALL,
    IPV6_DISABLE_DEFAULT,
    Sysctl,
    SysctlError,
)


@pytest.mark.parametrize("rule", ["jump relay", "goto relay", "meta l4proto vmap { udp : jump relay }"])
def test_indirect_forwarding_grants_are_refused(tmp_path: Path, rule: str):
    harness = build(tmp_path)
    template = Path("network/policy.nft.in").read_text()
    template = template.replace(
        "type filter hook forward priority filter; policy drop;",
        f"type filter hook forward priority filter; policy drop;\n        {rule}",
    ).replace("    chain output {", "    chain relay {\n        accept\n    }\n\n    chain output {")
    candidate = tmp_path / "indirect.nft.in"
    candidate.write_text(template)
    authority = replace(harness.authority, template=candidate)

    with pytest.raises(AuthorityError, match="forward"):
        authority.apply()

    assert authority.sysctl.read(IPV4_FORWARD) == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables


@pytest.mark.parametrize("knob", [IPV6_DISABLE_ALL, IPV6_DISABLE_DEFAULT])
def test_unreadable_ipv6_posture_returns_a_failed_containment_report(tmp_path: Path, knob: str):
    harness = build(tmp_path)
    harness.authority.apply()
    path = harness.authority.sysctl.root / knob
    path.mkdir(parents=True)

    checks = harness.authority.lockdown()

    assert any(check.name == knob and not check.ok for check in checks)
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, OSError])
def test_interruption_after_forwarding_grant_is_contained(tmp_path: Path, monkeypatch, interruption):
    harness = build(tmp_path)
    write = Sysctl.write

    def interrupted(self, knob, value):
        write(self, knob, value)
        if knob == IPV4_FORWARD and value == "1":
            raise interruption("injected interruption after grant")

    monkeypatch.setattr(Sysctl, "write", interrupted)
    expected = KeyboardInterrupt if interruption is KeyboardInterrupt else AuthorityError
    with pytest.raises(expected):
        harness.authority.apply()

    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables


def test_failed_cli_recheck_revokes_forwarding(tmp_path: Path, monkeypatch, capsys):
    harness = build(tmp_path)

    class Drifted:
        def apply(self):
            harness.authority.apply()

        def verify(self):
            return [Check("post-grant posture", False, "injected drift")]

        def lockdown(self):
            return harness.authority.lockdown()

    monkeypatch.setattr(fw, "authority_for", lambda args: Drifted())
    monkeypatch.setattr(fw, "require_root", lambda command: None)

    assert fw.cmd_apply(argparse.Namespace()) == 1
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi_lockdown" in harness.tables
    assert "locked down" in capsys.readouterr().err


def test_unexpected_cli_recheck_error_is_contained(tmp_path, monkeypatch):
    harness = build(tmp_path)

    class Unreadable:
        def apply(self):
            harness.authority.apply()

        def verify(self):
            raise OSError("live policy unreadable")

        def lockdown(self):
            return harness.authority.lockdown()

    monkeypatch.setattr(fw, "authority_for", lambda args: Unreadable())
    monkeypatch.setattr(fw, "require_root", lambda command: None)
    assert fw.cmd_apply(argparse.Namespace()) == 1
    assert harness.forwarding[IPV4_FORWARD] == "0"


def test_lockdown_reports_temporary_file_failure_without_removing_policy(tmp_path, monkeypatch):
    harness = build(tmp_path)
    harness.authority.apply()

    def no_space(*args):
        raise OSError("no space for nft transaction file")

    monkeypatch.setattr(Nft, "load", no_space)
    checks = harness.authority.lockdown()
    assert any(check.name == "deny posture installed" and not check.ok for check in checks)
    assert harness.forwarding[IPV4_FORWARD] == "0"
    assert "inet amnesic_pi" in harness.tables


def test_ignored_mac_change_never_raises_the_link(tmp_path: Path):
    kernel = FakeKernel(tmp_path / "net", {"eth0": FakeNic("b8:27:eb:11:22:33", accepts_mac_change=False)})
    run = kernel.run
    raised = []

    def observe(argv):
        if list(argv)[-1] == "up":
            raised.append(True)
        return run(argv)

    kernel.run = observe
    with pytest.raises(MacError):
        randomize_interface("eth0", kernel.interfaces(), 1)
    assert not raised, "the unverified burned-in address was briefly placed on an active link"


def test_entropy_failure_leaves_the_interface_down(tmp_path: Path):
    kernel = FakeKernel(tmp_path / "net", {"eth0": FakeNic("b8:27:eb:11:22:33", up=True)})

    def unavailable(count):
        raise OSError("entropy unavailable")

    with pytest.raises(MacError, match="entropy"):
        randomize_interface("eth0", kernel.interfaces(), 1, entropy=unavailable)
    assert not kernel.nics["eth0"].up


def test_one_failed_mac_revokes_the_other_interfaces_link(tmp_path: Path, monkeypatch):
    kernel = FakeKernel(tmp_path / "net", {
        "eth0": FakeNic("b8:27:eb:11:22:33"),
        "eth1": FakeNic("b8:27:eb:11:22:44", accepts_mac_change=False),
    })
    env = tmp_path / "network.env"
    env.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\n")
    monkeypatch.setattr(anon, "require_root", lambda command: None)
    monkeypatch.setattr(netif.NetworkInterfaces, "default", lambda: kernel.interfaces())

    assert anon.cmd_randomize_mac(argparse.Namespace(config=env)) == 1
    assert not any(nic.up for nic in kernel.nics.values())


@pytest.mark.parametrize("uplink,client", [("lo", "eth1"), ("eth0", "lo")])
def test_loopback_cannot_be_a_network_role(uplink, client):
    with pytest.raises(ConfigError, match="loopback"):
        Config(uplink, client).validate()


def test_hung_kernel_command_returns_a_timeout_failure(monkeypatch):
    def timed_out(argv, **kwargs):
        assert 0 < kwargs["timeout"] <= 10
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timed_out)
    result = netif.Runner.default().run(["nft", "list", "ruleset"])
    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_optional_knob_write_error_is_not_treated_as_absence(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError("procfs inaccessible")

    monkeypatch.setattr(Path, "write_text", denied)
    monkeypatch.setattr(Path, "exists", lambda self: False)
    with pytest.raises(SysctlError, match="cannot write"):
        Sysctl(root=tmp_path).write(IPV6_DISABLE_ALL, "1")


def test_socks_fields_share_one_deadline():
    class Trickle:
        def __init__(self):
            self.now = 0.0
            self.timeouts = []

        def settimeout(self, seconds):
            self.timeouts.append(seconds)

        def recv(self, count):
            self.now += 0.4
            return b"x"

    peer = Trickle()
    with pytest.raises(torpath.TorPathError, match="deadline"):
        torpath._recv_exact(peer, 10, deadline=1.0, clock=lambda: peer.now)
    assert peer.now <= 1.2 + 1e-9
    assert peer.timeouts == pytest.approx([1.0, 0.6, 0.2])


def test_failed_firewall_posture_never_probes_the_network(tmp_path: Path, monkeypatch):
    harness = build(tmp_path)  # no policy has been installed

    def forbidden(*args, **kwargs):
        pytest.fail("a failed firewall gate must not proceed to network probes")

    monkeypatch.setattr(torpath, "_tcp_probe", forbidden)
    monkeypatch.setattr(torpath, "resolve_via_tor_dns", forbidden)
    checks = torpath.verify_tor_path(Config("eth0", "eth1"), harness.authority)
    assert any(check.blocking for check in checks)
    assert all(not check.retryable for check in checks if check.blocking)


def test_security_failure_is_not_retried_as_a_bootstrap_delay(tmp_path: Path):
    harness = build(tmp_path)
    calls = []
    failure = torpath.PostureCheck("firewall", False, "unsafe", retryable=False)

    def checker(*args):
        calls.append(True)
        return [failure]

    result = torpath.wait_for_tor_path(Config("eth0", "eth1"), harness.authority, checker=checker)
    assert result == [failure]
    assert len(calls) == 1


@pytest.mark.parametrize("contain", [False, True])
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_signal_keeps_readonly_commands_readonly_and_contains_activation(monkeypatch, contain, signum):
    cleaned = []

    def interrupted(args):
        signal.raise_signal(signum)

    monkeypatch.setattr(clihelp, "lockdown", lambda *args: cleaned.append(True) or [Check("deny", True, "installed")], raising=False)
    monkeypatch.setattr(clihelp.os, "geteuid", lambda: 0)
    previous = signal.getsignal(signum)
    code = clihelp.dispatch(argparse.Namespace(func=interrupted), contain_on_interrupt=contain)
    assert code == 128 + signum
    assert bool(cleaned) == contain
    assert signal.getsignal(signum) == previous


def test_second_termination_does_not_interrupt_containment(monkeypatch):
    def interrupted(args):
        signal.raise_signal(signal.SIGTERM)

    completed = []

    def cleanup(*args):
        signal.raise_signal(signal.SIGTERM)
        completed.append(True)
        return [Check("deny", True, "installed")]

    monkeypatch.setattr(clihelp, "lockdown", cleanup)
    monkeypatch.setattr(clihelp.os, "geteuid", lambda: 0)
    assert clihelp.dispatch(argparse.Namespace(func=interrupted), contain_on_interrupt=True) == 143
    assert completed


@pytest.mark.parametrize("module,argv", [
    (fw, ["verify"]), (anon, ["verify-zero-ip"]), (anon, ["verify-tor-path"]),
    (cli, ["verify"]), (cli, ["firewall", "verify"]),
    (cli, ["anon", "verify-zero-ip"]), (cli, ["anon", "verify-tor-path"]),
])
def test_verification_entrypoints_do_not_install_mutating_signal_cleanup(monkeypatch, module, argv):
    def dispatch(args, *, contain_on_interrupt):
        assert not contain_on_interrupt
        return 0

    monkeypatch.setattr(module, "dispatch", dispatch)
    assert module.main(argv) == 0
