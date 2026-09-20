import argparse
import os
import subprocess
from pathlib import Path

from amnesic_pi import cli


def _args(tmp_path: Path) -> argparse.Namespace:
    config = tmp_path / "network.env"
    config.write_text("UPLINK_IF=eth0\nCLIENT_IF=eth1\n")
    template = tmp_path / "policy.nft.in"
    template.write_text(Path("network/policy.nft.in").read_text())
    return argparse.Namespace(config=config, template=template)


def _fake_run(returncodes):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        rc = returncodes[len(calls) - 1] if len(calls) <= len(returncodes) else 0
        return subprocess.CompletedProcess(argv, rc, "", "")

    return run, calls


def test_apply_enables_forwarding_only_after_nft_apply_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "tor_uid", lambda config: 4242)
    # table-present check, nft -c, nft -f: all succeed.
    run, calls = _fake_run([1, 0, 0])
    monkeypatch.setattr(cli.subprocess, "run", run)

    enabled = []
    monkeypatch.setattr(cli, "enable_ipv4_forwarding", lambda: enabled.append(True))

    rc = cli.cmd_apply(_args(tmp_path))

    assert rc == 0
    assert enabled == [True]


def test_apply_never_enables_forwarding_when_nft_validation_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "tor_uid", lambda config: 4242)
    # table-present check, nft -c fails: nft -f must never run.
    run, calls = _fake_run([1, 1])
    monkeypatch.setattr(cli.subprocess, "run", run)

    enabled = []
    monkeypatch.setattr(cli, "enable_ipv4_forwarding", lambda: enabled.append(True))

    rc = cli.cmd_apply(_args(tmp_path))

    assert rc == 1
    assert enabled == []
    assert len(calls) == 2, "nft -f must not run after nft -c fails"


def test_apply_never_enables_forwarding_when_nft_apply_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "tor_uid", lambda config: 4242)
    # table-present check, nft -c succeeds, nft -f fails.
    run, calls = _fake_run([1, 0, 1])
    monkeypatch.setattr(cli.subprocess, "run", run)

    enabled = []
    monkeypatch.setattr(cli, "enable_ipv4_forwarding", lambda: enabled.append(True))

    rc = cli.cmd_apply(_args(tmp_path))

    assert rc == 1
    assert enabled == []
