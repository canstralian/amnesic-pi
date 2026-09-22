import json
import subprocess

import pytest

import amnesic_pi.verify as verifier
from amnesic_pi.config import Config


def _nft_json(
    *,
    input_policy: str | None = "drop",
    forward_rule: bool = False,
    metainfo: bool = False,
) -> str:
    input_chain = {
        "family": "inet",
        "table": "amnesic_pi",
        "name": "input",
        "type": "filter",
        "hook": "input",
    }
    if input_policy is not None:
        input_chain["policy"] = input_policy

    entries: list[dict] = []
    if metainfo:
        entries.append({"metainfo": {"json_schema_version": 1}})
    entries.extend(
        [
            {"table": {"family": "inet", "name": "amnesic_pi"}},
            {"chain": input_chain},
            {
                "chain": {
                    "family": "inet",
                    "table": "amnesic_pi",
                    "name": "forward",
                    "type": "filter",
                    "hook": "forward",
                    "policy": "drop",
                }
            },
            {
                "chain": {
                    "family": "inet",
                    "table": "amnesic_pi",
                    "name": "output",
                    "type": "filter",
                    "hook": "output",
                    "policy": "drop",
                }
            },
        ]
    )
    if forward_rule:
        entries.append(
            {
                "rule": {
                    "family": "inet",
                    "table": "amnesic_pi",
                    "chain": "forward",
                    "expr": [{"accept": None}],
                }
            }
        )
    return json.dumps({"nftables": entries})


def test_chain_policies_do_not_bleed_between_chains():
    policies = verifier._chain_policies(_nft_json(input_policy="accept"))
    assert policies == {
        "input": "accept",
        "forward": "drop",
        "output": "drop",
    }


def test_absent_policy_is_treated_as_default_accept():
    policies = verifier._chain_policies(_nft_json(input_policy=None))
    assert policies["input"] == "accept"


def test_metainfo_is_ignored():
    policies = verifier._chain_policies(_nft_json(metainfo=True))
    assert policies["input"] == "drop"


@pytest.mark.parametrize("payload", [[], None, "invalid", 0, True])
def test_firewall_verifier_reports_non_object_json_as_failure(monkeypatch, payload):
    monkeypatch.setattr(
        verifier,
        "_run",
        lambda *args: subprocess.CompletedProcess(
            args, 0, stdout=json.dumps(payload), stderr=""
        ),
    )

    checks = {check.name: check for check in verifier.verify_firewall()}

    assert not checks["nft table"].ok
    assert checks["nft table"].detail == "nft JSON root must be an object"
    for name in ("input", "forward", "output"):
        assert not checks[f"{name} policy DROP"].ok


def test_firewall_verifier_rejects_any_forward_rule(monkeypatch):
    monkeypatch.setattr(
        verifier,
        "_run",
        lambda *args: subprocess.CompletedProcess(
            args,
            0,
            stdout=_nft_json(forward_rule=True),
            stderr="",
        ),
    )

    checks = {check.name: check for check in verifier.verify_firewall()}

    assert not checks["forward chain has no rules"].ok
    assert checks["forward chain has no rules"].detail == "1 rule(s)"


def test_firewall_verifier_fails_when_nft_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        verifier,
        "_run",
        lambda *args: subprocess.CompletedProcess(args, 127, stdout="", stderr="nft missing"),
    )

    checks = {check.name: check for check in verifier.verify_firewall()}

    assert not checks["nft table"].ok
    assert not checks["input policy DROP"].ok
    assert not checks["forward policy DROP"].ok
    assert not checks["output policy DROP"].ok


def test_verify_rejects_accept_even_when_following_chains_drop(monkeypatch):
    def fake_run(*args: str) -> subprocess.CompletedProcess[str]:
        if args[:2] == ("nft", "-j"):
            return subprocess.CompletedProcess(args, 0, stdout=_nft_json(input_policy="accept"), stderr="")
        if args[0] == "ss":
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n",
                stderr="",
            )
        raise AssertionError(f"unexpected command: {args!r}")

    def fake_sysctl(path: str) -> str:
        if path.endswith("/net/ipv4/ip_forward"):
            return "1"
        if path.endswith("/net/ipv6/conf/all/forwarding"):
            return "0"
        return "1"

    monkeypatch.setattr(verifier, "_run", fake_run)
    monkeypatch.setattr(verifier, "_read_sysctl", fake_sysctl)
    monkeypatch.setattr(verifier, "_port_open", lambda _port: True)

    checks = {check.name: check for check in verifier.verify(Config("eth0", "eth1"))}

    assert not checks["input policy DROP"].ok
    assert checks["input policy DROP"].detail.startswith("policy=accept")
    assert checks["forward policy DROP"].ok
    assert checks["output policy DROP"].ok
    assert checks["forward chain has no rules"].ok
    assert checks["IPv4 forwarding"].ok
    assert checks["IPv6 forwarding disabled"].ok


def test_enforced_mode_checks_effective_systemd_state(monkeypatch, tmp_path):
    requires_dir = tmp_path / "NetworkManager.service.requires"
    requires_dir.mkdir()
    (requires_dir / "amnesic-pi-firewall.service").symlink_to("../amnesic-pi-firewall.service")

    def fake_run(*args: str) -> subprocess.CompletedProcess[str]:
        if args[:2] == ("systemctl", "is-enabled"):
            return subprocess.CompletedProcess(args, 0, stdout="enabled\n", stderr="")
        if args[:3] == ("systemctl", "show", "NetworkManager.service"):
            if "--property=Requires" in args:
                stdout = "amnesic-pi-firewall.service dbus.service\n"
            else:
                stdout = "network-pre.target amnesic-pi-firewall.service\n"
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
        if args[:2] == ("systemctl", "cat"):
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="[Unit]\nBefore=NetworkManager.service\n",
                stderr="",
            )
        if args[:3] == ("systemctl", "show", "amnesic-pi-firewall.service"):
            return subprocess.CompletedProcess(args, 0, stdout="yes\n", stderr="")
        raise AssertionError(f"unexpected command: {args!r}")

    monkeypatch.setattr(verifier, "_run", fake_run)

    checks = verifier.verify_enforced_mode(tmp_path)

    assert all(check.ok for check in checks)


def test_enforced_mode_rejects_condition_skip(monkeypatch, tmp_path):
    requires_dir = tmp_path / "NetworkManager.service.requires"
    requires_dir.mkdir()
    (requires_dir / "amnesic-pi-firewall.service").symlink_to("../amnesic-pi-firewall.service")

    def fake_run(*args: str) -> subprocess.CompletedProcess[str]:
        if args[:2] == ("systemctl", "is-enabled"):
            return subprocess.CompletedProcess(args, 0, stdout="enabled\n", stderr="")
        if args[:3] == ("systemctl", "show", "NetworkManager.service"):
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="amnesic-pi-firewall.service\n",
                stderr="",
            )
        if args[:2] == ("systemctl", "cat"):
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="[Unit]\nConditionPathExists=/run/unsafe-skip\n",
                stderr="",
            )
        if args[:3] == ("systemctl", "show", "amnesic-pi-firewall.service"):
            return subprocess.CompletedProcess(args, 0, stdout="yes\n", stderr="")
        raise AssertionError(f"unexpected command: {args!r}")

    monkeypatch.setattr(verifier, "_run", fake_run)

    checks = {check.name: check for check in verifier.verify_enforced_mode(tmp_path)}

    assert not checks["firewall has no Condition skip"].ok
