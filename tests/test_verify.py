import json
import subprocess

import amnesic_pi.verify as verifier
from amnesic_pi.config import Config


def _nft_json(*, input_policy: str = "drop") -> str:
    return json.dumps(
        {
            "nftables": [
                {"table": {"family": "inet", "name": "amnesic_pi"}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "amnesic_pi",
                        "name": "input",
                        "type": "filter",
                        "hook": "input",
                        "policy": input_policy,
                    }
                },
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
        }
    )


def test_chain_policies_do_not_bleed_between_chains():
    policies = verifier._chain_policies(_nft_json(input_policy="accept"))
    assert policies == {
        "input": "accept",
        "forward": "drop",
        "output": "drop",
    }


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
            return "0"
        return "1"

    monkeypatch.setattr(verifier, "_run", fake_run)
    monkeypatch.setattr(verifier, "_read_sysctl", fake_sysctl)
    monkeypatch.setattr(verifier, "_port_open", lambda _port: True)

    checks = {check.name: check for check in verifier.verify(Config("eth0", "eth1"))}

    assert not checks["input policy DROP"].ok
    assert checks["input policy DROP"].detail == "accept"
    assert checks["forward policy DROP"].ok
    assert checks["output policy DROP"].ok
    assert checks["IPv4 forwarding disabled"].ok
