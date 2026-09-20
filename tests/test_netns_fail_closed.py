"""Packet-level fail-closed proof using Linux network namespaces.

For every pre-ready failure boundary, the failure is injected, the client sends
traffic, and the uplink namespace must observe ZERO packets from the client
subnet. The assertion is a packet count in another namespace, not a mocked
`subprocess.run` -- these tests would catch a transaction that ran all the
right commands and ignored their results.

They need root and network-namespace support, and skip otherwise. The skip is
loud: `pytest -m netns` fails rather than skips if the environment cannot run
them, so a CI change that quietly drops this coverage is visible.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import netns
import pytest

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "network" / "policy.nft.in"

_available, _reason = netns.available()
pytestmark = [
    pytest.mark.netns,
    pytest.mark.skipif(not _available, reason=_reason or "namespace tests unavailable"),
]


def write_env(
    tmp_path: Path, topology: netns.Topology, filename: str = "network.env", **overrides: str
) -> Path:
    values = {
        "UPLINK_IF": topology.uplink_if,
        "CLIENT_IF": topology.client_if,
        # Any existing account works; the policy only needs a real UID to bind
        # the uplink TCP grant to.
        "TOR_USER": "nobody",
        "IFACE_WAIT_SECONDS": "2",
    }
    values.update(overrides)
    path = tmp_path / filename
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    return path


def firewall(
    topology: netns.Topology,
    env: Path,
    *args: str,
    template: Path = TEMPLATE,
) -> subprocess.CompletedProcess[str]:
    """Run the real amnesic-pi-firewall CLI inside the gateway namespace."""
    return subprocess.run(
        [
            "ip", "netns", "exec", topology.gateway_ns,
            "python3", "-m", "amnesic_pi.fw",
            "--config", str(env),
            "--template", str(template),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
    )


def gateway_forwarding(topology: netns.Topology) -> str:
    return topology.exec(
        topology.gateway_ns, ["cat", "/proc/sys/net/ipv4/ip_forward"]
    ).stdout.strip()


def assert_no_clearnet(topology: netns.Topology, context: str) -> None:
    """Send client traffic and require the uplink to observe none of it."""
    topology.client_sends()
    topology.client_sends(port=80)
    topology.client_sends_udp()
    leaked = topology.uplink_packets_from_client()
    assert leaked == 0, f"{context}: {leaked} client packet(s) reached the uplink"


@pytest.fixture
def topology():
    built = netns.Topology(tag=uuid.uuid4().hex[:6]).build()
    try:
        yield built
    finally:
        built.destroy()


# -- the harness itself ----------------------------------------------------


def test_harness_detects_a_real_leak(topology: netns.Topology):
    """Positive control.

    Without this, every "zero packets" assertion below could be passing because
    the harness cannot see packets at all. Forwarding on and no policy is
    exactly the pre-fix failure mode, and it must show up as a leak.
    """
    topology.set_forwarding("1")
    topology.client_sends()
    assert topology.uplink_packets_from_client() > 0, "the leak detector is not working"


# -- the successful path still denies clearnet forwarding ------------------


def test_successful_apply_grants_forwarding_without_a_clearnet_path(
    topology: netns.Topology, tmp_path: Path
):
    """Even fully applied and with forwarding on, clients get no clearnet route.

    Forwarding is granted because the transaction verified the policy; the
    policy redirects client TCP into Tor's TransPort and drops everything in
    the forward chain. Tor is absent here, so the redirect goes nowhere -- and
    nowhere is the correct answer.
    """
    env = write_env(tmp_path, topology)
    result = firewall(topology, env, "apply")
    assert result.returncode == 0, result.stdout + result.stderr
    assert gateway_forwarding(topology) == "1"
    assert_no_clearnet(topology, "policy applied, Tor absent")


def test_verify_passes_against_the_live_kernel(topology: netns.Topology, tmp_path: Path):
    env = write_env(tmp_path, topology)
    assert firewall(topology, env, "apply").returncode == 0
    verify = firewall(topology, env, "verify")
    assert verify.returncode == 0, verify.stdout + verify.stderr


# -- failure injection -----------------------------------------------------


def test_topology_failure_denies_forwarding(topology: netns.Topology, tmp_path: Path):
    """An interface that never appears must stop the transaction."""
    env = write_env(tmp_path, topology, CLIENT_IF="ap-does-not-exist")
    result = firewall(topology, env, "apply")
    assert result.returncode != 0
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "topology failure")


def test_unparsable_config_denies_forwarding(topology: netns.Topology, tmp_path: Path):
    """A configuration parse failure must not grant authority either."""
    env = tmp_path / "broken.env"
    env.write_text("UPLINK_IF=eth0\nNOT_A_KEY=1\n", encoding="utf-8")
    result = firewall(topology, env, "apply")
    assert result.returncode != 0
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "configuration failure")


def test_nftables_apply_failure_denies_forwarding(topology: netns.Topology, tmp_path: Path):
    """A policy nft refuses must leave the appliance unable to forward."""
    broken = tmp_path / "broken.nft.in"
    broken.write_text(
        "table inet amnesic_pi {\n"
        "    chain forward {\n"
        "        type filter hook forward priority filter; policy drop;\n"
        "        this is not valid nftables syntax @UPLINK_IF@ @CLIENT_IF@\n"
        "        @TRANS_PORT@ @DNS_PORT@ @TOR_UID@\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    result = firewall(topology, env := write_env(tmp_path, topology), "apply", template=broken)
    assert result.returncode != 0
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "nftables apply failure")
    assert env.exists()


def test_nftables_verification_failure_denies_forwarding(
    topology: netns.Topology, tmp_path: Path
):
    """The decisive case: the policy installs cleanly but fails verification.

    This is syntactically valid nftables that nft will happily load, and whose
    forward chain defaults to ACCEPT. Verification must catch it, and
    forwarding must never be granted -- otherwise a policy that looks applied
    would carry full routing authority.
    """
    permissive = tmp_path / "permissive.nft.in"
    permissive.write_text(
        "table inet amnesic_pi {\n"
        "    chain prerouting {\n"
        "        type nat hook prerouting priority dstnat; policy accept;\n"
        '        iifname "@CLIENT_IF@" udp dport 53 redirect to :@DNS_PORT@\n'
        '        iifname "@CLIENT_IF@" meta l4proto tcp redirect to :@TRANS_PORT@\n'
        "    }\n"
        "    chain input {\n"
        "        type filter hook input priority filter; policy drop;\n"
        "    }\n"
        "    chain forward {\n"
        "        type filter hook forward priority filter; policy accept;\n"
        "    }\n"
        "    chain output {\n"
        "        type filter hook output priority filter; policy drop;\n"
        '        oifname "@UPLINK_IF@" meta skuid @TOR_UID@ meta l4proto tcp accept\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    env = write_env(tmp_path, topology)
    result = firewall(topology, env, "apply", template=permissive)
    assert result.returncode != 0, "a default-ACCEPT forward chain passed verification"
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "policy verification failure")


def test_lockdown_closes_a_running_appliance(topology: netns.Topology, tmp_path: Path):
    """The teardown path: what systemd runs on stop, failure and shutdown."""
    env = write_env(tmp_path, topology)
    assert firewall(topology, env, "apply").returncode == 0
    assert gateway_forwarding(topology) == "1"

    lockdown = firewall(topology, env, "lockdown")
    assert lockdown.returncode == 0, lockdown.stdout + lockdown.stderr
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "after lockdown")


def test_lockdown_is_idempotent_against_the_live_kernel(
    topology: netns.Topology, tmp_path: Path
):
    env = write_env(tmp_path, topology)
    assert firewall(topology, env, "apply").returncode == 0
    for attempt in range(3):
        result = firewall(topology, env, "lockdown")
        assert result.returncode == 0, f"lockdown {attempt} failed: {result.stdout}"
        assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "after repeated lockdown")


def test_no_transaction_means_no_forwarding(topology: netns.Topology):
    """The pre-anon state: nothing has run yet, so nothing may forward."""
    assert gateway_forwarding(topology) == "0"
    assert_no_clearnet(topology, "before any stage has run")


# -- the preserved regression ---------------------------------------------


def test_forwarding_is_never_left_on_by_a_failed_transaction(
    topology: netns.Topology, tmp_path: Path
):
    """The state "firewall unavailable + forwarding enabled" must be unreachable.

    That combination used to be producible at boot: the firewall unit failed,
    systemd-sysctl enabled forwarding regardless, and clearnet forwarding
    remained possible. Forwarding authority now lives only inside the
    transaction, so every failure path is checked for it here.
    """
    # Start from the worst case: forwarding already on from a previous state.
    topology.set_forwarding("1")

    broken = tmp_path / "broken.nft.in"
    broken.write_text("this is not nftables @UPLINK_IF@@CLIENT_IF@@TRANS_PORT@@DNS_PORT@@TOR_UID@\n")

    # Distinct filenames: a shared path would let the second scenario's config
    # silently overwrite the first's before either ran.
    scenarios = {
        "missing interface": (
            write_env(tmp_path, topology, filename="absent.env", CLIENT_IF="ap-absent"),
            TEMPLATE,
        ),
        "invalid policy": (write_env(tmp_path, topology, filename="valid.env"), broken),
    }
    for name, (env, template) in scenarios.items():
        topology.set_forwarding("1")
        result = firewall(topology, env, "apply", template=template)
        assert result.returncode != 0, f"{name} did not fail"
        assert gateway_forwarding(topology) == "0", (
            f"{name}: the transaction failed but left forwarding enabled"
        )
        assert_no_clearnet(topology, name)


def test_client_udp_never_reaches_the_uplink(topology: netns.Topology, tmp_path: Path):
    """Stage 1 gives downstream UDP no path out, QUIC included."""
    env = write_env(tmp_path, topology)
    assert firewall(topology, env, "apply").returncode == 0
    for port in (53, 443, 123):
        topology.client_sends_udp(port=port)
    leaked = topology.uplink_packets_from_client()
    assert leaked == 0, f"{leaked} downstream UDP packet(s) reached the uplink"
