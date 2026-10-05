"""Regression coverage for post-Tor egress posture verification.

Two properties matter here and neither is about Tor working:

1. Hard security gates and observational telemetry are different things. A
   third-party echo service being unreachable is an outage. It must not be
   reported as a clearnet leak, and must not decide readiness.
2. Exit-IP rotation is not a security invariant. Successive Tor circuits are
   not guaranteed to use distinct exits, so asserting uniqueness would make
   the release gate depend on something Tor does not promise.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from fakes import FakeKernel, FakeNft, FakeNic, FakeSysctl

from amnesic_pi import torpath
from amnesic_pi.authority import Authority
from amnesic_pi.config import Config
from amnesic_pi.torpath import Kind, PostureCheck, TorPathError, _external_address_check

TEMPLATE = Path("network/policy.nft.in")


def build_authority(tmp_path: Path, uplink_addresses: list[str] | None = None) -> Authority:
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address="02:00:00:00:00:01", addresses=uplink_addresses or []),
            "eth1": FakeNic(address="02:00:00:00:00:02"),
        },
    )
    return Authority(
        config=Config("eth0", "eth1", iface_wait_seconds=1),
        nft=FakeNft().interface(),
        sysctl=FakeSysctl.build(tmp_path / "proc"),
        interfaces=kernel.interfaces(),
        template=TEMPLATE,
        uid=4242,
    )


# -- hard gates versus telemetry -------------------------------------------


def test_a_hard_failure_blocks_readiness():
    assert PostureCheck("nft table", False, "missing", Kind.HARD).blocking


def test_an_observation_failure_does_not_block_readiness():
    assert not PostureCheck("echo", False, "unreachable", Kind.OBSERVED).blocking


def test_echo_outage_is_reported_but_does_not_block(tmp_path: Path, monkeypatch):
    """An unreachable echo service is an outage, not proof of a leak."""
    config = Config("eth0", "eth1", egress_echo_host="echo.example")
    monkeypatch.setattr(
        torpath,
        "observe_external_address",
        lambda *a, **k: (_ for _ in ()).throw(TorPathError("connection refused")),
    )
    check = _external_address_check(config, build_authority(tmp_path), False, 5.0)
    assert check.kind is Kind.OBSERVED
    assert not check.blocking
    assert "outage" in check.detail


def test_echo_outage_can_be_promoted_to_a_gate_for_hardware_testing(
    tmp_path: Path, monkeypatch
):
    """Release testing on hardware may demand the observation; boot must not."""
    config = Config("eth0", "eth1", egress_echo_host="echo.example")
    monkeypatch.setattr(
        torpath,
        "observe_external_address",
        lambda *a, **k: (_ for _ in ()).throw(TorPathError("connection refused")),
    )
    check = _external_address_check(config, build_authority(tmp_path), True, 5.0)
    assert check.blocking


def test_observing_our_own_address_is_a_hard_leak_signal(tmp_path: Path, monkeypatch):
    """Telemetry fails hard on a positive leak signal, whatever the mode."""
    config = Config("eth0", "eth1", egress_echo_host="echo.example")
    authority = build_authority(tmp_path, uplink_addresses=["inet 203.0.113.9/24"])
    monkeypatch.setattr(torpath, "observe_external_address", lambda *a, **k: "203.0.113.9")
    check = _external_address_check(config, authority, False, 5.0)
    assert check.kind is Kind.HARD
    assert check.blocking
    assert "leak" in check.detail


def test_a_distinct_external_address_passes_as_telemetry(tmp_path: Path, monkeypatch):
    config = Config("eth0", "eth1", egress_echo_host="echo.example")
    authority = build_authority(tmp_path, uplink_addresses=["inet 203.0.113.9/24"])
    monkeypatch.setattr(torpath, "observe_external_address", lambda *a, **k: "198.51.100.7")
    check = _external_address_check(config, authority, False, 5.0)
    assert check.ok
    assert check.kind is Kind.OBSERVED


def test_telemetry_is_disabled_by_default(tmp_path: Path):
    """No echo host configured means no third-party dependency at boot."""
    check = _external_address_check(Config("eth0", "eth1"), build_authority(tmp_path), False, 5.0)
    assert check.ok
    assert check.kind is Kind.OBSERVED
    assert "disabled" in check.detail


def test_verify_tor_path_reports_hard_failures_when_tor_is_absent(tmp_path: Path):
    """With no Tor listening, the hard gates fail and readiness is withheld."""
    authority = build_authority(tmp_path)
    checks = torpath.verify_tor_path(
        Config("eth0", "eth1", trans_port=1, socks_port=2, dns_port=3),
        authority,
        timeout=0.2,
    )
    assert any(check.blocking for check in checks)
    names = {check.name for check in checks if check.blocking}
    assert any("Tor" in name for name in names)


# -- bounded retry for Tor's own bootstrap timing --------------------------


class FakeClock:
    """Injectable monotonic clock. Only advances when told to."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, by: float) -> None:
        self.now += by


def _checker_sequence(*results: list[PostureCheck]):
    """A fake `verify_tor_path`: returns each result in order, then repeats
    the last one. Records how many times it was called."""
    calls: list[int] = []
    sequence = iter(results)

    def checker(config, authority, require_observation, probe_timeout):
        calls.append(1)
        try:
            return next(sequence)
        except StopIteration:
            return results[-1]

    checker.calls = calls
    return checker


def test_wait_for_tor_path_returns_immediately_on_first_success(tmp_path: Path):
    """A transient retry loop must not slow down the common case."""
    authority = build_authority(tmp_path)
    passing = [PostureCheck("Tor bootstrapped", True, "ok")]
    checker = _checker_sequence(passing)
    slept: list[float] = []

    result = torpath.wait_for_tor_path(
        Config("eth0", "eth1"),
        authority,
        checker=checker,
        clock=FakeClock(),
        sleep=slept.append,
        wait_seconds=10.0,
    )

    assert result == passing
    assert len(checker.calls) == 1
    assert slept == []


def test_wait_for_tor_path_retries_until_success_within_budget(tmp_path: Path):
    """Tor not having bootstrapped yet must be absorbed, not surfaced."""
    authority = build_authority(tmp_path)
    failing = [PostureCheck("Tor bootstrapped", False, "not yet")]
    passing = [PostureCheck("Tor bootstrapped", True, "ok")]
    checker = _checker_sequence(failing, failing, passing)
    slept: list[float] = []

    result = torpath.wait_for_tor_path(
        Config("eth0", "eth1"),
        authority,
        checker=checker,
        clock=FakeClock(),
        sleep=slept.append,
        wait_seconds=10.0,
        poll=2.0,
    )

    assert result == passing
    assert len(checker.calls) == 3
    assert slept == [2.0, 2.0]


def test_wait_for_tor_path_exhausts_the_budget_and_returns_the_last_failure(tmp_path: Path):
    """A sustained failure must still fail -- the retry is bounded, not a loop."""
    authority = build_authority(tmp_path)
    failing = [PostureCheck("Tor bootstrapped", False, "still not ready")]
    checker = _checker_sequence(failing, failing, failing, failing, failing)
    clock = FakeClock()

    result = torpath.wait_for_tor_path(
        Config("eth0", "eth1"),
        authority,
        checker=checker,
        clock=clock,
        sleep=clock.advance,
        wait_seconds=5.0,
        poll=3.0,
    )

    assert result == failing
    assert any(check.blocking for check in result)
    # t=0 (fail, sleep->3), t=3 (fail, sleep->6), t=6 (deadline 5 already passed): 3 calls.
    assert len(checker.calls) == 3


def test_wait_for_tor_path_defaults_its_budget_to_the_configured_value(tmp_path: Path):
    """With no explicit `wait_seconds`, the budget comes from the config."""
    authority = build_authority(tmp_path)
    failing = [PostureCheck("Tor bootstrapped", False, "not yet")]
    checker = _checker_sequence(failing, failing, failing)
    clock = FakeClock()

    torpath.wait_for_tor_path(
        Config("eth0", "eth1", tor_wait_seconds=7.0),
        authority,
        checker=checker,
        clock=clock,
        sleep=clock.advance,
        poll=7.0,
    )

    # t=0 (fail, sleep->7), t=7 (deadline 7 reached): 2 calls. A hardcoded
    # function-level default would not produce this number.
    assert len(checker.calls) == 2


# -- exit-IP rotation is not an invariant ----------------------------------


def test_no_exit_ip_uniqueness_assertion_exists():
    """Successive circuits are not guaranteed to use distinct exits.

    Stream isolation makes a fresh circuit likely, not a fresh relay. Making
    "different exit every request" a release gate would fail the build on Tor
    behaving exactly as documented.
    """
    tree = ast.parse(inspect.getsource(torpath))

    def is_len_of_set(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "len"
            and node.args
            and isinstance(node.args[0], ast.Call)
            and getattr(node.args[0].func, "id", None) == "set"
        )

    for node in ast.walk(tree):
        # The specific anti-pattern: len(set(exit_ips)) == len(exit_ips).
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            assert not any(is_len_of_set(operand) for operand in operands), (
                "torpath compares the size of a set of observations against the "
                "number of observations; exit-IP uniqueness is not a Tor guarantee "
                "and must not be a release gate"
            )
        # And no identifier that would only exist to track rotation.
        if isinstance(node, ast.Name):
            lowered = node.id.lower()
            assert "exit_ip" not in lowered and "rotat" not in lowered, (
                f"torpath tracks {node.id!r}; exit rotation is telemetry, not an invariant"
            )


def test_no_outer_tunnel_is_introduced():
    """Stage 1's scope is MAC, local authority, Tor and Tor-path verification.

    An outer VPN or proxy rotator would change the threat model, so it must not
    appear here by accident.
    """
    source = inspect.getsource(torpath).lower()
    for token in ("openvpn", "wireguard", "vpn", "rotator", "proxychains"):
        assert token not in source, f"torpath references {token!r}, which is out of Stage 1 scope"


# -- protocol helpers ------------------------------------------------------


def test_dns_query_is_well_formed():
    query = torpath.build_dns_query("example.com", transaction_id=0xABCD)
    assert query[:2] == b"\xab\xcd"
    assert b"\x07example\x03com\x00" in query
    assert query[-4:] == b"\x00\x01\x00\x01"


def test_dns_rcode_failure_is_surfaced():
    # Header with rcode 3 (NXDOMAIN) and no answers.
    response = b"\xab\xcd" + b"\x81\x83" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00\x00\x00"
    with pytest.raises(TorPathError, match="rcode 3"):
        torpath.dns_answer_count(response)


def test_dns_answer_count_is_read_from_the_header():
    response = b"\xab\xcd" + b"\x81\x80" + b"\x00\x01" + b"\x00\x02" + b"\x00\x00\x00\x00"
    assert torpath.dns_answer_count(response) == 2


def test_tor_dns_proof_is_not_claimed_to_prevent_direct_dns():
    """The DNSPort check proves Tor resolves; it does not prove nothing else can.

    Preventing non-Tor DNS is an nftables invariant, asserted in the policy
    checks and the namespace tests. The module must say so rather than let the
    two claims blur.
    """
    doc = torpath.__doc__ or ""
    assert "nftables invariant" in doc
