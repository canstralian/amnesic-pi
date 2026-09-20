"""Regression coverage for the pre-network anonymity gate.

Every test here is about behaviour the threat model depends on: an address that
cannot be linked back to the device, a change that is proven to have taken
effect, and a hard failure whenever either of those cannot be established.
"""

from __future__ import annotations

import ast
import inspect
import os
import re
from pathlib import Path

import pytest
from fakes import FakeKernel, FakeNic, fixed_entropy

from amnesic_pi import anon, mac, netif
from amnesic_pi.mac import (
    LOCALLY_ADMINISTERED_BIT,
    MULTICAST_BIT,
    MacError,
    generate_mac,
    is_locally_administered,
    is_unicast,
    randomize_interface,
)

BURNED_IN = "b8:27:eb:11:22:33"


@pytest.fixture
def kernel(tmp_path: Path) -> FakeKernel:
    return FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, permanent=BURNED_IN),
            "eth1": FakeNic(address="00:e0:4c:aa:bb:cc", permanent="00:e0:4c:aa:bb:cc"),
        },
    )


def write_env(tmp_path: Path, **overrides: str) -> Path:
    values = {"UPLINK_IF": "eth0", "CLIENT_IF": "eth1", "IFACE_WAIT_SECONDS": "5"}
    values.update(overrides)
    path = tmp_path / "network.env"
    path.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    return path


# -- address properties ----------------------------------------------------


def test_generated_mac_is_unicast_and_locally_administered():
    for _ in range(256):
        address = generate_mac()
        assert is_unicast(address), f"{address} is a multicast address"
        assert is_locally_administered(address), f"{address} is not locally administered"


def test_generated_mac_bit_handling_is_exact():
    # Worst case for the bit maths: every bit set, then every bit clear.
    assert generate_mac(entropy=fixed_entropy(b"\xff" * 6)) == "fe:ff:ff:ff:ff:ff"
    assert generate_mac(entropy=fixed_entropy(b"\x00\x11\x22\x33\x44\x55")) == "02:11:22:33:44:55"


def test_generated_mac_defaults_to_os_urandom():
    """The entropy source must be cryptographic, not derived or seeded.

    A MAC derived from machine-id, hostname, wall-clock time or persistent
    state would be stable across boots and therefore linkable -- which is the
    property randomization exists to remove.
    """
    default = inspect.signature(generate_mac).parameters["entropy"].default
    assert default is os.urandom


def test_generated_mac_does_not_depend_on_persistent_state():
    """Two generators fed different entropy must not converge.

    This is the observable form of "no machine-id, no hostname, no clock": with
    the entropy source pinned, the output is a pure function of that source and
    of nothing else the host provides.
    """
    first = generate_mac(entropy=fixed_entropy(b"\x01\x02\x03\x04\x05\x06"))
    second = generate_mac(entropy=fixed_entropy(b"\x0a\x0b\x0c\x0d\x0e\x0f"))
    assert first != second
    # Same entropy, same result: nothing else leaks into the address.
    assert first == generate_mac(entropy=fixed_entropy(b"\x01\x02\x03\x04\x05\x06"))


def test_generated_macs_vary_across_calls():
    addresses = {generate_mac() for _ in range(64)}
    assert len(addresses) > 32, "the entropy source appears to be degenerate"


def test_generation_never_returns_a_prohibited_address():
    # Entropy that would produce exactly the prohibited address, then a usable one.
    entropy = fixed_entropy(b"\x02\x11\x22\x33\x44\x55", b"\x02\x99\x88\x77\x66\x55")
    assert generate_mac(entropy=entropy, prohibited=["02:11:22:33:44:55"]) == "02:99:88:77:66:55"


def test_generation_fails_rather_than_returning_a_prohibited_address():
    """A wedged entropy source must not be papered over."""
    stuck = lambda _n: b"\x02\x11\x22\x33\x44\x55"  # noqa: E731
    with pytest.raises(MacError):
        generate_mac(entropy=stuck, prohibited=["02:11:22:33:44:55"])


def test_bit_constants_match_ieee_802():
    assert LOCALLY_ADMINISTERED_BIT == 0x02
    assert MULTICAST_BIT == 0x01


# -- readback verification -------------------------------------------------


def test_successful_randomization_reports_the_readback_address(kernel: FakeKernel):
    result = randomize_interface("eth0", kernel.interfaces(), wait_seconds=5)
    assert result.assigned != BURNED_IN
    assert result.previous == BURNED_IN
    assert result.permanent == BURNED_IN
    # The returned value is what the kernel reports, not what we asked for.
    assert kernel.interfaces().read_mac("eth0") == result.assigned
    assert is_locally_administered(result.assigned)
    assert is_unicast(result.assigned)


def test_readback_mismatch_fails(kernel: FakeKernel):
    """A driver that assigns a different address than requested is a hard failure.

    Some drivers accept the netlink request and then apply an address of their
    own choosing. The result is still locally administered and still not the
    burned-in address -- and still not the address this process generated, so
    it must not be accepted.
    """
    original_run = kernel.run

    def substitute_address(argv):
        args = list(argv)
        result = original_run(argv)
        if args[:3] == ["ip", "link", "set"] and "address" in args:
            kernel.nics["eth0"].address = "02:de:ad:be:ef:01"
            kernel.sync()
        return result

    kernel.run = substitute_address  # type: ignore[method-assign]
    with pytest.raises(MacError, match="readback mismatch"):
        randomize_interface("eth0", kernel.interfaces(), wait_seconds=5)
    assert kernel.nics["eth0"].up is False


def test_driver_that_silently_ignores_the_change_fails(kernel: FakeKernel):
    """The USB-Ethernet case: netlink says OK, the address never changes."""
    kernel.nics["eth0"].accepts_mac_change = False
    with pytest.raises(MacError) as excinfo:
        randomize_interface("eth0", kernel.interfaces(), wait_seconds=5)
    assert "readback" in str(excinfo.value)
    # The burned-in address is still there, and the link was forced down rather
    # than left carrying traffic under it.
    assert kernel.interfaces().read_mac("eth0") == BURNED_IN
    assert kernel.nics["eth0"].up is False


def test_permanent_mac_is_rejected_even_when_it_is_not_the_previous_address(tmp_path: Path):
    """`new != previous` is not the assertion; `new != burned-in` is.

    A NIC can already be carrying a randomized address from an earlier boot
    while still refusing further changes. Comparing against the previous
    address alone would call that a success.
    """
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(
                address="02:aa:aa:aa:aa:aa",  # already randomized
                permanent=BURNED_IN,
                accepts_mac_change=False,
            )
        },
    )
    # Force the driver to snap back to the burned-in address on any write.
    original_run = kernel.run

    def snap_back(argv):
        result = original_run(argv)
        args = list(argv)
        if args[:3] == ["ip", "link", "set"] and "address" in args:
            kernel.nics["eth0"].address = BURNED_IN
            kernel.sync()
        return result

    kernel.run = snap_back  # type: ignore[method-assign]
    interfaces = kernel.interfaces()

    with pytest.raises(MacError) as excinfo:
        randomize_interface("eth0", interfaces, wait_seconds=5)
    message = str(excinfo.value)
    assert "readback" in message or "prohibited" in message


def test_prohibited_set_contains_both_permanent_and_previous(kernel: FakeKernel):
    kernel.nics["eth0"].address = "02:aa:aa:aa:aa:aa"
    kernel.sync()
    result = randomize_interface("eth0", kernel.interfaces(), wait_seconds=5)
    assert result.assigned not in {BURNED_IN, "02:aa:aa:aa:aa:aa"}


def test_command_exits_nonzero_when_the_mac_change_is_rejected(kernel: FakeKernel):
    kernel.nics["eth0"].rejects_mac_change_loudly = True
    with pytest.raises(MacError, match="rejected"):
        randomize_interface("eth0", kernel.interfaces(), wait_seconds=5)
    assert kernel.nics["eth0"].up is False


# -- bounded device enumeration -------------------------------------------


def test_slow_usb_enumeration_is_tolerated_within_the_budget(tmp_path: Path):
    """A late-enumerating USB adapter is waited for, not worked around."""
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={"eth1": FakeNic(address=BURNED_IN, permanent=BURNED_IN, appears_at=6.0)},
    )
    result = randomize_interface("eth1", kernel.interfaces(), wait_seconds=20)
    assert result.assigned != BURNED_IN
    assert kernel.slept >= 6.0


def test_interface_missing_after_bounded_retry_fails(tmp_path: Path):
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={"eth1": FakeNic(address=BURNED_IN, appears_at=900.0)},
    )
    with pytest.raises(MacError, match="did not appear"):
        randomize_interface("eth1", kernel.interfaces(), wait_seconds=10)
    # The wait is bounded: it gives up instead of hanging the boot forever.
    assert kernel.slept <= 11.0


def test_absent_interface_fails_rather_than_being_skipped(tmp_path: Path):
    kernel = FakeKernel(sysfs=tmp_path / "net", nics={})
    with pytest.raises(MacError, match="did not appear"):
        randomize_interface("eth9", kernel.interfaces(), wait_seconds=1)


# -- the command surface ---------------------------------------------------


def test_randomize_mac_command_returns_zero_on_success(tmp_path, monkeypatch, capsys):
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, permanent=BURNED_IN),
            "eth1": FakeNic(address="00:e0:4c:aa:bb:cc", permanent="00:e0:4c:aa:bb:cc"),
        },
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "randomize-mac"]
    )
    assert args.func(args) == 0
    assert kernel.nics["eth0"].address != BURNED_IN
    assert kernel.nics["eth1"].address != "00:e0:4c:aa:bb:cc"


def test_randomize_mac_command_returns_nonzero_when_any_interface_fails(
    tmp_path, monkeypatch, capsys
):
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, permanent=BURNED_IN),
            "eth1": FakeNic(
                address="00:e0:4c:aa:bb:cc",
                permanent="00:e0:4c:aa:bb:cc",
                accepts_mac_change=False,
            ),
        },
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "randomize-mac"]
    )
    assert args.func(args) != 0


def test_randomize_mac_requires_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "randomize-mac"]
    )
    assert args.func(args) == 2


def test_verify_zero_ip_passes_with_no_configured_address(tmp_path, monkeypatch):
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={"eth0": FakeNic(address=BURNED_IN), "eth1": FakeNic(address="02:00:00:00:00:01")},
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "verify-zero-ip"]
    )
    assert args.func(args) == 0


def test_verify_zero_ip_fails_when_an_address_is_already_configured(tmp_path, monkeypatch):
    """An IP before the network manager starts means something jumped the gate."""
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, addresses=["inet 192.0.2.10/24"]),
            "eth1": FakeNic(address="02:00:00:00:00:01"),
        },
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "verify-zero-ip"]
    )
    assert args.func(args) == 1


def test_ipv6_link_local_does_not_violate_zero_ip(tmp_path, monkeypatch):
    """A kernel-generated link-local address is not a configured address."""
    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, addresses=["inet6 fe80::1/64"]),
            "eth1": FakeNic(address="02:00:00:00:00:01"),
        },
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "verify-zero-ip"]
    )
    assert args.func(args) == 0


# -- phase separation ------------------------------------------------------


def test_pre_network_mac_gate_has_no_tor_dependency():
    """Phase 1 must not depend on Phase 2.

    Tor cannot be running when randomize-mac executes: Tor is gated on the
    firewall, which is gated on this stage. Any Tor-dependent check here would
    be unsatisfiable by construction, so it must not exist.
    """
    forbidden = {"tor", "socks", "circuit", "onion", "bootstrap", "torpath", "verify_tor_path"}
    for module in (mac, netif):
        tree = ast.parse(inspect.getsource(module))
        symbols: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                symbols.add(node.id.lower())
            elif isinstance(node, ast.Attribute):
                symbols.add(node.attr.lower())
            elif isinstance(node, ast.Import):
                symbols.update(alias.name.lower() for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                symbols.add((node.module or "").lower())
                symbols.update(alias.name.lower() for alias in node.names)
        # Split dotted and underscored names so `torpath.verify` or
        # `tor_socket` cannot hide inside a longer identifier.
        parts = {piece for symbol in symbols for piece in re.split(r"[._]", symbol) if piece}
        leaked = forbidden & (symbols | parts)
        assert not leaked, (
            f"{module.__name__} references {sorted(leaked)}; the pre-network gate "
            "cannot depend on a service that is gated behind it"
        )


def test_randomize_mac_does_not_reach_the_network(tmp_path, monkeypatch):
    """Belt and braces: fail the test if the MAC stage opens any socket."""
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("the pre-network MAC gate must not open a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    kernel = FakeKernel(
        sysfs=tmp_path / "net",
        nics={
            "eth0": FakeNic(address=BURNED_IN, permanent=BURNED_IN),
            "eth1": FakeNic(address="00:e0:4c:aa:bb:cc", permanent="00:e0:4c:aa:bb:cc"),
        },
    )
    monkeypatch.setattr(netif.NetworkInterfaces, "default", staticmethod(kernel.interfaces))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    args = anon.build_parser().parse_args(
        ["--config", str(write_env(tmp_path)), "randomize-mac"]
    )
    assert args.func(args) == 0
