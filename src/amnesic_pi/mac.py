"""MAC randomization with mandatory readback verification.

The security claim this module makes is narrow and testable: after
`randomize_interface` returns, the kernel reports an address that this process
generated from OS entropy, and that address is neither the burned-in address
nor the address the interface carried beforehand. If any of that cannot be
proven, the function raises and the caller exits nonzero.

Nothing here may depend on Tor, on the network being up, or on persistent
state. This stage runs before the network manager is allowed to start.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from .netif import InterfaceError, NetworkInterfaces, normalize_mac

# Bit 1 of the first octet marks a locally administered address.
LOCALLY_ADMINISTERED_BIT = 0x02
# Bit 0 of the first octet marks a group (multicast) address; it must be clear.
MULTICAST_BIT = 0x01

_MAX_GENERATION_ATTEMPTS = 16


class MacError(RuntimeError):
    """Raised when a MAC address cannot be generated or cannot be proven applied."""


def generate_mac(
    entropy: Callable[[int], bytes] = os.urandom,
    prohibited: Iterable[str] = (),
) -> str:
    """Generate a locally administered, unicast MAC from cryptographic entropy.

    `entropy` exists so tests can pin the byte stream. It defaults to
    `os.urandom`: the address must not derive from machine-id, hostname,
    wall-clock time, persistent state, or a seeded non-cryptographic PRNG,
    because any of those make the address linkable across boots or devices.
    """
    blocked = {normalize_mac(value) for value in prohibited}
    for _ in range(_MAX_GENERATION_ATTEMPTS):
        raw = bytearray(entropy(6))
        if len(raw) != 6:
            raise MacError("entropy source returned the wrong number of bytes")
        raw[0] |= LOCALLY_ADMINISTERED_BIT
        raw[0] &= ~MULTICAST_BIT & 0xFF
        candidate = ":".join(f"{byte:02x}" for byte in raw)
        if candidate in blocked:
            continue
        if all(byte == 0 for byte in raw[1:]):
            # Degenerate all-zero tail; cheap to reject and trivially fingerprintable.
            continue
        return candidate
    raise MacError("could not generate an acceptable MAC address from the entropy source")


def is_locally_administered(mac: str) -> bool:
    return bool(int(normalize_mac(mac).split(":")[0], 16) & LOCALLY_ADMINISTERED_BIT)


def is_unicast(mac: str) -> bool:
    return not int(normalize_mac(mac).split(":")[0], 16) & MULTICAST_BIT


@dataclass(frozen=True)
class MacResult:
    iface: str
    previous: str
    permanent: str | None
    assigned: str


def randomize_interface(
    iface: str,
    interfaces: NetworkInterfaces,
    wait_seconds: float,
    entropy: Callable[[int], bytes] = os.urandom,
) -> MacResult:
    """Randomize `iface`'s MAC and prove the change took effect.

    Sequence: bounded discovery, capture prohibited addresses, link down, set,
    link up, read back, assert the readback equals what we generated and is not
    a prohibited address.

    A driver that silently ignores `ip link set address` -- common with cheap
    USB-Ethernet parts -- fails here rather than letting the appliance claim an
    anonymity property it does not have.
    """
    try:
        interfaces.wait_for(iface, timeout=wait_seconds)
    except InterfaceError as exc:
        raise MacError(str(exc)) from exc

    try:
        previous = interfaces.read_mac(iface)
    except InterfaceError as exc:
        raise MacError(f"{iface}: cannot read the current MAC: {exc}") from exc

    permanent = interfaces.permanent_mac(iface)

    # The burned-in address is prohibited explicitly. The pre-change address is
    # prohibited too, but it is not a substitute: a driver may already be
    # carrying a randomized address while still refusing further changes.
    prohibited = {previous}
    if permanent is not None:
        prohibited.add(normalize_mac(permanent))

    generated = generate_mac(entropy=entropy, prohibited=prohibited)

    try:
        interfaces.link_down(iface)
        interfaces.set_mac(iface, generated)
        interfaces.link_up(iface)
    except InterfaceError as exc:
        interfaces.force_down(iface)
        raise MacError(f"{iface}: MAC change was rejected: {exc}") from exc

    try:
        actual = interfaces.read_mac(iface)
    except InterfaceError as exc:
        interfaces.force_down(iface)
        raise MacError(f"{iface}: cannot read back the MAC after the change: {exc}") from exc

    if actual != generated:
        interfaces.force_down(iface)
        raise MacError(
            f"{iface}: MAC readback mismatch: kernel reports {actual}, expected {generated}"
        )
    if actual in prohibited:
        interfaces.force_down(iface)
        raise MacError(
            f"{iface}: MAC readback returned a prohibited address {actual} "
            "(the driver appears to ignore address changes)"
        )
    if not is_locally_administered(actual) or not is_unicast(actual):
        interfaces.force_down(iface)
        raise MacError(f"{iface}: applied MAC {actual} is not a locally administered unicast address")

    return MacResult(iface=iface, previous=previous, permanent=permanent, assigned=actual)
