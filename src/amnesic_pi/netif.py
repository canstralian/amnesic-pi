"""Interface primitives for the pre-network anonymity stage.

Everything that touches the kernel is funnelled through a small, injectable
surface so the security logic above it can be tested without a live NIC.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

SYSFS_NET = Path("/sys/class/net")

_MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_PERMADDR_RE = re.compile(r"\bpermaddr\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", re.IGNORECASE)
# `ip -o addr show` lines look like: "3: eth1    inet 10.0.0.1/24 scope global eth1"
_ADDR_RE = re.compile(r"\b(inet6?)\s+(\S+)")


class InterfaceError(RuntimeError):
    """Raised when an interface operation cannot be proven to have succeeded."""


@dataclass(frozen=True)
class Runner:
    """Injectable process runner. Tests substitute a fake; production uses subprocess."""

    run: Callable[[Sequence[str]], subprocess.CompletedProcess[str]]

    @staticmethod
    def default() -> Runner:
        def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(list(argv), text=True, capture_output=True, check=False)

        return Runner(run=_run)


def normalize_mac(value: str) -> str:
    """Return a lowercase canonical MAC string, or raise if it is not one."""
    candidate = value.strip().lower()
    if not _MAC_RE.fullmatch(candidate):
        raise InterfaceError(f"not a MAC address: {value!r}")
    return candidate


@dataclass(frozen=True)
class NetworkInterfaces:
    """Kernel-facing interface operations, rooted at an injectable sysfs path."""

    runner: Runner
    sysfs: Path = SYSFS_NET
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic

    @staticmethod
    def default() -> NetworkInterfaces:
        return NetworkInterfaces(runner=Runner.default())

    # -- discovery ---------------------------------------------------------

    def exists(self, iface: str) -> bool:
        return (self.sysfs / iface / "address").exists()

    def wait_for(self, iface: str, timeout: float, poll: float = 0.25) -> None:
        """Bounded retry for slow device enumeration.

        USB-Ethernet adapters on a headless Pi routinely enumerate after the
        unit starts. Waiting here is correct; weakening the dependency graph to
        accommodate the delay is not. When the budget expires this raises, and
        the caller fails closed.
        """
        deadline = self.clock() + timeout
        while True:
            if self.exists(iface):
                return
            if self.clock() >= deadline:
                raise InterfaceError(
                    f"interface {iface!r} did not appear within {timeout:g}s"
                )
            self.sleep(poll)

    # -- addresses ---------------------------------------------------------

    def read_mac(self, iface: str) -> str:
        try:
            raw = (self.sysfs / iface / "address").read_text(encoding="utf-8")
        except OSError as exc:
            raise InterfaceError(f"cannot read MAC of {iface!r}: {exc}") from exc
        return normalize_mac(raw)

    def permanent_mac(self, iface: str) -> str | None:
        """Best-effort burned-in address.

        Modern kernels expose it through `ip -details link` as `permaddr` and
        through `ethtool -P`. Neither is guaranteed for every driver, so the
        caller must not treat `None` as "no prohibited address" -- it combines
        this with the pre-change address instead.
        """
        result = self.runner.run(["ip", "-details", "link", "show", "dev", iface])
        if result.returncode == 0:
            match = _PERMADDR_RE.search(result.stdout or "")
            if match:
                return match.group(1).lower()

        result = self.runner.run(["ethtool", "-P", iface])
        if result.returncode == 0:
            match = re.search(r"((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", result.stdout or "", re.I)
            if match:
                return match.group(1).lower()
        return None

    def assigned_addresses(self, iface: str) -> list[str]:
        """Return every IP address currently configured on the interface."""
        result = self.runner.run(["ip", "-o", "addr", "show", "dev", iface])
        if result.returncode != 0:
            raise InterfaceError(
                f"cannot enumerate addresses on {iface!r}: {(result.stderr or '').strip()}"
            )
        found: list[str] = []
        for line in (result.stdout or "").splitlines():
            match = _ADDR_RE.search(line)
            if match:
                found.append(f"{match.group(1)} {match.group(2)}")
        return found

    # -- link state --------------------------------------------------------

    def _ip(self, *args: str) -> None:
        argv = ["ip", *args]
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise InterfaceError(
                f"{' '.join(argv)} failed ({result.returncode}): {(result.stderr or '').strip()}"
            )

    def link_down(self, iface: str) -> None:
        self._ip("link", "set", "dev", iface, "down")

    def link_up(self, iface: str) -> None:
        self._ip("link", "set", "dev", iface, "up")

    def set_mac(self, iface: str, mac: str) -> None:
        self._ip("link", "set", "dev", iface, "address", normalize_mac(mac))

    def force_down(self, iface: str) -> None:
        """Best-effort link-down used on the failure path.

        A NIC that refused a MAC change must not be left carrying traffic under
        its burned-in address, so failures here are swallowed: the command has
        already decided to exit nonzero.
        """
        try:
            self.link_down(iface)
        except InterfaceError:
            pass
