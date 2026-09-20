"""Test doubles for the kernel-facing surfaces.

These model *behaviour* -- a NIC that refuses address changes, a driver that
reports a stale address, a device that enumerates late -- rather than recording
which subprocess arguments were used. Asserting on argv would pass for an
implementation that runs the right commands and then ignores their results,
which is precisely the failure mode these tests exist to catch.

The fake kernel keeps a real directory tree standing in for /sys/class/net, so
the production code reads addresses back through exactly the path it uses on
the appliance.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from amnesic_pi.netif import NetworkInterfaces, Runner
from amnesic_pi.nft import Nft
from amnesic_pi.sysctl import FORWARDING_KNOBS, Sysctl


def completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


@dataclass
class FakeNic:
    """A simulated network interface."""

    address: str
    permanent: str | None = None
    # False models the cheap USB-Ethernet adapters whose drivers accept the
    # netlink request and then keep the burned-in address anyway.
    accepts_mac_change: bool = True
    # True models a driver that returns an error instead of ignoring silently.
    rejects_mac_change_loudly: bool = False
    up: bool = False
    addresses: list[str] = field(default_factory=list)
    # Seconds of simulated waiting before the device enumerates. Models a USB
    # adapter appearing after the unit has already started.
    appears_at: float = 0.0


@dataclass
class FakeKernel:
    """Backs a NetworkInterfaces instance without touching the real kernel."""

    sysfs: Path
    nics: dict[str, FakeNic] = field(default_factory=dict)
    now: float = 0.0
    slept: float = 0.0

    def __post_init__(self) -> None:
        self.sync()

    # -- injected clock ----------------------------------------------------

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds
        self.slept += seconds
        self.sync()

    # -- sysfs mirror ------------------------------------------------------

    def sync(self) -> None:
        """Materialize the address files for every NIC that has enumerated."""
        for name, nic in self.nics.items():
            if nic.appears_at > self.now:
                continue
            directory = self.sysfs / name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "address").write_text(nic.address + "\n", encoding="utf-8")

    def interfaces(self) -> NetworkInterfaces:
        return NetworkInterfaces(
            runner=Runner(run=self.run),
            sysfs=self.sysfs,
            sleep=self.sleep,
            clock=self.clock,
        )

    # -- command surface ---------------------------------------------------

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        if args[0] == "ip":
            result = self._ip(args[1:])
            self.sync()
            return result
        if args[0] == "ethtool" and args[1:2] == ["-P"]:
            nic = self.nics.get(args[2])
            if nic is not None and nic.permanent:
                return completed(0, f"Permanent address: {nic.permanent}\n")
            return completed(1, stderr="Operation not supported\n")
        return completed(1, stderr=f"unexpected command: {args}\n")

    def _visible(self, name: str) -> FakeNic | None:
        nic = self.nics.get(name)
        if nic is None or nic.appears_at > self.now:
            return None
        return nic

    def _ip(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:3] == ["-details", "link", "show"]:
            nic = self._visible(args[-1])
            if nic is None:
                return completed(1, stderr="Device does not exist\n")
            suffix = f" permaddr {nic.permanent}" if nic.permanent else ""
            return completed(
                0, f"2: {args[-1]}: <BROADCAST>\n    link/ether {nic.address}{suffix}\n"
            )
        if args[:3] == ["-o", "addr", "show"]:
            iface = args[-1]
            nic = self._visible(iface)
            if nic is None:
                return completed(1, stderr="Device does not exist\n")
            body = "".join(
                f"2: {iface}    {entry} scope global {iface}\n" for entry in nic.addresses
            )
            return completed(0, body)
        if args[:3] == ["link", "set", "dev"]:
            iface = args[3]
            nic = self._visible(iface)
            if nic is None:
                return completed(1, stderr="Cannot find device\n")
            verb = args[4]
            if verb == "down":
                nic.up = False
                return completed(0)
            if verb == "up":
                nic.up = True
                return completed(0)
            if verb == "address":
                if nic.rejects_mac_change_loudly:
                    return completed(2, stderr="RTNETLINK answers: Operation not supported\n")
                if nic.accepts_mac_change:
                    nic.address = args[5]
                # Otherwise: success is reported, the address does not change.
                # Only the readback assertion catches this.
                return completed(0)
        return completed(1, stderr=f"unexpected ip args: {args}\n")


def fixed_entropy(*blocks: bytes):
    """An entropy source that returns pinned bytes, for deterministic assertions."""
    queue = list(blocks)

    def source(count: int) -> bytes:
        block = queue.pop(0) if queue else b"\x00" * count
        return block[:count]

    return source


@dataclass
class FakeNft:
    """An in-memory nftables ruleset with injectable failure points.

    Models the properties the transaction depends on: `nft -f` is atomic (a
    rejected batch leaves the previous ruleset untouched) and `nft -c` can
    reject a batch the kernel would have refused.
    """

    tables: dict[str, str] = field(default_factory=dict)
    fail_check: bool = False
    fail_load: bool = False
    fail_delete: bool = False
    loads: int = 0

    def run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        if args[:2] != ["nft"] and args[0] != "nft":
            return completed(1, stderr="not nft\n")
        rest = args[1:]
        if rest[:2] == ["list", "table"]:
            key = f"{rest[2]} {rest[3]}"
            if key not in self.tables:
                return completed(1, stderr="Error: No such file or directory\n")
            return completed(0, self.tables[key])
        if rest[:2] == ["list", "ruleset"]:
            return completed(0, "\n".join(self.tables.values()))
        if rest[:2] == ["delete", "table"]:
            key = f"{rest[2]} {rest[3]}"
            if self.fail_delete:
                return completed(1, stderr="Error: could not delete table\n")
            self.tables.pop(key, None)
            return completed(0)
        if rest and rest[0] in {"-c", "-f"}:
            dry_run = rest[0] == "-c"
            path = Path(rest[-1])
            body = path.read_text(encoding="utf-8")
            if dry_run and self.fail_check:
                return completed(1, stderr="Error: syntax error\n")
            if self.fail_delete and "delete table" in body:
                # The batch replaces an existing table and the delete is
                # refused. nft is atomic, so the whole transaction is rejected
                # and the previous ruleset survives untouched.
                return completed(1, stderr="Error: Could not process rule: Device or resource busy\n")
            if not dry_run and self.fail_load:
                # Atomic: the ruleset is left exactly as it was.
                return completed(1, stderr="Error: could not process rule\n")
            if not dry_run:
                self.loads += 1
                self._apply(body)
            return completed(0)
        return completed(1, stderr=f"unexpected nft args: {rest}\n")

    def _apply(self, body: str) -> None:
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("delete table "):
                self.tables.pop(stripped[len("delete table ") :].strip(), None)
        for match in re.finditer(r"table\s+(\w+)\s+(\S+)\s*\{", body):
            if body[: match.start()].rstrip().endswith("delete"):
                continue
            depth = 0
            start = match.end() - 1
            for index in range(start, len(body)):
                if body[index] == "{":
                    depth += 1
                elif body[index] == "}":
                    depth -= 1
                    if depth == 0:
                        key = f"{match.group(1)} {match.group(2)}"
                        self.tables[key] = body[match.start() : index + 1]
                        break

    def interface(self) -> Nft:
        return Nft(runner=Runner(run=self.run))


class FakeSysctl(Sysctl):
    """A Sysctl backed by a temporary directory instead of /proc/sys."""

    @staticmethod
    def build(root: Path, present: Sequence[str] = FORWARDING_KNOBS) -> Sysctl:
        for knob in present:
            path = root / knob
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("0\n", encoding="utf-8")
        return Sysctl(root=root)
