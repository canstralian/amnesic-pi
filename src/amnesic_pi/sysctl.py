"""Forwarding-state primitives.

Forwarding is written through /proc/sys directly rather than the `sysctl`
binary so that reads and writes hit exactly the knob named, with no config-file
layer in between that could reintroduce a boot-time grant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

PROC_SYS = Path("/proc/sys")

IPV4_FORWARD = "net/ipv4/ip_forward"
IPV6_FORWARD_ALL = "net/ipv6/conf/all/forwarding"
IPV6_FORWARD_DEFAULT = "net/ipv6/conf/default/forwarding"
IPV6_DISABLE_ALL = "net/ipv6/conf/all/disable_ipv6"
IPV6_DISABLE_DEFAULT = "net/ipv6/conf/default/disable_ipv6"


def ipv6_disable_knob(iface: str) -> str:
    """The per-interface disable_ipv6 knob path for `iface`."""
    return f"net/ipv6/conf/{iface}/disable_ipv6"


def _is_optional_ipv6_disable_knob(knob: str) -> bool:
    """True for any interface's disable_ipv6 knob, `all`/`default` included.

    A kernel with IPv6 compiled out has none of these -- not just the two
    fixed `all`/`default` paths -- so a named role interface's knob must get
    the same "absent means compiled out" treatment, not a hardcoded pair.
    """
    return knob.startswith("net/ipv6/conf/") and knob.endswith("/disable_ipv6")

# Every forwarding knob the appliance is responsible for holding at zero until
# the firewall transaction says otherwise.
FORWARDING_KNOBS = (IPV4_FORWARD, IPV6_FORWARD_ALL, IPV6_FORWARD_DEFAULT)


class SysctlError(RuntimeError):
    pass


@dataclass(frozen=True)
class Sysctl:
    """Read/write access to kernel knobs, rooted at an injectable /proc/sys."""

    root: Path = PROC_SYS
    # Knobs that are legitimately absent on some kernels (e.g. IPv6 compiled
    # out). Reading a missing knob yields None; writing one is a no-op.
    optional: frozenset[str] = field(default=frozenset({
        IPV6_FORWARD_ALL,
        IPV6_FORWARD_DEFAULT,
        IPV6_DISABLE_ALL,
        IPV6_DISABLE_DEFAULT,
    }))

    def read(self, knob: str) -> str | None:
        path = self.root / knob
        try:
            return path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            # The one OSError that actually means "this knob does not exist
            # on this kernel" -- IPv6 compiled out, for the optional set.
            if knob in self.optional or _is_optional_ipv6_disable_knob(knob):
                return None
            raise SysctlError(f"cannot read {knob}: knob does not exist") from None
        except OSError as exc:
            # Anything else -- permission denied, an unreadable procfs entry
            # -- is a real failure even for an optional knob. Reporting it as
            # "absent" would let an unprovable IPv6 posture pass as satisfied.
            raise SysctlError(f"cannot read {knob}: {exc}") from exc

    def write(self, knob: str, value: str) -> None:
        path = self.root / knob
        try:
            path.write_text(f"{value}\n", encoding="utf-8")
        except FileNotFoundError as exc:
            if knob in self.optional:
                return
            raise SysctlError(f"cannot write {knob}={value}: {exc}") from exc
        except OSError as exc:
            raise SysctlError(f"cannot write {knob}={value}: {exc}") from exc

    def disable_forwarding(self) -> list[str]:
        """Set every forwarding knob to 0. Returns the knobs that could not be written."""
        failed: list[str] = []
        for knob in FORWARDING_KNOBS:
            try:
                self.write(knob, "0")
            except SysctlError:
                failed.append(knob)
        return failed

    def forwarding_state(self) -> dict[str, str | None]:
        return {knob: self.read(knob) for knob in FORWARDING_KNOBS}
