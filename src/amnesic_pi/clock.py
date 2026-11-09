"""Clock correction from the Tor consensus, for a Pi with no trusted clock.

Tor will not use a consensus whose validity window does not contain the system
clock. A Pi without a battery-backed RTC boots with whatever time was last
saved, and under OverlayFS that is the time the image was frozen -- days or
months behind. Tor then fetches a consensus it considers "not yet valid" and
never finishes bootstrapping.

The appliance has no NTP authority: the Tor UID is the only egress principal,
and adding a time principal would widen the boundary AGENTS.md protects.
Instead the clock is taken from the consensus Tor has already fetched over its
own authenticated directory connections. No packet leaves the appliance for
this; the consensus is read from Tor's data directory.

Three rules bound the authority this grants over the clock:

* Forward only. A clock ahead of the consensus is reported, never corrected:
  moving it back would let a stale, replayed consensus look current.
* Only a consensus fetched this boot counts. `forget_consensus` runs before Tor
  starts and removes the cached one, because under OverlayFS the cache and the
  boot clock come from the same frozen image and would agree with each other
  while both being wrong.
* The document must look like a consensus: a version line, all three validity
  timestamps, in order, spanning at most a day.

With a battery-backed RTC the clock is already inside the window and nothing
is changed.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .authority import Check

TOR_DATA_DIR = Path("/var/lib/tor")
TOR_UNIT = "tor@default.service"

# Every name Tor stores a consensus under. The unverified-* files hold one whose
# signatures Tor could not yet check -- the usual state when the clock is far
# enough off that authority certificates look not-yet-valid.
CONSENSUS_FILES = (
    "cached-microdesc-consensus",
    "unverified-microdesc-consensus",
    "cached-consensus",
    "unverified-consensus",
)

# A clock this far behind valid-after is corrected. Tor itself tolerates more,
# but certificate checks and its own clock-skew warnings start well before that.
BEHIND_TOLERANCE_SECONDS = 3600
# A real consensus is valid for three hours; anything spanning more than a day
# is not one.
MAX_WINDOW_SECONDS = 24 * 3600
# The validity lines sit in the first few hundred bytes of a multi-megabyte file.
HEADER_BYTES = 64 * 1024
POLL_SECONDS = 2.0

_VERSION_LINE = "network-status-version 3"
_TIME_LINE = re.compile(
    r"^(valid-after|fresh-until|valid-until) (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$", re.MULTILINE
)


class ClockError(RuntimeError):
    pass


@dataclass(frozen=True)
class ConsensusWindow:
    valid_after: float
    fresh_until: float
    valid_until: float


def _utc(stamp: str) -> float:
    parsed = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_window(text: str) -> ConsensusWindow:
    """Extract the validity window from a consensus header, or refuse it."""
    if not text.startswith(_VERSION_LINE):
        raise ClockError(f"not a consensus document: missing {_VERSION_LINE!r}")
    found: dict[str, float] = {}
    for key, stamp in _TIME_LINE.findall(text):
        try:
            found.setdefault(key, _utc(stamp))
        except ValueError as exc:
            raise ClockError(f"unparseable {key}: {stamp!r}") from exc
    missing = [key for key in ("valid-after", "fresh-until", "valid-until") if key not in found]
    if missing:
        raise ClockError(f"consensus header lacks {', '.join(missing)}")
    window = ConsensusWindow(found["valid-after"], found["fresh-until"], found["valid-until"])
    if not window.valid_after <= window.fresh_until <= window.valid_until:
        raise ClockError("consensus validity timestamps are out of order")
    if window.valid_until - window.valid_after > MAX_WINDOW_SECONDS:
        raise ClockError("consensus validity window spans more than a day")
    return window


def newest_window(data_dir: Path) -> ConsensusWindow | None:
    """The latest-dated well-formed consensus Tor has stored, if any."""
    windows: list[ConsensusWindow] = []
    for name in CONSENSUS_FILES:
        try:
            with (data_dir / name).open("r", encoding="utf-8", errors="replace") as fh:
                header = fh.read(HEADER_BYTES)
        except FileNotFoundError:
            continue
        try:
            windows.append(parse_window(header))
        except ClockError:
            # A partly written or foreign file is not evidence of anything; Tor
            # will write a complete one, and the caller keeps polling.
            continue
    return max(windows, key=lambda w: w.valid_after, default=None)


def forget_consensus(data_dir: Path) -> list[Check]:
    """Remove every cached consensus, so the next one is fetched this boot.

    A failure to remove an existing file is a failure: a stale cache left in
    place would let the clock check agree with a frozen image.
    """
    checks: list[Check] = []
    for name in CONSENSUS_FILES:
        path = data_dir / name
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            checks.append(Check(f"forget {name}", False, str(exc)))
            continue
        checks.append(Check(f"forget {name}", True, "removed"))
    if not checks:
        checks.append(Check("forget cached consensus", True, "none cached"))
    return checks


def restart_tor() -> None:
    result = subprocess.run(
        ["systemctl", "restart", TOR_UNIT], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise ClockError(f"systemctl restart {TOR_UNIT} failed: {result.stderr.strip()}")


def set_realtime(epoch: float) -> None:
    try:
        time.clock_settime(time.CLOCK_REALTIME, epoch)
    except OSError as exc:
        raise ClockError(f"cannot set the system clock: {exc}") from exc


def sync_clock(
    data_dir: Path,
    wait_seconds: float,
    *,
    now: Callable[[], float] = time.time,
    set_clock: Callable[[float], None] = set_realtime,
    restart: Callable[[], None] = restart_tor,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[Check]:
    """Wait for this boot's consensus, then move the clock forward if it is behind."""
    deadline = monotonic() + wait_seconds
    while True:
        window = newest_window(data_dir)
        if window is not None:
            return _reconcile(window, now(), set_clock, restart)
        if monotonic() >= deadline:
            return [
                Check(
                    "consensus fetched this boot",
                    False,
                    f"no consensus in {data_dir} after {wait_seconds:g}s; clock not verified",
                )
            ]
        sleep(POLL_SECONDS)


def _reconcile(
    window: ConsensusWindow,
    current: float,
    set_clock: Callable[[float], None],
    restart: Callable[[], None],
) -> list[Check]:
    span = f"{_iso(window.valid_after)} .. {_iso(window.valid_until)}"
    if current > window.valid_until:
        return [
            Check(
                "system clock",
                False,
                f"{_iso(current)} is ahead of the consensus window {span}; "
                "not moved backwards (forward-only)",
            )
        ]
    if current >= window.valid_after - BEHIND_TOLERANCE_SECONDS:
        return [Check("system clock", True, f"{_iso(current)} agrees with consensus {span}")]

    behind = window.valid_after - current
    try:
        set_clock(window.valid_after)
    except ClockError as exc:
        return [Check("system clock", False, str(exc))]
    checks = [
        Check(
            "system clock",
            True,
            f"moved forward {behind:.0f}s from {_iso(current)} to {_iso(window.valid_after)}",
        )
    ]
    # Tor judged its consensus against the old clock. Restart it so it
    # re-evaluates against the corrected one rather than waiting it out.
    try:
        restart()
    except ClockError as exc:
        checks.append(Check("Tor restarted on the corrected clock", False, str(exc)))
    else:
        checks.append(Check("Tor restarted on the corrected clock", True, TOR_UNIT))
    return checks
