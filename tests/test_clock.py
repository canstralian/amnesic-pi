"""Clock correction from the Tor consensus: forward-only, this boot's only.

Each test names the rule it holds. The clock, the setter and the Tor restart
are injected, so nothing here touches the host clock or systemd.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from amnesic_pi import clock
from amnesic_pi.clock import (
    BEHIND_TOLERANCE_SECONDS,
    ClockError,
    forget_consensus,
    newest_window,
    parse_window,
    sync_clock,
)

VALID_AFTER = datetime(2026, 10, 26, 5, 0, tzinfo=timezone.utc).timestamp()


def consensus(valid_after: str = "2026-10-26 05:00:00", fresh: str = "2026-10-26 06:00:00",
              until: str = "2026-10-26 08:00:00") -> str:
    return (
        "network-status-version 3 microdesc\n"
        "vote-status consensus\n"
        f"valid-after {valid_after}\n"
        f"fresh-until {fresh}\n"
        f"valid-until {until}\n"
        "voting-delay 300 300\n"
    )


class Recorder:
    def __init__(self, fail_set: bool = False, fail_restart: bool = False):
        self.set_to: list[float] = []
        self.restarts = 0
        self.fail_set = fail_set
        self.fail_restart = fail_restart

    def set_clock(self, epoch: float) -> None:
        if self.fail_set:
            raise ClockError("cannot set the system clock: EPERM")
        self.set_to.append(epoch)

    def restart(self) -> None:
        if self.fail_restart:
            raise ClockError("systemctl restart failed")
        self.restarts += 1


def run(tmp_path: Path, current: float, recorder: Recorder, wait: float = 0.0):
    ticks = iter(range(10_000))
    return sync_clock(
        tmp_path,
        wait,
        now=lambda: current,
        set_clock=recorder.set_clock,
        restart=recorder.restart,
        sleep=lambda _: None,
        monotonic=lambda: float(next(ticks)),
    )


# -- parsing ---------------------------------------------------------------


def test_parse_reads_the_validity_window():
    window = parse_window(consensus())
    assert window.valid_after == VALID_AFTER
    assert window.valid_until - window.valid_after == 3 * 3600


@pytest.mark.parametrize(
    "text, reason",
    [
        ("vote-status consensus\nvalid-after 2026-10-26 05:00:00\n", "not a consensus"),
        (consensus().replace("fresh-until", "fresh-later"), "lacks fresh-until"),
        (consensus(fresh="2026-10-26 04:00:00"), "out of order"),
        (consensus(until="2026-10-29 05:00:00"), "more than a day"),
    ],
)
def test_parse_refuses_documents_that_are_not_a_plausible_consensus(text: str, reason: str):
    with pytest.raises(ClockError, match=reason):
        parse_window(text)


def test_newest_window_prefers_the_latest_and_skips_partial_files(tmp_path: Path):
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    (tmp_path / "unverified-microdesc-consensus").write_text(
        consensus("2026-10-26 06:00:00", "2026-10-26 07:00:00", "2026-10-26 09:00:00")
    )
    (tmp_path / "cached-consensus").write_text("network-status-version 3\nvalid-aft")
    assert newest_window(tmp_path).valid_after == VALID_AFTER + 3600


# -- forward only ----------------------------------------------------------


def test_a_clock_months_behind_is_moved_forward_and_tor_restarted(tmp_path: Path):
    (tmp_path / "unverified-microdesc-consensus").write_text(consensus())
    recorder = Recorder()
    checks = run(tmp_path, VALID_AFTER - 120 * 86400, recorder)
    assert all(c.ok for c in checks)
    assert recorder.set_to == [VALID_AFTER]
    assert recorder.restarts == 1


def test_a_clock_ahead_of_the_consensus_is_never_moved_back(tmp_path: Path):
    """Moving back would let a replayed, stale consensus look current."""
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    recorder = Recorder()
    checks = run(tmp_path, VALID_AFTER + 30 * 86400, recorder)
    assert not any(c.ok for c in checks)
    assert "forward-only" in checks[0].detail
    assert recorder.set_to == [] and recorder.restarts == 0


@pytest.mark.parametrize(
    "offset", [0, -BEHIND_TOLERANCE_SECONDS, 2 * 3600, 3 * 3600]
)
def test_a_clock_inside_the_window_is_left_alone(tmp_path: Path, offset: int):
    """The battery-backed RTC case: nothing to do, nothing done."""
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    recorder = Recorder()
    checks = run(tmp_path, VALID_AFTER + offset, recorder)
    assert all(c.ok for c in checks)
    assert recorder.set_to == [] and recorder.restarts == 0


def test_a_clock_that_cannot_be_set_fails_without_restarting_tor(tmp_path: Path):
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    recorder = Recorder(fail_set=True)
    checks = run(tmp_path, VALID_AFTER - 86400, recorder)
    assert not any(c.ok for c in checks)
    assert recorder.restarts == 0


def test_a_failed_tor_restart_is_reported(tmp_path: Path):
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    recorder = Recorder(fail_restart=True)
    checks = run(tmp_path, VALID_AFTER - 86400, recorder)
    assert [c.ok for c in checks] == [True, False]


def test_no_consensus_within_the_budget_fails_without_touching_the_clock(tmp_path: Path):
    recorder = Recorder()
    checks = run(tmp_path, VALID_AFTER - 86400, recorder, wait=5)
    assert len(checks) == 1 and not checks[0].ok
    assert "clock not verified" in checks[0].detail
    assert recorder.set_to == []


# -- this boot's consensus only --------------------------------------------


def test_forget_removes_every_cached_consensus(tmp_path: Path):
    for name in clock.CONSENSUS_FILES:
        (tmp_path / name).write_text(consensus())
    (tmp_path / "cached-certs").write_text("kept")
    checks = forget_consensus(tmp_path)
    assert all(c.ok for c in checks)
    assert newest_window(tmp_path) is None
    assert (tmp_path / "cached-certs").exists(), "only consensus documents are forgotten"


def test_forget_with_nothing_cached_succeeds(tmp_path: Path):
    assert all(c.ok for c in forget_consensus(tmp_path))


def test_forget_fails_when_a_stale_consensus_cannot_be_removed(tmp_path: Path, monkeypatch):
    """A cache left in place could agree with a frozen image clock."""
    (tmp_path / "cached-microdesc-consensus").write_text(consensus())
    original = Path.unlink

    def refuse(self, *args, **kwargs):
        if self.name == "cached-microdesc-consensus":
            raise PermissionError("read-only file system")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    checks = forget_consensus(tmp_path)
    assert not all(c.ok for c in checks)
