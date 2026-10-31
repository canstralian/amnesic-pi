"""Regression coverage for `Sysctl`'s read/write primitives.

The property under test: an "optional" knob (IPv6 compiled out, for example)
may legitimately not exist, and that case alone must read as absent. Any
other failure to read it -- permission denied, an unreadable procfs entry --
is a real failure and must not be silently reported the same way a missing
knob is. An unprovable posture is not a passing one.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from amnesic_pi.sysctl import IPV6_DISABLE_ALL, IPV6_FORWARD_ALL, Sysctl, SysctlError


def test_read_missing_optional_knob_is_absent(tmp_path: Path):
    sysctl = Sysctl(root=tmp_path)
    assert sysctl.read(IPV6_FORWARD_ALL) is None


def test_read_missing_required_knob_raises(tmp_path: Path):
    sysctl = Sysctl(root=tmp_path, optional=frozenset())
    with pytest.raises(SysctlError):
        sysctl.read("net/ipv4/ip_forward")


def test_read_present_optional_knob_returns_its_value(tmp_path: Path):
    path = tmp_path / IPV6_DISABLE_ALL
    path.parent.mkdir(parents=True)
    path.write_text("1\n", encoding="utf-8")
    assert Sysctl(root=tmp_path).read(IPV6_DISABLE_ALL) == "1"


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permission checks")
def test_read_permission_denied_on_an_optional_knob_still_raises(tmp_path: Path):
    """A missing knob and an unreadable one are different failures.

    Only "this knob does not exist" may read as absent. A knob that exists
    but cannot be read -- permission denied, in this test -- must raise, even
    though it is on the optional list. Reporting it as "absent" would let an
    unprovable IPv6 posture pass as satisfied.
    """
    path = tmp_path / IPV6_DISABLE_ALL
    path.parent.mkdir(parents=True)
    path.write_text("1\n", encoding="utf-8")
    path.chmod(0o000)
    try:
        with pytest.raises(SysctlError, match="cannot read"):
            Sysctl(root=tmp_path).read(IPV6_DISABLE_ALL)
    finally:
        path.chmod(0o644)


def test_write_missing_optional_knob_is_a_no_op(tmp_path: Path):
    Sysctl(root=tmp_path).write(IPV6_FORWARD_ALL, "0")  # must not raise


def test_write_missing_required_knob_raises(tmp_path: Path):
    sysctl = Sysctl(root=tmp_path, optional=frozenset())
    with pytest.raises(SysctlError):
        sysctl.write("net/ipv4/ip_forward", "0")
