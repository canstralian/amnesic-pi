"""Regression coverage for the resolved systemd authority graph.

These tests do not grep unit files for "BindsTo=". They lay the units out the
way `image/provision.sh` installs them, merge every drop-in the way systemd
does, and assert on the *resolved* relationships, including the reverse edges
(`BoundBy=`) systemd synthesises.

The goal is narrow and deliberate: make it hard for a future edit to downgrade
a `BindsTo=` into a `Before=` without CI going red.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
import unitgraph

ANON = "amnesic-pi-anon.service"
FIREWALL = "amnesic-pi-firewall.service"
LOCKDOWN = "amnesic-pi-lockdown.service"
POSTURE = "amnesic-pi-posture.service"
READY = "amnesic-pi-ready.target"
TOR = "tor@default.service"
NETWORKD = "systemd-networkd.service"
NETWORKMANAGER = "NetworkManager.service"

NETWORK_MANAGERS = (NETWORKD, NETWORKMANAGER)


@pytest.fixture(scope="module")
def root(tmp_path_factory) -> Path:
    return unitgraph.materialize(tmp_path_factory.mktemp("units") / "systemd")


@pytest.fixture(scope="module")
def graph(root: Path) -> unitgraph.Graph:
    return unitgraph.resolve(root)


# -- the authority gate ----------------------------------------------------


@pytest.mark.parametrize("manager", NETWORK_MANAGERS)
def test_network_manager_binds_to_firewall(graph: unitgraph.Graph, manager: str):
    """The network manager cannot start without the firewall, and cannot outlive it.

    Ordering alone would not do this: a unit ordered Before= another may fail
    while the other still starts. BindsTo= is the lifetime relationship.
    """
    assert FIREWALL in graph.binds_to[manager], (
        f"{manager} does not BindsTo {FIREWALL}; ordering is not an authority gate"
    )


@pytest.mark.parametrize("manager", NETWORK_MANAGERS)
def test_network_manager_ordered_after_firewall(graph: unitgraph.Graph, manager: str):
    assert FIREWALL in graph.after[manager]


def test_tor_binds_to_firewall(graph: unitgraph.Graph):
    """Tor must not survive the firewall unit disappearing."""
    assert FIREWALL in graph.binds_to[TOR]


def test_tor_ordered_after_firewall(graph: unitgraph.Graph):
    assert FIREWALL in graph.after[TOR]


def test_firewall_binds_to_the_anonymity_stage(graph: unitgraph.Graph):
    assert ANON in graph.binds_to[FIREWALL]


def test_firewall_ordered_after_the_anonymity_stage(graph: unitgraph.Graph):
    assert ANON in graph.after[FIREWALL]


def test_reverse_edges_name_every_bound_consumer(graph: unitgraph.Graph):
    """Assert the relationship from the firewall's side as well.

    If the firewall stops, systemd stops everything in BoundBy. Naming the full
    set here means adding a new network consumer without gating it is visible
    as a test failure rather than a silent omission.
    """
    assert graph.bound_by[FIREWALL] == {NETWORKD, NETWORKMANAGER, TOR, POSTURE}
    assert graph.bound_by[ANON] == {FIREWALL}


# -- phase separation ------------------------------------------------------


def test_anonymity_stage_precedes_the_firewall_and_the_network(graph: unitgraph.Graph):
    assert FIREWALL in graph.before[ANON]
    assert "network-pre.target" in graph.before[ANON]


def test_anonymity_stage_runs_only_pre_network_work(root: Path):
    """No Tor-dependent verification may be invoked from the pre-network stage.

    Tor cannot be running at that point -- it is gated on the firewall, which is
    gated on this unit -- so a Tor check here could only ever fail or lie.
    """
    text = (root / ANON).read_text(encoding="utf-8")
    exec_lines = [line for line in text.splitlines() if line.startswith("ExecStart")]
    assert exec_lines, "the anonymity stage has no ExecStart"
    for line in exec_lines:
        assert "verify-tor-path" not in line
        assert "tor" not in line.split("#", 1)[0].lower().replace("amnesic-pi-anon", "")
    assert any("randomize-mac" in line for line in exec_lines)
    assert any("verify-zero-ip" in line for line in exec_lines)


def test_tor_path_verifier_runs_after_tor(graph: unitgraph.Graph, root: Path):
    assert TOR in graph.after[POSTURE]
    assert TOR in graph.requires[POSTURE]
    assert "verify-tor-path" in (root / POSTURE).read_text(encoding="utf-8")


def test_posture_stage_is_still_bound_to_the_firewall(graph: unitgraph.Graph):
    """A posture verified against a policy that has since gone is not verified."""
    assert FIREWALL in graph.binds_to[POSTURE]
    assert FIREWALL in graph.after[POSTURE]


def test_ready_target_requires_every_stage(graph: unitgraph.Graph):
    """READY is the end of the pipeline, not a synonym for "booted"."""
    for stage in (ANON, FIREWALL, TOR, POSTURE):
        assert stage in graph.requires[READY], f"{READY} does not require {stage}"
        assert stage in graph.after[READY], f"{READY} is not ordered after {stage}"


def test_firewall_is_ordered_before_every_network_consumer(graph: unitgraph.Graph):
    for consumer in (NETWORKD, NETWORKMANAGER, TOR):
        assert consumer in graph.before[FIREWALL]


# -- failure and teardown paths -------------------------------------------


def test_failure_paths_reach_lockdown(graph: unitgraph.Graph):
    for unit in (ANON, FIREWALL):
        assert LOCKDOWN in graph.on_failure[unit], f"{unit} has no OnFailure lockdown"


def test_explicit_stop_also_reaches_lockdown(root: Path):
    """OnFailure= is not a universal cleanup mechanism.

    It fires on the unit entering a failed state. An administrator `systemctl
    stop`, a dependency teardown and shutdown are *not* failures, and for a
    Type=oneshot unit whose ExecStart failed systemd does not run ExecStop at
    all. Both directives are therefore required; neither subsumes the other.
    """
    text = (root / "amnesic-pi-firewall.service").read_text(encoding="utf-8")
    exec_stop = [line for line in text.splitlines() if line.startswith("ExecStop=")]
    assert exec_stop, "no ExecStop: an explicit stop would leave the last posture in place"
    assert all("lockdown" in line for line in exec_stop)


def test_firewall_grants_forwarding_and_the_sysctl_baseline_does_not():
    """Forwarding authority lives inside the firewall transaction, nowhere else."""
    baseline = Path("config/99-amnesic-pi.conf").read_text(encoding="utf-8")
    for knob in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
        assignments = [
            line for line in baseline.splitlines()
            if line.strip().startswith(knob) and "=" in line
        ]
        assert assignments, f"{knob} is not pinned in the sysctl baseline"
        for line in assignments:
            value = line.split("=", 1)[1].strip()
            assert value == "0", f"{knob} is granted at boot by sysctl: {line!r}"


def test_firewall_runs_after_the_sysctl_baseline(graph: unitgraph.Graph):
    """Otherwise systemd-sysctl would reset forwarding to 0 after the grant."""
    assert "systemd-sysctl.service" in graph.after[FIREWALL]


def test_firewall_applies_then_verifies(root: Path):
    text = (root / FIREWALL).read_text(encoding="utf-8")
    assert "amnesic-pi-firewall apply" in text
    assert "ExecStartPost=" in text and "verify" in text


# -- graph integrity -------------------------------------------------------


def test_no_dependency_cycle(graph: unitgraph.Graph):
    cycles = unitgraph.ordering_cycles(graph)
    assert not cycles, f"ordering cycle in the resolved graph: {cycles}"


UNITS_UNDER_VERIFY = [ANON, FIREWALL, LOCKDOWN, POSTURE, READY]

# ExecStart paths are absolute and only exist once provision.sh has run, so a
# bare verify reports them as missing. That says nothing about the graph.
_NOT_INSTALLED = re.compile(r"Command \S+ is not executable")


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed"
)
def test_systemd_analyze_reports_no_errors(root: Path, tmp_path_factory):
    """Run systemd's own loader over the units as they will be installed.

    Where the distribution's unit directory is available the whole graph is
    resolved inside a throwaway root, so this is systemd resolving real
    targets, not a hand-rolled approximation.
    """
    sysroot = unitgraph.build_sysroot(root, tmp_path_factory.mktemp("sysroot"))
    result = unitgraph.analyze_verify(root, UNITS_UNDER_VERIFY, sysroot=sysroot)
    combined = (result.stdout or "") + (result.stderr or "")
    residue = [
        line
        for line in combined.splitlines()
        if line.strip() and not _NOT_INSTALLED.search(line)
    ]
    assert not residue, "\n".join(residue)
    if sysroot is not None:
        # Nothing to excuse: with a complete root the run must be clean.
        assert result.returncode == 0, combined
    # systemd-analyze can exit 0 while reporting a loop it broke itself.
    assert "Found ordering cycle" not in combined, combined
    assert "Found dependency on" not in combined, combined


def test_unit_commands_are_the_installed_console_scripts(root: Path):
    """Catch a typo'd ExecStart path, which a stubbed verify cannot see."""
    declared = set()
    for line in Path("pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("amnesic-pi") and "=" in line:
            declared.add(f"/usr/local/bin/{line.split('=', 1)[0].strip()}")
    used = unitgraph.exec_binaries(root, repo_units_only=True)
    assert used, "no ExecStart commands found in the units"
    assert used <= declared, f"units invoke commands the package does not provide: {used - declared}"

    provision = Path("image/provision.sh").read_text(encoding="utf-8")
    for binary in sorted(used):
        name = Path(binary).name
        assert name in provision, f"{name} is never installed by provision.sh"


def test_install_map_covers_every_repository_unit():
    """A unit added to systemd/ but never installed would gate nothing."""
    mapped = {source for source, _ in unitgraph.install_pairs()}
    on_disk = {
        path.name
        for path in Path("systemd").iterdir()
        if path.suffix in {".service", ".target", ".conf"}
    }
    assert on_disk == mapped, f"unmapped units: {sorted(on_disk ^ mapped)}"


def test_drop_ins_land_on_the_units_they_are_meant_to_gate():
    destinations = dict(unitgraph.install_pairs())
    assert destinations["tor-amnesic-pi.conf"].startswith("tor@default.service.d/")
    assert destinations["networkd-amnesic-pi.conf"].startswith("systemd-networkd.service.d/")
    assert destinations["NetworkManager-amnesic-pi.conf"].startswith("NetworkManager.service.d/")
