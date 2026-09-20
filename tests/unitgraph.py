"""Offline resolver for the installed systemd unit graph.

Tests must not settle for grepping unit files for the string "BindsTo=": that
passes even if the directive lands on the wrong unit, sits in a drop-in nothing
installs, or is overridden later. This module instead reproduces what systemd
does at load time -- lay the units out as `systemd/install-map.tsv` says they
will be installed, merge each unit with its drop-ins in lexical order, and
resolve the resulting relationships, including the reverse ones systemd
synthesises (`Before=` implies the other unit's `After=`; `BindsTo=` implies
the other unit's `BoundBy=`).

A future edit that downgrades `BindsTo=` to `Before=` therefore loses a
resolved `binds_to` edge and fails, which is the point.
"""

from __future__ import annotations

import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO_UNITS = Path("systemd")
INSTALL_MAP = REPO_UNITS / "install-map.tsv"

# Directives whose values are space-separated lists of unit names and which
# drop-ins append to rather than replace.
LIST_DIRECTIVES = frozenset(
    {
        "After",
        "Before",
        "BindsTo",
        "Requires",
        "Requisite",
        "Wants",
        "PartOf",
        "Conflicts",
        "OnFailure",
        "WantedBy",
        "RequiredBy",
        "UpheldBy",
    }
)

# Units referenced by the graph that the distribution provides. Stubs are
# generated for them so systemd-analyze can resolve the whole graph offline.
EXTERNAL_UNITS = ("tor@.service", "systemd-networkd.service", "NetworkManager.service")


def install_pairs() -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for line in INSTALL_MAP.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        source, destination = stripped.split("\t", 1)
        pairs.append((source.strip(), destination.strip()))
    return pairs


def materialize(root: Path) -> Path:
    """Lay the repository's units out exactly as provision.sh installs them."""
    root.mkdir(parents=True, exist_ok=True)
    for source, destination in install_pairs():
        target = root / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_UNITS / source, target)
    for name in EXTERNAL_UNITS:
        stub = root / name
        if not stub.exists():
            stub.write_text(
                f"[Unit]\nDescription=test stub for {name}\n\n"
                "[Service]\nType=simple\nExecStart=/bin/true\n",
                encoding="utf-8",
            )
    return root


def _parse(path: Path) -> dict[str, list[str]]:
    """Parse one unit file's [Unit] section, honouring line continuations."""
    directives: dict[str, list[str]] = defaultdict(list)
    section = ""
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = (pending + raw).strip()
        pending = ""
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Unit" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key in LIST_DIRECTIVES and value == "":
            # An empty assignment resets the list, exactly as systemd does.
            directives[key] = []
            continue
        directives[key].append(value)
    return dict(directives)


def _merge(root: Path, unit: str) -> dict[str, list[str]]:
    """Merge a unit file with its .d drop-ins, in systemd's lexical order.

    Instance units (`tor@default.service`) also read the template's drop-in
    directory (`tor@.service.d`), which is how the Tor drop-in reaches the
    running instance.
    """
    merged: dict[str, list[str]] = defaultdict(list)

    def absorb(path: Path) -> None:
        for key, values in _parse(path).items():
            if key in LIST_DIRECTIVES:
                merged[key].extend(values)
            else:
                merged[key] = values

    base = root / unit
    if base.exists():
        absorb(base)
    elif "@" in unit:
        template = unit.split("@", 1)[0] + "@." + unit.rsplit(".", 1)[1]
        if (root / template).exists():
            absorb(root / template)

    dropin_dirs = [root / f"{unit}.d"]
    if "@" in unit:
        template = unit.split("@", 1)[0] + "@." + unit.rsplit(".", 1)[1]
        dropin_dirs.append(root / f"{template}.d")
    for directory in dropin_dirs:
        if not directory.is_dir():
            continue
        for dropin in sorted(directory.glob("*.conf")):
            absorb(dropin)
    return dict(merged)


def _expand(values: list[str]) -> list[str]:
    """Unit lists are space separated; a directive may also be repeated."""
    out: list[str] = []
    for value in values:
        out.extend(value.split())
    return out


@dataclass
class Graph:
    root: Path
    units: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    after: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    before: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    binds_to: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    bound_by: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    requires: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    wants: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    on_failure: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def directive(self, unit: str, key: str) -> list[str]:
        return self.units.get(unit, {}).get(key, [])


def resolve(root: Path, extra_units: tuple[str, ...] = ()) -> Graph:
    """Build the resolved relationship graph for everything under `root`."""
    names: set[str] = set(extra_units)
    for _, destination in install_pairs():
        if destination.endswith((".service", ".target", ".socket", ".mount")):
            names.add(destination)
    # Drop-in directories name the units they extend.
    for path in root.rglob("*.d"):
        stem = path.name[:-2]
        names.add("tor@default.service" if stem == "tor@default.service" else stem)
    names.update(name for name in EXTERNAL_UNITS if not name.endswith("@.service"))
    names.add("tor@default.service")

    graph = Graph(root=root)
    for unit in sorted(names):
        graph.units[unit] = _merge(root, unit)

    for unit, directives in graph.units.items():
        graph.after[unit] |= set(_expand(directives.get("After", [])))
        graph.before[unit] |= set(_expand(directives.get("Before", [])))
        graph.binds_to[unit] |= set(_expand(directives.get("BindsTo", [])))
        graph.requires[unit] |= set(_expand(directives.get("Requires", [])))
        graph.wants[unit] |= set(_expand(directives.get("Wants", [])))
        graph.on_failure[unit] |= set(_expand(directives.get("OnFailure", [])))

    # Reverse edges systemd synthesises.
    for unit in list(graph.units):
        for other in graph.before[unit]:
            graph.after[other].add(unit)
        for other in graph.after[unit]:
            graph.before[other].add(unit)
        for other in graph.binds_to[unit]:
            graph.bound_by[other].add(unit)
    return graph


def ordering_cycles(graph: Graph) -> list[list[str]]:
    """Find cycles in the resolved After= ordering graph (DFS, colour marking)."""
    colour: dict[str, int] = {}
    stack: list[str] = []
    cycles: list[list[str]] = []

    def visit(unit: str) -> None:
        colour[unit] = 1
        stack.append(unit)
        for dependency in sorted(graph.after.get(unit, set())):
            state = colour.get(dependency, 0)
            if state == 0:
                visit(dependency)
            elif state == 1:
                cycles.append(stack[stack.index(dependency) :] + [dependency])
        stack.pop()
        colour[unit] = 2

    for unit in sorted(set(graph.after) | set(graph.units)):
        if colour.get(unit, 0) == 0:
            visit(unit)
    return cycles


SYSTEM_UNIT_DIRS = (Path("/usr/lib/systemd/system"), Path("/lib/systemd/system"))


def exec_binaries(root: Path, repo_units_only: bool = False) -> set[str]:
    """Absolute executables named by ExecStart/ExecStartPost/ExecStop in the units.

    With `repo_units_only`, the external stubs materialize() writes are skipped
    so the result is exactly the commands this repository asks systemd to run.
    """
    if repo_units_only:
        paths = [root / destination for _, destination in install_pairs()]
    else:
        paths = [path for path in root.rglob("*") if path.is_file()]
    binaries: set[str] = set()
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() not in {"ExecStart", "ExecStartPost", "ExecStop", "ExecReload"}:
                continue
            command = value.strip().lstrip("-+!:@").split()
            if command and command[0].startswith("/"):
                binaries.add(command[0])
    return binaries


def build_sysroot(root: Path, sysroot: Path) -> Path | None:
    """Assemble a throwaway root `systemd-analyze --root` can resolve completely.

    The distribution's own units are copied in so targets like sysinit.target
    resolve, and an executable stub is created for each ExecStart path so the
    run reports only graph problems rather than "binary not installed" noise.
    Returns None when no system unit directory is available.
    """
    source = next((candidate for candidate in SYSTEM_UNIT_DIRS if candidate.is_dir()), None)
    if source is None:
        return None
    (sysroot / "usr/lib/systemd").mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source, sysroot / "usr/lib/systemd/system", symlinks=True, dirs_exist_ok=True
    )
    shutil.copytree(root, sysroot / "etc/systemd/system", symlinks=True, dirs_exist_ok=True)
    for binary in exec_binaries(root):
        stub = sysroot / binary.lstrip("/")
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
    return sysroot


def analyze_verify(
    root: Path, units: list[str], sysroot: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run `systemd-analyze verify` against the materialized layout."""
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SYSTEMD_LOG_LEVEL": "warning",
    }
    if sysroot is not None:
        return subprocess.run(
            ["systemd-analyze", "verify", "--no-pager", f"--root={sysroot}", *units],
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
    environment["SYSTEMD_UNIT_PATH"] = f"{root}:"
    return subprocess.run(
        ["systemd-analyze", "verify", "--no-pager", *[str(root / unit) for unit in units]],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
