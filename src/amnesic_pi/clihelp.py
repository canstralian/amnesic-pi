"""Helpers shared by the three command-line entry points."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from .authority import DEFAULT_TEMPLATE, Authority
from .config import Config, ConfigError, load_env

DEFAULT_CONFIG = Path("/etc/amnesic-pi/network.env")


class Reportable(Protocol):
    name: str
    ok: bool
    detail: str


def load_config(path: Path) -> Config:
    try:
        return load_env(path)
    except (OSError, ConfigError) as exc:
        raise SystemExit(f"configuration error: {exc}") from exc


def require_root(command: str) -> int | None:
    """Return an exit code when the command needs root and does not have it."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{command} must run as root", file=sys.stderr)
        return 2
    return None


def authority_for(args: argparse.Namespace) -> Authority:
    return Authority.default(load_config(args.config), template=args.template)


def report(checks: Sequence[Reportable], stream=None) -> bool:
    """Print a check table. Returns True when every *blocking* check passed.

    A check may opt out of blocking readiness (observational telemetry); those
    print as WARN and do not change the exit code.
    """
    stream = stream or sys.stdout
    if not checks:
        return True
    width = max(len(check.name) for check in checks)
    failed = False
    for check in checks:
        blocking = getattr(check, "blocking", not check.ok)
        status = "PASS" if check.ok else ("FAIL" if blocking else "WARN")
        failed |= blocking
        print(f"{status:4}  {check.name:<{width}}  {check.detail}", file=stream)
    return not failed


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
