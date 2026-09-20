"""`amnesic-pi-firewall` -- the authority transaction entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .authority import AuthorityError, lockdown, lockdown_succeeded
from .clihelp import add_common, authority_for, report, require_root
from .nft import Nft
from .sysctl import Sysctl


def cmd_apply(args: argparse.Namespace) -> int:
    denied = require_root("amnesic-pi-firewall apply")
    if denied is not None:
        return denied
    authority = authority_for(args)
    try:
        authority.apply()
    except AuthorityError as exc:
        print(f"firewall apply failed, appliance locked down: {exc}", file=sys.stderr)
        return 1
    report(authority.verify())
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Read-only. Never mutates the system, including on failure."""
    authority = authority_for(args)
    return 0 if report(authority.verify()) else 1


def cmd_lockdown(args: argparse.Namespace) -> int:
    """Tear the appliance down. Deliberately does NOT load the configuration.

    systemd runs this from OnFailure= and ExecStop=. If a typo in
    /etc/amnesic-pi/network.env is what made the firewall unit fail, handing
    that same file to lockdown would make the containment fail for the same
    reason and leave forwarding enabled. Lockdown needs nothing from it: the
    forwarding knobs and the deny ruleset are constants.
    """
    denied = require_root("amnesic-pi-firewall lockdown")
    if denied is not None:
        return denied
    checks = lockdown(Nft.default(), Sysctl())
    report(checks)
    return 0 if lockdown_succeeded(checks) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="amnesic-pi-firewall",
        description="Install, verify, or tear down Amnesic Pi network authority.",
    )
    add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    apply_cmd = sub.add_parser(
        "apply", help="verify topology, install policy, verify it, then grant forwarding"
    )
    apply_cmd.set_defaults(func=cmd_apply)

    verify_cmd = sub.add_parser("verify", help="read-only check of the live security posture")
    verify_cmd.set_defaults(func=cmd_verify)

    lockdown_cmd = sub.add_parser(
        "lockdown", help="disable forwarding, then install an unconditional deny posture"
    )
    lockdown_cmd.set_defaults(func=cmd_lockdown)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
