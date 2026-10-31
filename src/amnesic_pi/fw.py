"""`amnesic-pi-firewall` -- the authority transaction entry point."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .authority import (
    CONTAINMENT_INCOMPLETE,
    CONTAINMENT_LOCKED_DOWN,
    CONTAINMENT_PRESERVED,
    AuthorityError,
    lockdown,
    lockdown_succeeded,
)
from .clihelp import add_common, authority_for, dispatch, report, require_root
from .nft import Nft
from .shutdown import shutdown_signals
from .sysctl import Sysctl

# What to tell an operator about the appliance's state after a failed apply.
# These are three different situations and only one of them is containment;
# reporting "locked down" for all of them makes the word worthless at exactly
# the moment it has to be trusted.
CONTAINMENT_REPORT = {
    CONTAINMENT_PRESERVED: (
        "the previously installed policy and forwarding state are unchanged "
        "and the appliance was NOT locked down"
    ),
    CONTAINMENT_LOCKED_DOWN: "appliance locked down",
    CONTAINMENT_INCOMPLETE: "lockdown incomplete, posture unproven",
}
UNKNOWN_CONTAINMENT = "containment state unknown"


def cmd_apply(args: argparse.Namespace) -> int:
    denied = require_root("amnesic-pi-firewall apply")
    if denied is not None:
        return denied
    authority = authority_for(args)
    try:
        authority.apply()
    except AuthorityError as exc:
        outcome = CONTAINMENT_REPORT.get(
            getattr(exc, "containment", None), UNKNOWN_CONTAINMENT
        )
        print(f"firewall apply failed, {outcome}: {exc}", file=sys.stderr)
        return 1
    # The transaction reported success. Exit zero only if the live posture
    # still agrees -- a final report nobody acts on is not verification.
    try:
        verified = report(authority.verify())
    except Exception as exc:
        print(f"live posture could not be verified: {exc}", file=sys.stderr)
        verified = False
    if not verified:
        with shutdown_signals(ignore=True):
            try:
                cleanup = authority.lockdown()
                contained = lockdown_succeeded(cleanup)
                report(cleanup, stream=sys.stderr)
            except Exception as exc:
                contained = False
                print(f"lockdown could not complete: {exc}", file=sys.stderr)
        print(
            "firewall apply completed but the live posture failed verification; "
            + ("appliance locked down" if contained else "lockdown incomplete, posture unproven"),
            file=sys.stderr,
        )
        return 1
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
    return dispatch(args, contain_on_interrupt=args.func in {cmd_apply, cmd_lockdown})


if __name__ == "__main__":
    raise SystemExit(main())
