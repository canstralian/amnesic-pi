"""The `amnesic-pi` umbrella command.

Three executables exist, matching the boot stages they gate:

    amnesic-pi-anon      pre-network anonymity (MAC, zero-IP) and, at the other
                         end of the boot, post-Tor egress posture
    amnesic-pi-firewall  the authority transaction (apply / verify / lockdown)
    amnesic-pi           umbrella carrying both, plus render-firewall

The systemd units call the stage-specific names so a unit file reads as the
stage it gates.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .anon import cmd_randomize_mac, cmd_verify_tor_path, cmd_verify_zero_ip
from .clihelp import add_common, authority_for, load_config, report
from .firewall import FirewallError, render_file, tor_uid
from .fw import cmd_apply, cmd_lockdown, cmd_verify
from .verify import verify as verify_posture


def cmd_render(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    try:
        uid = args.tor_uid if args.tor_uid is not None else tor_uid(config)
        rendered = render_file(args.template, config, uid)
    except (OSError, FirewallError) as exc:
        print(f"firewall render error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(rendered)
    return 0


def cmd_verify_all(args: argparse.Namespace) -> int:
    """Read-only: the firewall posture plus the Tor listener checks.

    Kept distinct from `firewall verify`, which is deliberately about network
    authority alone. Neither mutates the system. Neither is a substitute for
    `anon verify-tor-path`, which is the only command that exercises the Tor
    path itself.
    """
    config = load_config(args.config)
    return 0 if report(verify_posture(config, authority=authority_for(args))) else 1


def _add_firewall_subcommands(sub: argparse._SubParsersAction) -> None:
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


def _add_anon_subcommands(sub: argparse._SubParsersAction) -> None:
    mac = sub.add_parser(
        "randomize-mac", help="randomize interface MACs and verify the change took effect"
    )
    mac.set_defaults(func=cmd_randomize_mac)

    zero_ip = sub.add_parser(
        "verify-zero-ip", help="assert the role interfaces carry no IP before the network starts"
    )
    zero_ip.set_defaults(func=cmd_verify_zero_ip)

    tor_path = sub.add_parser(
        "verify-tor-path",
        help="post-Tor egress posture verification; runs after Tor, never before the firewall",
    )
    tor_path.add_argument("--require-observation", action="store_true")
    tor_path.set_defaults(func=cmd_verify_tor_path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amnesic-pi")
    add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    render = sub.add_parser("render-firewall", help="print the rendered nftables policy")
    render.add_argument("--tor-uid", type=int)
    render.set_defaults(func=cmd_render)

    firewall = sub.add_parser("firewall", help="firewall authority transaction")
    _add_firewall_subcommands(firewall.add_subparsers(dest="firewall_command", required=True))

    anon = sub.add_parser("anon", help="anonymity stages")
    _add_anon_subcommands(anon.add_subparsers(dest="anon_command", required=True))

    # Retained spellings from before the authority model was split into stages.
    # `apply-firewall` now runs the full transaction, so it is no longer
    # possible to apply policy without also proving it before forwarding.
    legacy_apply = sub.add_parser("apply-firewall", help="alias for `firewall apply`")
    legacy_apply.set_defaults(func=cmd_apply)

    legacy_verify = sub.add_parser(
        "verify", help="firewall posture plus Tor listener checks (read-only)"
    )
    legacy_verify.set_defaults(func=cmd_verify_all)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
