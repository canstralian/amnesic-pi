from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import ConfigError, load_env
from .firewall import FirewallError, render_file, tor_uid
from .verify import Check, verify, verify_enforced_mode, verify_firewall

DEFAULT_CONFIG = Path("/etc/amnesic-pi/network.env")
DEFAULT_TEMPLATE = Path("/usr/share/amnesic-pi/policy.nft.in")


def _load(path: Path):
    try:
        return load_env(path)
    except (OSError, ConfigError) as exc:
        raise SystemExit(f"configuration error: {exc}") from exc


def _print_checks(checks: list[Check]) -> int:
    width = max(len(c.name) for c in checks)
    failed = False
    for check in checks:
        status = "PASS" if check.ok else "FAIL"
        failed |= not check.ok
        print(f"{status:4}  {check.name:<{width}}  {check.detail}")
    return 1 if failed else 0


def cmd_render(args: argparse.Namespace) -> int:
    config = _load(args.config)
    try:
        uid = args.tor_uid if args.tor_uid is not None else tor_uid(config)
        rendered = render_file(args.template, config, uid)
    except (OSError, FirewallError) as exc:
        print(f"firewall render error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(rendered)
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    if hasattr(os := __import__("os"), "geteuid") and os.geteuid() != 0:
        print("apply-firewall must run as root", file=sys.stderr)
        return 2
    config = _load(args.config)
    try:
        rendered = render_file(args.template, config, tor_uid(config))
    except (OSError, FirewallError) as exc:
        print(f"firewall render error: {exc}", file=sys.stderr)
        return 2

    # Replace only our table. nft batches are transactional: if any command fails,
    # the existing ruleset remains unchanged. The delete command is included only
    # when the table currently exists so first boot does not fail on ENOENT.
    present = subprocess.run(
        ["nft", "list", "table", "inet", "amnesic_pi"],
        text=True,
        capture_output=True,
        check=False,
    ).returncode == 0
    transaction = ("delete table inet amnesic_pi\n" if present else "") + rendered

    with tempfile.NamedTemporaryFile("w", prefix="amnesic-pi-", suffix=".nft", delete=False) as fh:
        fh.write(transaction)
        candidate = Path(fh.name)
    try:
        check = subprocess.run(["nft", "-c", "-f", str(candidate)], check=False)
        if check.returncode != 0:
            print("candidate nftables policy failed validation; existing ruleset untouched", file=sys.stderr)
            return check.returncode
        apply = subprocess.run(["nft", "-f", str(candidate)], check=False)
        return apply.returncode
    finally:
        candidate.unlink(missing_ok=True)


def cmd_verify(args: argparse.Namespace) -> int:
    return _print_checks(verify(_load(args.config)))


def cmd_verify_firewall(_args: argparse.Namespace) -> int:
    return _print_checks(verify_firewall())


def cmd_verify_enforced_mode(_args: argparse.Namespace) -> int:
    return _print_checks(verify_enforced_mode())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amnesic-pi")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    sub = parser.add_subparsers(dest="command", required=True)

    render = sub.add_parser("render-firewall")
    render.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    render.add_argument("--tor-uid", type=int)
    render.set_defaults(func=cmd_render)

    apply = sub.add_parser("apply-firewall")
    apply.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    apply.set_defaults(func=cmd_apply)

    verify_cmd = sub.add_parser("verify")
    verify_cmd.set_defaults(func=cmd_verify)

    verify_firewall_cmd = sub.add_parser("verify-firewall")
    verify_firewall_cmd.set_defaults(func=cmd_verify_firewall)

    verify_mode_cmd = sub.add_parser("verify-enforced-mode")
    verify_mode_cmd.set_defaults(func=cmd_verify_enforced_mode)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
