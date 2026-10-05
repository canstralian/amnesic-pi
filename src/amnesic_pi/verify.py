"""Read-only posture verification.

This module is the stable name for "check the live kernel state against the
intended security posture". The checks themselves live in `authority` (network
authority) and `torpath` (post-Tor egress posture); this is the seam the CLI
and the tests use.

Nothing here mutates the system. If a check cannot be performed, it fails --
an unprovable posture is not a passing posture.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from .authority import Authority, Check
from .config import Config
from .netif import Runner

__all__ = ["Check", "verify", "tor_listener_checks"]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    # Via Runner.default(), so an absent binary becomes returncode 127 rather
    # than a FileNotFoundError. A probe that cannot run is a failed check, and
    # this module promises a FAIL row rather than a traceback.
    return Runner.default().run(args)


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


def _udp_port_listening(stdout: str, port: int) -> bool:
    """Does any line of `ss -H -lun` output show a listener on exactly `port`?

    Not a substring match: `:5353` is a substring of `0.0.0.0:53530`, so a
    completely unrelated UDP listener on 53530 would satisfy a check meant to
    prove port 5353. The local-address:port field is always the fourth
    whitespace-separated column in `ss -H` output (no header, so this is the
    first row); the port itself is whatever follows the *last* `:`, which
    handles bracketed IPv6 forms (`[::]:5353`) the same as IPv4.
    """
    target = str(port)
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        local = fields[3]
        if ":" not in local:
            continue
        if local.rsplit(":", 1)[1] == target:
            return True
    return False


def tor_listener_checks(config: Config) -> list[Check]:
    """Confirm the configured Tor listeners exist.

    A listener existing is a hard gate; it is not evidence that traffic leaves
    through Tor. That claim belongs to `torpath.verify_tor_path`, which runs
    after Tor has bootstrapped.
    """
    checks = [Check("Tor TransPort", _port_open(config.trans_port), str(config.trans_port))]
    # DNSPort is UDP and cannot be proven with a TCP connect probe; listener
    # state is read from `ss` instead.
    ss = _run("ss", "-H", "-lun")
    detail = str(config.dns_port)
    listening = ss.returncode == 0 and _udp_port_listening(ss.stdout or "", config.dns_port)
    checks.append(Check("Tor DNSPort", listening, detail))
    return checks


def verify(
    config: Config,
    authority: Authority | None = None,
    template: Path | None = None,
) -> list[Check]:
    """Full read-only check: network authority posture plus Tor listeners."""
    if authority is None:
        authority = (
            Authority.default(config, template=template)
            if template is not None
            else Authority.default(config)
        )
    return authority.verify() + tor_listener_checks(config)
