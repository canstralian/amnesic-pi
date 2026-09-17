from __future__ import annotations

import pwd
from pathlib import Path

from .config import Config


class FirewallError(RuntimeError):
    pass


def tor_uid(config: Config) -> int:
    try:
        return pwd.getpwnam(config.tor_user).pw_uid
    except KeyError as exc:
        raise FirewallError(f"Tor user {config.tor_user!r} does not exist") from exc


def render(template: str, config: Config, uid: int) -> str:
    config.validate()
    if uid < 0:
        raise FirewallError("Tor UID must be non-negative")

    replacements = {
        "@UPLINK_IF@": config.uplink_if,
        "@CLIENT_IF@": config.client_if,
        "@TRANS_PORT@": str(config.trans_port),
        "@DNS_PORT@": str(config.dns_port),
        "@TOR_UID@": str(uid),
    }
    rendered = template
    for token, value in replacements.items():
        rendered = rendered.replace(token, value)

    leftovers = [token for token in replacements if token in rendered]
    if leftovers:
        raise FirewallError(f"unrendered firewall tokens: {', '.join(leftovers)}")
    return rendered


def render_file(template_path: Path, config: Config, uid: int) -> str:
    return render(template_path.read_text(encoding="utf-8"), config, uid)
