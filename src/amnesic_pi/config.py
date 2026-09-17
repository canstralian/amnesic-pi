from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re


_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    uplink_if: str
    client_if: str
    trans_port: int = 9040
    dns_port: int = 5353
    socks_port: int = 9050
    tor_user: str = "debian-tor"

    def validate(self) -> None:
        for label, value in (("UPLINK_IF", self.uplink_if), ("CLIENT_IF", self.client_if)):
            if not _IFACE_RE.fullmatch(value):
                raise ConfigError(f"{label} is not a valid Linux interface name: {value!r}")
        if self.uplink_if == self.client_if:
            raise ConfigError("UPLINK_IF and CLIENT_IF must be different interfaces")
        for label, value in (
            ("TRANS_PORT", self.trans_port),
            ("DNS_PORT", self.dns_port),
            ("SOCKS_PORT", self.socks_port),
        ):
            if not 1 <= value <= 65535:
                raise ConfigError(f"{label} must be between 1 and 65535")
        if len({self.trans_port, self.dns_port, self.socks_port}) != 3:
            raise ConfigError("Tor listener ports must be distinct")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.tor_user):
            raise ConfigError(f"TOR_USER is invalid: {self.tor_user!r}")


def load_env(path: Path) -> Config:
    values: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key in values:
            raise ConfigError(f"{path}:{lineno}: duplicate key {key}")
        values[key] = value

    allowed = {"UPLINK_IF", "CLIENT_IF", "TRANS_PORT", "DNS_PORT", "SOCKS_PORT", "TOR_USER"}
    unknown = set(values) - allowed
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")

    try:
        cfg = Config(
            uplink_if=values["UPLINK_IF"],
            client_if=values["CLIENT_IF"],
            trans_port=int(values.get("TRANS_PORT", "9040")),
            dns_port=int(values.get("DNS_PORT", "5353")),
            socks_port=int(values.get("SOCKS_PORT", "9050")),
            tor_user=values.get("TOR_USER", "debian-tor"),
        )
    except KeyError as exc:
        raise ConfigError(f"missing required configuration key: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ConfigError(f"port values must be integers: {exc}") from exc

    cfg.validate()
    return cfg
