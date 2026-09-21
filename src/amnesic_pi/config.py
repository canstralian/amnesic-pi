from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
# Hostnames used as Tor probe targets. Deliberately strict: these values are
# passed to a resolver and to a SOCKS request, never to a shell.
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class ConfigError(ValueError):
    pass


def _parse_bool(label: str, value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"1", "yes", "true", "on"}:
        return True
    if lowered in {"0", "no", "false", "off"}:
        return False
    raise ConfigError(f"{label} must be a boolean (yes/no), got {value!r}")


@dataclass(frozen=True)
class Config:
    uplink_if: str
    client_if: str
    trans_port: int = 9040
    dns_port: int = 5353
    socks_port: int = 9050
    tor_user: str = "debian-tor"
    # Interfaces whose MAC is randomized in the pre-network anonymity stage.
    # Defaults to both role interfaces; an empty tuple is never allowed because
    # "randomize nothing" would silently weaken the anonymity gate.
    mac_ifaces: tuple[str, ...] = field(default=())
    # Bounded wait for slow device enumeration (headless Pi + USB-Ethernet).
    # This is a retry budget, not a relaxation of the dependency graph.
    iface_wait_seconds: float = 20.0
    # Tor-path probe targets. Used only after Tor has bootstrapped.
    tor_probe_host: str = "check.torproject.org"
    tor_probe_port: int = 443
    tor_dns_probe_name: str = "check.torproject.org"
    # Observational telemetry only. Empty disables the external echo probe.
    egress_echo_host: str = ""
    egress_echo_path: str = "/"

    def resolved_mac_ifaces(self) -> tuple[str, ...]:
        return self.mac_ifaces or (self.uplink_if, self.client_if)

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
            ("TOR_PROBE_PORT", self.tor_probe_port),
        ):
            if not 1 <= value <= 65535:
                raise ConfigError(f"{label} must be between 1 and 65535")
        if len({self.trans_port, self.dns_port, self.socks_port}) != 3:
            raise ConfigError("Tor listener ports must be distinct")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.tor_user):
            raise ConfigError(f"TOR_USER is invalid: {self.tor_user!r}")

        for name in self.mac_ifaces:
            if not _IFACE_RE.fullmatch(name):
                raise ConfigError(f"MAC_IFACES contains an invalid interface name: {name!r}")
        if len(set(self.mac_ifaces)) != len(self.mac_ifaces):
            raise ConfigError("MAC_IFACES contains duplicate interface names")

        if not 0 < self.iface_wait_seconds <= 300:
            raise ConfigError("IFACE_WAIT_SECONDS must be greater than 0 and at most 300")

        for label, value in (
            ("TOR_PROBE_HOST", self.tor_probe_host),
            ("TOR_DNS_PROBE_NAME", self.tor_dns_probe_name),
        ):
            if not _HOST_RE.fullmatch(value) or len(value) > 253:
                raise ConfigError(f"{label} is not a valid hostname: {value!r}")
        if self.egress_echo_host and (
            not _HOST_RE.fullmatch(self.egress_echo_host) or len(self.egress_echo_host) > 253
        ):
            raise ConfigError(f"EGRESS_ECHO_HOST is not a valid hostname: {self.egress_echo_host!r}")
        if not self.egress_echo_path.startswith("/"):
            raise ConfigError("EGRESS_ECHO_PATH must start with '/'")


ALLOWED_KEYS = frozenset(
    {
        "UPLINK_IF",
        "CLIENT_IF",
        "TRANS_PORT",
        "DNS_PORT",
        "SOCKS_PORT",
        "TOR_USER",
        "MAC_IFACES",
        "IFACE_WAIT_SECONDS",
        "TOR_PROBE_HOST",
        "TOR_PROBE_PORT",
        "TOR_DNS_PROBE_NAME",
        "EGRESS_ECHO_HOST",
        "EGRESS_ECHO_PATH",
    }
)


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

    unknown = set(values) - ALLOWED_KEYS
    if unknown:
        raise ConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")

    mac_ifaces_raw = values.get("MAC_IFACES", "").strip()
    mac_ifaces = tuple(part for part in re.split(r"[,\s]+", mac_ifaces_raw) if part)

    try:
        cfg = Config(
            uplink_if=values["UPLINK_IF"],
            client_if=values["CLIENT_IF"],
            trans_port=int(values.get("TRANS_PORT", "9040")),
            dns_port=int(values.get("DNS_PORT", "5353")),
            socks_port=int(values.get("SOCKS_PORT", "9050")),
            tor_user=values.get("TOR_USER", "debian-tor"),
            mac_ifaces=mac_ifaces,
            iface_wait_seconds=float(values.get("IFACE_WAIT_SECONDS", "20")),
            tor_probe_host=values.get("TOR_PROBE_HOST", "check.torproject.org"),
            tor_probe_port=int(values.get("TOR_PROBE_PORT", "443")),
            tor_dns_probe_name=values.get("TOR_DNS_PROBE_NAME", "check.torproject.org"),
            egress_echo_host=values.get("EGRESS_ECHO_HOST", ""),
            egress_echo_path=values.get("EGRESS_ECHO_PATH", "/"),
        )
    except KeyError as exc:
        raise ConfigError(f"missing required configuration key: {exc.args[0]}") from exc
    except ValueError as exc:
        raise ConfigError(f"numeric configuration value is invalid: {exc}") from exc

    cfg.validate()
    return cfg
