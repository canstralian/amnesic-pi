from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import Config


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _read_sysctl(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


def _chain_policies(text: str) -> dict[str, str]:
    payload = json.loads(text)
    entries = payload.get("nftables")
    if not isinstance(entries, list):
        raise ValueError("nft JSON is missing the nftables list")

    policies: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        chain = entry.get("chain")
        if not isinstance(chain, dict):
            continue
        name = chain.get("name")
        if name not in {"input", "forward", "output"}:
            continue
        if name in policies:
            raise ValueError(f"duplicate nft chain {name!r}")
        policy = chain.get("policy")
        policies[name] = policy.lower() if isinstance(policy, str) else ""

    return policies


def verify(config: Config) -> list[Check]:
    checks: list[Check] = []

    nft = _run("nft", "-j", "list", "table", "inet", "amnesic_pi")
    policies: dict[str, str] = {}
    parse_error = ""
    if nft.returncode == 0:
        try:
            policies = _chain_policies(nft.stdout)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            parse_error = str(exc)

    table_ok = nft.returncode == 0 and not parse_error
    table_detail = nft.stderr.strip() or parse_error or "present"
    checks.append(Check("nft table", table_ok, table_detail))

    for chain in ("input", "forward", "output"):
        policy = policies.get(chain)
        ok = policy == "drop"
        checks.append(
            Check(
                f"{chain} policy DROP",
                ok,
                policy or "missing/not proven",
            )
        )

    try:
        forwarding = _read_sysctl("/proc/sys/net/ipv4/ip_forward")
    except OSError as exc:
        forwarding = f"error:{exc}"
    checks.append(Check("IPv4 forwarding disabled", forwarding == "0", forwarding))

    ipv6_values: list[str] = []
    for path in (
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/sys/net/ipv6/conf/default/disable_ipv6",
    ):
        try:
            ipv6_values.append(_read_sysctl(path))
        except OSError:
            ipv6_values.append("missing")
    checks.append(Check("IPv6 disabled", all(v == "1" for v in ipv6_values), ",".join(ipv6_values)))

    checks.append(Check("Tor TransPort", _port_open(config.trans_port), str(config.trans_port)))
    # Tor DNSPort is UDP and cannot be proven with a TCP connect probe; listener state is checked via ss.
    ss = _run("ss", "-H", "-lun")
    dns_marker = f":{config.dns_port}"
    checks.append(Check("Tor DNSPort", ss.returncode == 0 and dns_marker in ss.stdout, dns_marker))

    return checks
