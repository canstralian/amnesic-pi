from __future__ import annotations

import json
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config

EXPECTED_CHAINS = {
    "input": ("filter", "input"),
    "forward": ("filter", "forward"),
    "output": ("filter", "output"),
}


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _read_sysctl(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, text=True, capture_output=True, check=False)
    except OSError as exc:
        return subprocess.CompletedProcess(args, 127, stdout="", stderr=f"{type(exc).__name__}: {exc}")


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


def _nft_state(text: str) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("nft JSON root must be an object")
    entries = payload.get("nftables")
    if not isinstance(entries, list):
        raise ValueError("nft JSON is missing the nftables list")

    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {name: [] for name in EXPECTED_CHAINS}

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        chain = entry.get("chain")
        if isinstance(chain, dict):
            name = chain.get("name")
            if name in EXPECTED_CHAINS:
                if name in chains:
                    raise ValueError(f"duplicate nft chain {name!r}")
                chains[name] = chain
            continue

        rule = entry.get("rule")
        if isinstance(rule, dict):
            chain_name = rule.get("chain")
            if chain_name in rules:
                rules[chain_name].append(rule)

    return chains, rules


def _chain_policies(text: str) -> dict[str, str]:
    chains, _ = _nft_state(text)
    policies: dict[str, str] = {}
    for name, chain in chains.items():
        policy = chain.get("policy", "accept")
        policies[name] = policy.lower() if isinstance(policy, str) else "invalid"
    return policies


def verify_firewall() -> list[Check]:
    checks: list[Check] = []
    nft = _run("nft", "-j", "list", "table", "inet", "amnesic_pi")

    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {name: [] for name in EXPECTED_CHAINS}
    parse_error = ""

    if nft.returncode == 0:
        try:
            chains, rules = _nft_state(nft.stdout)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            parse_error = str(exc)

    table_ok = nft.returncode == 0 and not parse_error
    table_detail = nft.stderr.strip() or parse_error or "present"
    checks.append(Check("nft table", table_ok, table_detail))

    for name, (expected_type, expected_hook) in EXPECTED_CHAINS.items():
        chain = chains.get(name)
        if chain is None:
            checks.append(Check(f"{name} policy DROP", False, "missing/not proven"))
            continue

        policy = chain.get("policy", "accept")
        actual_policy = policy.lower() if isinstance(policy, str) else "invalid"
        actual_type = chain.get("type")
        actual_hook = chain.get("hook")
        ok = (
            actual_policy == "drop"
            and actual_type == expected_type
            and actual_hook == expected_hook
        )
        detail = f"policy={actual_policy} type={actual_type!s} hook={actual_hook!s}"
        checks.append(Check(f"{name} policy DROP", ok, detail))

    forward_rules = rules.get("forward", [])
    checks.append(
        Check(
            "forward chain has no rules",
            not forward_rules,
            f"{len(forward_rules)} rule(s)",
        )
    )

    return checks


def verify_enforced_mode(unit_root: Path = Path("/etc/systemd/system")) -> list[Check]:
    checks: list[Check] = []

    enabled = _run("systemctl", "is-enabled", "amnesic-pi-firewall.service")
    checks.append(
        Check(
            "firewall enabled",
            enabled.returncode == 0 and enabled.stdout.strip() == "enabled",
            enabled.stdout.strip() or enabled.stderr.strip() or f"rc={enabled.returncode}",
        )
    )

    required_link = (
        unit_root
        / "NetworkManager.service.requires"
        / "amnesic-pi-firewall.service"
    )
    checks.append(
        Check(
            "NetworkManager .requires link",
            required_link.is_symlink(),
            str(required_link),
        )
    )

    requires = _run(
        "systemctl",
        "show",
        "NetworkManager.service",
        "--property=Requires",
        "--value",
    )
    required_units = set(requires.stdout.split()) if requires.returncode == 0 else set()
    checks.append(
        Check(
            "NetworkManager requires firewall",
            "amnesic-pi-firewall.service" in required_units,
            requires.stdout.strip() or requires.stderr.strip() or f"rc={requires.returncode}",
        )
    )

    after = _run(
        "systemctl",
        "show",
        "NetworkManager.service",
        "--property=After",
        "--value",
    )
    after_units = set(after.stdout.split()) if after.returncode == 0 else set()
    checks.append(
        Check(
            "NetworkManager starts after firewall",
            "amnesic-pi-firewall.service" in after_units,
            after.stdout.strip() or after.stderr.strip() or f"rc={after.returncode}",
        )
    )

    unit_text = _run("systemctl", "cat", "amnesic-pi-firewall.service")
    has_condition = bool(
        re.search(r"(?m)^\s*Condition[A-Za-z0-9]+\s*=", unit_text.stdout)
    )
    checks.append(
        Check(
            "firewall has no Condition skip",
            unit_text.returncode == 0 and not has_condition,
            unit_text.stderr.strip() or ("condition present" if has_condition else "none"),
        )
    )

    refuse_stop = _run(
        "systemctl",
        "show",
        "amnesic-pi-firewall.service",
        "--property=RefuseManualStop",
        "--value",
    )
    checks.append(
        Check(
            "manual firewall stop refused",
            refuse_stop.returncode == 0 and refuse_stop.stdout.strip() == "yes",
            refuse_stop.stdout.strip() or refuse_stop.stderr.strip() or f"rc={refuse_stop.returncode}",
        )
    )

    return checks


def verify(config: Config) -> list[Check]:
    checks = verify_firewall()

    try:
        forwarding = _read_sysctl("/proc/sys/net/ipv4/ip_forward")
    except OSError as exc:
        forwarding = f"error:{exc}"
    checks.append(Check("IPv4 forwarding", forwarding == "1", forwarding))

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

    try:
        ipv6_forwarding = _read_sysctl("/proc/sys/net/ipv6/conf/all/forwarding")
    except OSError as exc:
        ipv6_forwarding = f"error:{exc}"
    checks.append(Check("IPv6 forwarding disabled", ipv6_forwarding == "0", ipv6_forwarding))

    checks.append(Check("Tor TransPort", _port_open(config.trans_port), str(config.trans_port)))
    # Tor DNSPort is UDP and cannot be proven with a TCP connect probe; listener state is checked via ss.
    ss = _run("ss", "-H", "-lun")
    dns_marker = f":{config.dns_port}"
    checks.append(Check("Tor DNSPort", ss.returncode == 0 and dns_marker in ss.stdout, dns_marker))

    return checks
