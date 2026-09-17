from __future__ import annotations

from dataclasses import dataclass
import socket
import subprocess
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


def verify(config: Config) -> list[Check]:
    checks: list[Check] = []

    nft = _run("nft", "list", "table", "inet", "amnesic_pi")
    checks.append(Check("nft table", nft.returncode == 0, nft.stderr.strip() or "present"))

    text = nft.stdout
    for chain in ("input", "forward", "output"):
        marker = f"chain {chain}"
        start = text.find(marker)
        segment = text[start : start + 700] if start >= 0 else ""
        ok = start >= 0 and "policy drop" in segment.lower()
        checks.append(Check(f"{chain} policy DROP", ok, "drop" if ok else "not proven"))

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

    checks.append(Check("Tor TransPort", _port_open(config.trans_port), str(config.trans_port)))
    # Tor DNSPort is UDP and cannot be proven with a TCP connect probe; listener state is checked via ss.
    ss = _run("ss", "-H", "-lun")
    dns_marker = f":{config.dns_port}"
    checks.append(Check("Tor DNSPort", ss.returncode == 0 and dns_marker in ss.stdout, dns_marker))

    return checks
