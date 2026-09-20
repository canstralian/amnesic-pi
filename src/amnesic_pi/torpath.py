"""Post-Tor egress posture verification.

This runs *after* Tor has started. It is deliberately not the pre-network
anonymity gate: the pre-network gate (MAC, zero-IP, firewall) cannot depend on
Tor, because Tor is not allowed to start until that gate has passed.

Checks are split into two kinds, and the distinction is the point of the
module:

HARD    -- the appliance's security posture. A failure means the appliance is
           not ready. Examples: the nftables policy is installed and verified,
           the configured Tor listeners exist, Tor can complete a circuit.

OBSERVED -- third-party telemetry. A reachable echo service reporting an exit
           address is informative; an *unreachable* echo service is an outage,
           not proof of a leak, and must not decide readiness. The one case
           where telemetry fails hard is a positive leak signal: an observed
           external address that belongs to this appliance.

Note on DNS: proving Tor's DNSPort resolves names proves that path works. It
does not prove some other process cannot send DNS directly -- that is an
nftables invariant, asserted in the firewall policy checks and in the
namespace regression tests, not here.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from .authority import Authority
from .config import Config

SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_CONNECT = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_SUCCEEDED = 0x00


class Kind(Enum):
    HARD = "HARD"
    OBSERVED = "OBSERVED"


@dataclass(frozen=True)
class PostureCheck:
    name: str
    ok: bool
    detail: str
    kind: Kind = Kind.HARD

    @property
    def blocking(self) -> bool:
        """Only hard failures block readiness."""
        return self.kind is Kind.HARD and not self.ok


class TorPathError(RuntimeError):
    pass


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def socks_connect(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 30.0,
) -> socket.socket:
    """Open a SOCKS5 CONNECT through Tor and return the live socket.

    Tor answers a CONNECT only once it has a usable circuit, so a success here
    is also the bootstrap proof. The hostname is passed as a domain rather than
    resolved locally, which keeps name resolution inside Tor.
    """
    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(bytes([SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]))
        greeting = sock.recv(2)
        if len(greeting) != 2 or greeting[0] != SOCKS5_VERSION or greeting[1] != SOCKS5_NO_AUTH:
            raise TorPathError("SOCKS5 greeting was refused by the local Tor listener")

        encoded = target_host.encode("idna")
        if len(encoded) > 255:
            raise TorPathError("SOCKS5 target hostname is too long")
        request = bytes([SOCKS5_VERSION, SOCKS5_CONNECT, 0x00, SOCKS5_ATYP_DOMAIN, len(encoded)])
        request += encoded + struct.pack("!H", target_port)
        sock.sendall(request)

        reply = sock.recv(4)
        if len(reply) != 4 or reply[0] != SOCKS5_VERSION:
            raise TorPathError("malformed SOCKS5 reply from the local Tor listener")
        if reply[1] != SOCKS5_SUCCEEDED:
            raise TorPathError(
                f"Tor refused the SOCKS5 CONNECT (reply code {reply[1]}); "
                "the circuit is not usable"
            )
        # Drain the bound-address field so the socket is positioned at payload.
        atyp = reply[3]
        if atyp == 0x01:
            sock.recv(4)
        elif atyp == SOCKS5_ATYP_DOMAIN:
            length = sock.recv(1)
            sock.recv(length[0] if length else 0)
        elif atyp == 0x04:
            sock.recv(16)
        sock.recv(2)
        return sock
    except OSError as exc:
        sock.close()
        raise TorPathError(f"SOCKS5 negotiation failed: {exc}") from exc
    except TorPathError:
        sock.close()
        raise


def build_dns_query(name: str, transaction_id: int = 0x1337) -> bytes:
    """Minimal DNS A query. Avoids depending on a resolver library."""
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label for label in name.encode("idna").split(b".") if label
    )
    return header + question + b"\x00" + struct.pack("!HH", 1, 1)


def dns_answer_count(response: bytes) -> int:
    if len(response) < 12:
        raise TorPathError("DNS response is truncated")
    flags, _, ancount = struct.unpack("!HHH", response[2:8])
    rcode = flags & 0x0F
    if rcode != 0:
        raise TorPathError(f"DNS response carried rcode {rcode}")
    return ancount


def resolve_via_tor_dns(name: str, port: int, host: str = "127.0.0.1", timeout: float = 20.0) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(build_dns_query(name), (host, port))
        response, _ = sock.recvfrom(4096)
    except OSError as exc:
        raise TorPathError(f"Tor DNSPort query failed: {exc}") from exc
    finally:
        sock.close()
    return dns_answer_count(response)


def local_addresses(config: Config, authority: Authority) -> set[str]:
    """Every IP this appliance holds on its own role interfaces."""
    found: set[str] = set()
    for iface in {config.uplink_if, config.client_if}:
        try:
            entries = authority.interfaces.assigned_addresses(iface)
        except Exception:  # noqa: BLE001 - telemetry only; never block readiness
            continue
        for entry in entries:
            value = entry.split(" ", 1)[-1].split("/", 1)[0]
            try:
                found.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
    return found


def observe_external_address(
    config: Config,
    timeout: float = 45.0,
    connect: Callable[..., socket.socket] = socks_connect,
) -> str | None:
    """Fetch the exit-observed address through Tor. Telemetry, not a gate."""
    if not config.egress_echo_host:
        return None
    sock = connect("127.0.0.1", config.socks_port, config.egress_echo_host, 80, timeout)
    try:
        request = (
            f"GET {config.egress_echo_path} HTTP/1.1\r\n"
            f"Host: {config.egress_echo_host}\r\n"
            "Connection: close\r\n"
            "User-Agent: amnesic-pi\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        chunks: list[bytes] = []
        while len(b"".join(chunks)) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    body = b"".join(chunks).split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace").strip()
    for token in body.replace(",", " ").split():
        try:
            return str(ipaddress.ip_address(token.strip()))
        except ValueError:
            continue
    return None


def verify_tor_path(
    config: Config,
    authority: Authority,
    require_observation: bool = False,
    timeout: float = 45.0,
) -> list[PostureCheck]:
    """Prove the post-Tor egress posture. Hard gates first, telemetry last."""
    checks: list[PostureCheck] = []

    # The firewall posture is re-proven here rather than assumed: this unit is
    # the last gate before the appliance declares itself ready.
    for check in authority.verify():
        checks.append(PostureCheck(f"firewall: {check.name}", check.ok, check.detail))

    trans_ok = _tcp_probe("127.0.0.1", config.trans_port, timeout=5.0)
    checks.append(
        PostureCheck("Tor TransPort listener", trans_ok, f"127.0.0.1:{config.trans_port}")
    )

    socks_ok = _tcp_probe("127.0.0.1", config.socks_port, timeout=5.0)
    checks.append(PostureCheck("Tor SocksPort listener", socks_ok, f"127.0.0.1:{config.socks_port}"))

    # A completed SOCKS CONNECT is the bootstrap proof: Tor will not answer one
    # until it holds a usable circuit.
    if socks_ok:
        try:
            sock = socks_connect(
                "127.0.0.1",
                config.socks_port,
                config.tor_probe_host,
                config.tor_probe_port,
                timeout,
            )
            sock.close()
            checks.append(
                PostureCheck(
                    "Tor bootstrapped (SOCKS circuit established)",
                    True,
                    f"{config.tor_probe_host}:{config.tor_probe_port}",
                )
            )
        except (TorPathError, OSError) as exc:
            checks.append(
                PostureCheck("Tor bootstrapped (SOCKS circuit established)", False, str(exc))
            )
    else:
        checks.append(
            PostureCheck(
                "Tor bootstrapped (SOCKS circuit established)", False, "SOCKS listener unreachable"
            )
        )

    try:
        answers = resolve_via_tor_dns(config.tor_dns_probe_name, config.dns_port, timeout=timeout)
        checks.append(
            PostureCheck(
                "Tor DNSPort resolves",
                answers > 0,
                f"{config.tor_dns_probe_name}: {answers} answer(s)",
            )
        )
    except TorPathError as exc:
        checks.append(PostureCheck("Tor DNSPort resolves", False, str(exc)))

    checks.append(_external_address_check(config, authority, require_observation, timeout))
    return checks


def _external_address_check(
    config: Config,
    authority: Authority,
    require_observation: bool,
    timeout: float,
) -> PostureCheck:
    """Observational telemetry, with one hard-failure case.

    An echo service that is simply unreachable proves nothing and must not be
    mistaken for a leak. An echo service that reports one of this appliance's
    own addresses is a genuine leak signal and fails hard regardless.
    """
    if not config.egress_echo_host:
        return PostureCheck(
            "external address observed via Tor",
            True,
            "no echo host configured; telemetry disabled",
            Kind.OBSERVED,
        )
    try:
        observed = observe_external_address(config, timeout=timeout)
    except (TorPathError, OSError) as exc:
        return PostureCheck(
            "external address observed via Tor",
            not require_observation,
            f"echo service unreachable ({exc}); this is an outage, not proof of a leak",
            Kind.HARD if require_observation else Kind.OBSERVED,
        )
    if observed is None:
        return PostureCheck(
            "external address observed via Tor",
            not require_observation,
            "echo service returned no parsable address",
            Kind.HARD if require_observation else Kind.OBSERVED,
        )
    mine = local_addresses(config, authority)
    if observed in mine:
        return PostureCheck(
            "external address observed via Tor",
            False,
            f"observed {observed}, which is an address of this appliance: clearnet leak",
            Kind.HARD,
        )
    return PostureCheck(
        "external address observed via Tor",
        True,
        f"observed {observed}, distinct from this appliance's addresses",
        Kind.OBSERVED,
    )
