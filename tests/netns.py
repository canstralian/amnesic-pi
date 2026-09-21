"""Linux network-namespace harness for packet-level fail-closed testing.

Three namespaces model the appliance and its neighbours:

    client  --veth--  gateway  --veth--  uplink

The gateway runs the real `amnesic-pi-firewall apply` transaction against the
veth pair, with the real nftables template. The uplink namespace counts every
packet that arrives from the client subnet, so a leak is a number rather than
an inference: any count above zero means a client packet crossed the gateway.

This is the evidence that matters. Asserting on `subprocess.run` arguments
proves the code called `nft`; counting packets in another namespace proves the
kernel did not forward.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

# The appliance's shipped sysctl baseline. Applied to the gateway namespace
# exactly as systemd-sysctl applies it at boot, so the tests exercise the file
# that actually ships rather than whatever the host happens to default to.
SYSCTL_BASELINE = Path(__file__).resolve().parent.parent / "config" / "99-amnesic-pi.conf"

CLIENT_ADDR = "10.77.0.2"
GATEWAY_CLIENT_ADDR = "10.77.0.1"
GATEWAY_UPLINK_ADDR = "10.88.0.1"
UPLINK_ADDR = "10.88.0.2"
CLIENT_SUBNET = "10.77.0.0/24"

# The destination port host-originated probes aim at. Nothing listens on it;
# the assertion is whether the SYN arrives at all, not whether it is answered.
GATEWAY_PROBE_PORT = 4443


def available() -> tuple[bool, str]:
    """Whether this host can run the namespace tests at all."""
    if os.geteuid() != 0:
        return False, "network namespace tests need root"
    for tool in ("ip", "nft"):
        if shutil.which(tool) is None:
            return False, f"{tool} is not installed"
    probe = subprocess.run(
        ["ip", "netns", "add", f"ap-probe-{uuid.uuid4().hex[:8]}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return False, f"cannot create network namespaces: {probe.stderr.strip()}"
    name = probe.args[-1]
    subprocess.run(["ip", "netns", "del", name], capture_output=True, check=False)
    return True, ""


def run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
    return result


@dataclass
class Topology:
    """Three namespaces and the veth pairs between them."""

    tag: str
    client_ns: str = field(init=False)
    gateway_ns: str = field(init=False)
    uplink_ns: str = field(init=False)
    client_if: str = field(init=False)
    uplink_if: str = field(init=False)

    def __post_init__(self) -> None:
        self.client_ns = f"ap-cl-{self.tag}"
        self.gateway_ns = f"ap-gw-{self.tag}"
        self.uplink_ns = f"ap-up-{self.tag}"
        # Interface names as the gateway sees them.
        self.client_if = f"ap{self.tag}c"
        self.uplink_if = f"ap{self.tag}u"

    # -- lifecycle ---------------------------------------------------------

    def build(self) -> Topology:
        for namespace in (self.client_ns, self.gateway_ns, self.uplink_ns):
            run(["ip", "netns", "add", namespace])

        # client <-> gateway
        run(["ip", "link", "add", f"{self.tag}cli", "type", "veth", "peer", "name", self.client_if])
        run(["ip", "link", "set", f"{self.tag}cli", "netns", self.client_ns])
        run(["ip", "link", "set", self.client_if, "netns", self.gateway_ns])

        # gateway <-> uplink
        run(["ip", "link", "add", f"{self.tag}upl", "type", "veth", "peer", "name", self.uplink_if])
        run(["ip", "link", "set", f"{self.tag}upl", "netns", self.uplink_ns])
        run(["ip", "link", "set", self.uplink_if, "netns", self.gateway_ns])

        self._configure(self.client_ns, f"{self.tag}cli", f"{CLIENT_ADDR}/24")
        self._configure(self.gateway_ns, self.client_if, f"{GATEWAY_CLIENT_ADDR}/24")
        self._configure(self.gateway_ns, self.uplink_if, f"{GATEWAY_UPLINK_ADDR}/24")
        self._configure(self.uplink_ns, f"{self.tag}upl", f"{UPLINK_ADDR}/24")

        # The client routes everything through the gateway. This is the whole
        # point: the client *tries* to reach the uplink, and the appliance's
        # policy decides whether that succeeds.
        run(["ip", "netns", "exec", self.client_ns, "ip", "route", "add", "default",
             "via", GATEWAY_CLIENT_ADDR])
        # The uplink knows how to answer, so a successful leak is observable
        # rather than merely dropped on the way back.
        run(["ip", "netns", "exec", self.uplink_ns, "ip", "route", "add", CLIENT_SUBNET,
             "via", GATEWAY_UPLINK_ADDR])

        self._install_uplink_counter()
        self.apply_sysctl_baseline()
        return self

    def apply_sysctl_baseline(self) -> dict[str, str]:
        """Apply the shipped sysctl baseline to the gateway namespace.

        A new network namespace INHERITS net.ipv4.ip_forward from the host, so
        a runner with Docker installed (host forwarding on) hands every fresh
        namespace forwarding already enabled. Without this the tests would be
        asserting the host's configuration rather than the appliance's, and
        would pass or fail depending on where CI happened to run.

        This is the same thing systemd-sysctl does at boot, from the same file,
        which is why it is a baseline rather than a workaround.
        """
        applied: dict[str, str] = {}
        for raw in SYSCTL_BASELINE.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            # A namespace may legitimately lack IPv6 knobs; a key that is not
            # present cannot grant anything, so skipping it is safe.
            result = self.exec(
                self.gateway_ns, ["sysctl", "-qw", f"{key}={value}"], check=False
            )
            if result.returncode == 0:
                applied[key] = value
        return applied

    def _configure(self, namespace: str, iface: str, address: str) -> None:
        run(["ip", "netns", "exec", namespace, "ip", "addr", "add", address, "dev", iface])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", iface, "up"])
        run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])

    def _install_uplink_counter(self) -> None:
        """Count packets arriving at the uplink, by origin.

        Two counters, because the appliance makes two different claims. Traffic
        from the client subnet is forwarded traffic: any of it is a leak. Traffic
        from the gateway's own uplink address is host-originated, and the claim
        there is narrower -- Tor's UID may send it and nothing else may. Counting
        them separately keeps a host-originated probe from being scored against
        the forwarding invariant, or the reverse.
        """
        ruleset = f"""table inet observer {{
    chain ingress {{
        type filter hook prerouting priority -300; policy accept;
        ip saddr {CLIENT_SUBNET} counter
        ip saddr {GATEWAY_UPLINK_ADDR} tcp dport {GATEWAY_PROBE_PORT} counter
    }}
}}
"""
        self.nft(self.uplink_ns, ruleset)

    def destroy(self) -> None:
        for namespace in (self.client_ns, self.gateway_ns, self.uplink_ns):
            run(["ip", "netns", "del", namespace], check=False)

    def __enter__(self) -> Topology:
        return self.build()

    def __exit__(self, *_exc) -> None:
        self.destroy()

    # -- operations --------------------------------------------------------

    def nft(self, namespace: str, ruleset: str) -> None:
        path = Path(f"/tmp/ap-{self.tag}-{uuid.uuid4().hex[:8]}.nft")
        path.write_text(ruleset, encoding="utf-8")
        try:
            run(["ip", "netns", "exec", namespace, "nft", "-f", str(path)])
        finally:
            path.unlink(missing_ok=True)

    def exec(self, namespace: str, argv: list[str], check: bool = True):
        return run(["ip", "netns", "exec", namespace, *argv], check=check)

    def set_forwarding(self, value: str) -> None:
        self.exec(self.gateway_ns, ["sysctl", "-qw", f"net.ipv4.ip_forward={value}"])

    def uplink_packets_from_gateway(self) -> int:
        """Packets the uplink saw that the GATEWAY ITSELF originated.

        Host-originated traffic never carries a client-subnet source address, so
        the forwarding counter cannot see it. This is what proves the output
        chain's egress grant is bound to the Tor UID in the kernel, rather than
        merely written down in a rule the verifier read back.
        """
        return self._counter_packets(f"ip saddr {GATEWAY_UPLINK_ADDR}")

    def uplink_packets_from_client(self) -> int:
        """Packets the uplink namespace saw from the client subnet.

        Read only; there is deliberately no reset helper. `nft reset counters`
        exits 0 but silently does nothing to an ANONYMOUS (inline) counter like
        the one in the observer rule -- it only resets named counter objects.
        A reset here would therefore report stale totals while looking like it
        worked, which in this harness means a leak count that is quietly wrong.

        Each test gets a fresh Topology instead, so every counter starts at 0
        by construction. If you need a mid-test baseline, tear the observer
        table down and reinstall it rather than resetting it.
        """
        return self._counter_packets(CLIENT_SUBNET)

    def _counter_packets(self, marker: str) -> int:
        listing = self.exec(self.uplink_ns, ["nft", "list", "table", "inet", "observer"]).stdout
        for line in listing.splitlines():
            if "counter" in line and marker in line:
                parts = line.split()
                return int(parts[parts.index("packets") + 1])
        raise RuntimeError(f"observer counter for {marker!r} not found in:\n{listing}")

    def gateway_sends_as(self, user: str, port: int = GATEWAY_PROBE_PORT) -> None:
        """Originate a TCP connection FROM the gateway as `user`.

        This is the non-forwarded egress path: a local process on the appliance
        opening a clearnet socket. Only Tor's UID is authorized to do it.
        """
        script = (
            "import socket\n"
            "for _ in range(3):\n"
            "    s = socket.socket()\n"
            "    s.settimeout(0.4)\n"
            "    try:\n"
            f"        s.connect(({UPLINK_ADDR!r}, {port}))\n"
            "    except OSError:\n"
            "        pass\n"
            "    finally:\n"
            "        s.close()\n"
        )
        self.exec(
            self.gateway_ns,
            ["setpriv", "--reuid", user, "--regid", "nogroup", "--clear-groups",
             "python3", "-c", script],
            check=False,
        )

    def client_sends(self, port: int = 443, attempts: int = 3) -> None:
        """Have the client attempt a clearnet TCP connection to the uplink.

        Whether the connection succeeds is not the assertion -- the assertion
        is whether any packet reached the uplink at all.
        """
        script = (
            "import socket\n"
            f"for _ in range({attempts}):\n"
            "    s = socket.socket()\n"
            "    s.settimeout(0.4)\n"
            "    try:\n"
            f"        s.connect(({UPLINK_ADDR!r}, {port}))\n"
            "    except OSError:\n"
            "        pass\n"
            "    finally:\n"
            "        s.close()\n"
        )
        self.exec(self.client_ns, ["python3", "-c", script], check=False)

    def client_sends_udp(self, port: int = 53) -> None:
        script = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(0.3)\n"
            "for _ in range(3):\n"
            f"    s.sendto(b'leak', ({UPLINK_ADDR!r}, {port}))\n"
        )
        self.exec(self.client_ns, ["python3", "-c", script], check=False)
