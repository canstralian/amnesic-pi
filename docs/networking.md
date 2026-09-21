# Networking

## Default interface model

`/etc/amnesic-pi/network.env` defines two roles:

- `UPLINK_IF`: interface with Internet reachability
- `CLIENT_IF`: interface receiving downstream client traffic

The service refuses malformed names and refuses to use the same interface for
both roles. Interface names are never guessed at runtime: an interface that does
not appear within `IFACE_WAIT_SECONDS` is a hard failure.

## Configuration keys

| Key | Default | Purpose |
| --- | --- | --- |
| `UPLINK_IF` | -- | uplink interface (required) |
| `CLIENT_IF` | -- | downstream interface (required) |
| `TRANS_PORT` | `9040` | Tor transparent proxy port |
| `DNS_PORT` | `5353` | Tor DNSPort |
| `SOCKS_PORT` | `9050` | Tor SocksPort (loopback only) |
| `TOR_USER` | `debian-tor` | account holding the uplink TCP grant |
| `MAC_IFACES` | both role interfaces | interfaces whose MAC is randomized |
| `IFACE_WAIT_SECONDS` | `20` | bounded enumeration retry budget |
| `TOR_PROBE_HOST` / `TOR_PROBE_PORT` | `check.torproject.org` / `443` | SOCKS circuit probe target |
| `TOR_DNS_PROBE_NAME` | `check.torproject.org` | Tor DNS probe name |
| `EGRESS_ECHO_HOST` / `EGRESS_ECHO_PATH` | empty / `/` | optional exit-address telemetry |

## MAC randomization

`amnesic-pi-anon randomize-mac` runs before anything may configure or use an
interface. Per interface it:

1. waits, bounded, for the device to enumerate;
2. captures the current address and the burned-in (`permaddr`) address;
3. generates an address from `os.urandom`, sets the locally-administered bit and
   clears the multicast bit;
4. brings the link down, sets the address, brings it up;
5. reads the address back from `/sys/class/net/<iface>/address`;
6. asserts the readback equals what it generated, and is neither the burned-in
   address nor the pre-change address.

The generated address derives from cryptographic OS entropy only -- not from
machine-id, hostname, wall-clock time, persistent state, or a seeded
non-cryptographic PRNG. Any of those would be stable across boots and therefore
linkable, which is what randomization exists to prevent.

`new != previous` is deliberately **not** the assertion. A NIC can already carry
a randomized address from an earlier boot while still refusing further changes;
the burned-in address is excluded explicitly.

If the driver ignores the change, the command exits nonzero and forces the link
down. Failing loudly is correct: claiming anonymity the hardware does not
provide is worse than refusing to boot.

Slow USB enumeration is handled by the retry budget, never by weakening the
dependency graph.

## Zero-IP posture

`amnesic-pi-anon verify-zero-ip` asserts the role interfaces carry no configured
IP address before the network manager starts. An IPv6 link-local address is
kernel-generated rather than configured and does not violate the posture.

## Why no FORWARD accept rule exists

This is a transparent proxy appliance, not a normal IP router. Downstream TCP
and DNS traffic is redirected into local Tor listeners in nftables `prerouting`;
all remaining forwarding is denied. `verify` fails if any accept verdict appears
in the forward chain, or if another table installs a forwarding path.

## UDP

Tor does not provide a generic UDP transport. Stage 1 drops downstream UDP
except DNS to Tor's DNSPort. QUIC/HTTP3 will fail; well-behaved browsers
normally fall back to TCP.

## DNS

Downstream UDP DNS is redirected to the local Tor DNSPort. Stage 1 does not
support arbitrary DNS record types or TCP DNS through Tor DNSPort.

Preventing *non-Tor* DNS is an nftables property, not something the DNS probe
demonstrates. See [verification.md](verification.md).

## IPv6

Disabled in Stage 1, and IPv6 forwarding is never granted. A future IPv6
implementation must add equivalent transparent-proxy semantics and leak tests
before it is enabled.

## Local management

The default firewall does **not** open SSH or a web UI on the client interface.
Use a local console during early development. A management plane, if added,
should have a separate explicit trust boundary.
