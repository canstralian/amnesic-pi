# Verification

## Verification tiers

Claims about this appliance must state which tier produced them. They are not
interchangeable.

| Tier | What it proves | Where it runs |
| --- | --- | --- |
| **Unit tested** | The security logic behaves correctly against injected kernel behaviour. | `pytest` in CI |
| **Namespace/kernel integration tested** | A real Linux kernel does not forward a client packet under any injected pre-ready failure. | `pytest -m netns`, root + netns |
| **systemd graph verified** | The resolved unit relationships are the intended authority graph, and `systemd-analyze verify` is clean. | `tests/test_systemd.py` |
| **Raspberry Pi hardware tested** | The appliance behaves as designed on the target board. | **Not yet performed** |
| **Specific USB-Ethernet adapter tested** | That adapter accepts runtime MAC changes. | **Not yet performed** |

The first three are automated and currently green. The last two require
hardware and have not been done. See "Unverified on hardware" below.

## Commands

### `amnesic-pi-firewall verify`

Read-only. It never mutates the system, on any path. It checks the live kernel
state against the intended posture:

- the `inet amnesic_pi` table exists;
- `prerouting`, `input`, `forward`, `output` exist with the expected type, hook,
  priority and default policy;
- the `forward` chain carries no accept verdict at all;
- client DNS and client TCP redirect rules are present and name the configured
  Tor ports;
- the output chain is bound to the uplink interface and the Tor UID holds the
  only ordinary uplink TCP grant;
- no *other* table in the ruleset hooks `forward` with a non-drop policy or an
  accept verdict;
- nothing in the ruleset source-NATs downstream traffic;
- IPv4 forwarding matches the expected state and IPv6 forwarding is off.

Exit code is nonzero on any mismatch. A posture that cannot be proven is not a
passing posture.

### `amnesic-pi-anon verify-tor-path`

Runs after Tor. Its checks are split, and the split is the point.

**Hard gates** -- these decide readiness:

- the firewall posture above still verifies;
- the configured Tor `TransPort` and `SocksPort` listeners accept connections;
- a SOCKS5 CONNECT through Tor completes (Tor does not answer one until it holds
  a usable circuit, so this is also the bootstrap proof);
- a DNS query to Tor's `DNSPort` resolves.

**Observational telemetry** -- reported, but does not decide readiness:

- the external address an echo service reports for the exit;
- relay/circuit metadata;
- exit geography.

An echo service being unreachable is an **outage**. It is not proof of a
clearnet leak and never fails the boot. The one exception is a positive leak
signal: if the echo service reports an address that belongs to this appliance,
that fails hard regardless of mode.

Telemetry is off unless `EGRESS_ECHO_HOST` is set. For hardware release testing,
`--require-observation` promotes it to a gate.

### What the Tor DNS check does and does not prove

Resolving a name through Tor's `DNSPort` proves that path works.

It does **not** prove that another process cannot send DNS directly. That is an
nftables invariant: it is asserted in the policy checks above and exercised by
the namespace tests, not by the DNS probe.

## Exit-IP rotation is not a release gate

Successive Tor circuits are not guaranteed to use distinct exit relays. Fresh
streams and stream isolation make a fresh *circuit* likely, not a fresh *exit*.

The repository therefore contains no assertion of the form:

```python
assert len(set(exit_ips)) == len(exit_ips)   # NOT an invariant
```

`tests/test_torpath.py` fails the build if one is reintroduced.

## Namespace fail-closed suite

`pytest -m netns` builds three network namespaces:

```text
client  --veth--  gateway  --veth--  uplink
```

The gateway runs the real transaction against the real policy template. The
uplink namespace counts every packet arriving from the client subnet, so a leak
is a number rather than an inference.

A positive control runs first: forwarding on with no policy **must** register a
leak. Without it, every "zero packets" result could be an artefact of a detector
that cannot see packets at all.

Failure points injected, each asserting zero packets at the uplink:

- no stage has run yet;
- topology failure (an interface that never enumerates);
- configuration parse failure;
- nftables apply failure (a policy nft refuses);
- nftables **verification** failure (a policy nft accepts whose forward chain
  defaults to ACCEPT);
- lockdown after a successful apply;
- repeated lockdown;
- forwarding already enabled before a failing transaction -- the preserved
  regression.

## Hardware adversarial checks

Before a release, use a downstream test client and prove:

1. normal TCP exits through Tor;
2. the observed public IP differs from the uplink's clearnet address;
3. DNS requests do not appear at the uplink resolver;
4. `systemctl stop tor@default` causes loss of client Internet;
5. downstream UDP/443 does not leave directly;
6. IPv6 has no usable path;
7. adding a second unclassified interface does not create forwarding authority;
8. each USB-Ethernet adapter in use accepts a runtime MAC change
   (`amnesic-pi-anon randomize-mac` returns zero);
9. `amnesic-pi-ready.target` is reached only after the posture stage passes;
10. a marker written to root disappears after reboot with OverlayFS enabled.

Do not convert absence of an observed leak into a broad anonymity claim.

## Unverified on hardware

The following are **[UNVERIFIED]** until run on a Raspberry Pi:

- whether each USB-Ethernet adapter permits runtime MAC changes;
- device enumeration timing, and whether `IFACE_WAIT_SECONDS` is large enough;
- interface naming stability across boots;
- behaviour across reboot on Raspberry Pi OS;
- the actual Tor/network boot sequence on the target board.

The gate is deliberately designed to expose an unsupported adapter by failing
closed: if the driver ignores `ip link set address`, `randomize-mac` exits
nonzero, `amnesic-pi-firewall.service` never starts, and nothing bound to it
starts either.
