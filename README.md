# Amnesic Pi

<p align="center">
  <img src="assets/amnesic-pi-logo.jpg" alt="Amnesic Pi logo" width="512">
</p>

**Fail-closed ARM64 Tor gateway for Raspberry Pi with an ephemeral OverlayFS runtime.**

Amnesic Pi is an experimental Raspberry Pi security appliance. It combines Raspberry Pi OS Lite ARM64, Tor, nftables, systemd ordering, and Raspberry Pi's RAM-backed OverlayFS to create a small gateway where downstream TCP traffic is transparently routed through Tor and ordinary runtime filesystem changes disappear after reboot.

> **Status: experimental / pre-1.0.** Amnesic Pi is not Tails, is not affiliated with the Tails Project or Tor Project, and does not claim Tails-equivalent anonymity guarantees.

## Stage 1 objective

```text
TOPOLOGY -> MAC RANDOMIZE + READBACK -> ZERO-IP -> FIREWALL APPLY
         -> FIREWALL VERIFY -> FORWARDING ENABLE -> NETWORK -> TOR
         -> TOR-PATH VERIFY -> READY
                            \\-> any failure before READY -> LOCKDOWN -> DENY
```

The core rule is simple:

> **Network authority is absent by default.** An application wanting a socket does not grant it authority to reach the Internet.

And the rule that makes it enforceable:

> **Ordering is not authority.** `Before=` only says "run me first"; if the unit fails, the target is still reached. The network manager, Tor and the posture verifier are `BindsTo=` the firewall unit, which is a lifetime relationship.

Stage 1 is intentionally narrow. It proves the network and amnesia invariants before adding convenience features such as Wi-Fi AP mode, DHCP, browser integration, persistence UI, or image publishing.

## Security invariants

1. Client traffic has no ordinary clearnet forwarding path.
2. `input`, `forward`, and `output` use default `DROP` policies.
3. Tor is the only normal process granted outbound Internet TCP authority.
4. Downstream TCP is redirected into Tor's `TransPort`.
5. Downstream UDP/53 is redirected into Tor's `DNSPort`.
6. Other downstream UDP, including QUIC, is denied.
7. IPv6 is disabled until equivalent leak-proof policy and tests exist.
8. Stopping or crashing Tor must remove connectivity rather than expose clearnet.
9. Runtime root-filesystem changes disappear after reboot once OverlayFS is enabled.
10. Persistent storage is separate, opt-in, and outside the Stage 1 base system.
11. Forwarding is off at boot and is granted **only** inside a firewall transaction that has already verified the installed policy.
12. Each role interface gets a randomized MAC, verified by readback, before the network manager may start.
13. The network manager and Tor cannot start without the firewall unit, and cannot outlive it.
14. No Tor-dependent check runs before Tor; no pre-network check depends on the network.

### What Stage 1 does not claim

`BindsTo=` tracks **systemd unit state**, not **nftables kernel state**. If root
runs `nft flush ruleset` while the firewall unit is still `active (exited)`,
systemd sees nothing and the bound units keep running. Stage 1 therefore does
not claim "policy loss implies connectivity loss". See
[THREAT-MODEL.md](THREAT-MODEL.md#known-limitation-out-of-band-nftables-mutation).

Exit-IP rotation is also **not** an invariant: successive Tor circuits are not
guaranteed to use distinct exits, so "a different exit every request" is not a
release gate.

## Reference topology

Stage 1 uses two wired interfaces because it is easier to audit and does not silently depend on hostapd/DHCP configuration.

```text
                         Internet/router
                               |
                         eth0  UPLINK
                               |
                    +----------v----------+
                    |    Raspberry Pi 5   |
                    |                     |
                    | nftables -> Tor     |
                    | default DROP        |
                    +----------+----------+
                               |
                         eth1  CLIENT
                               |
                         laptop / phone
```

A USB-to-Ethernet adapter is sufficient for `eth1`.

## Traffic path

```text
DOWNSTREAM CLIENT
       |
       v
[nftables prerouting]
       |
       +-- UDP/53 ------> Tor DNSPort :5353
       |
       +-- TCP ---------> Tor TransPort :9040
       |
       +-- other traffic -> DENY

Tor process
       |
       v
[nftables output]
       |
       +-- Tor UID + TCP + uplink -> ALLOW
       +-- anything else          -> DENY
```

The transparent Tor listeners bind on IPv4 wildcard addresses so redirected packets arriving from the client interface can reach them. The firewall permits access to those ports only from the configured downstream interface. The SOCKS listener remains bound to loopback.

## Hardware

Primary target:

- Raspberry Pi 5
- Raspberry Pi OS Lite 64-bit
- 16 GB or larger microSD, USB SSD, or NVMe storage
- Ethernet uplink
- USB-to-Ethernet adapter for downstream traffic
- local keyboard/display during initial firewall deployment

Pi 3 and Pi 4 run the same ARM64 Raspberry Pi OS, but no hardware target --
primary or otherwise -- has been validated against this authority model.

> **No Raspberry Pi hardware testing has been performed on the current authority model.** The automated evidence covers unit behaviour, kernel/namespace packet authority, and the resolved systemd graph. Hardware behaviour -- including whether a given USB-Ethernet adapter accepts runtime MAC changes, device enumeration timing, interface naming stability, and the real boot sequence -- is **[UNVERIFIED]**. See [docs/verification.md](docs/verification.md#unverified-on-hardware).

## Repository layout

```text
amnesic-pi/
├── README.md
├── BUILD.md
├── SECURITY.md
├── THREAT-MODEL.md
├── AGENTS.md
├── config/
│   ├── network.env.example
│   ├── torrc
│   └── 99-amnesic-pi.conf
├── network/
│   └── policy.nft.in
├── systemd/
│   ├── install-map.tsv               # single source of truth for unit install paths
│   ├── amnesic-pi-anon.service       # phase 1: MAC + zero-IP
│   ├── amnesic-pi-firewall.service   # the authority transaction
│   ├── amnesic-pi-lockdown.service   # OnFailure target
│   ├── amnesic-pi-posture.service    # phase 2: Tor-path verification
│   ├── amnesic-pi-ready.target       # READY
│   ├── networkd-amnesic-pi.conf      # BindsTo drop-in
│   ├── NetworkManager-amnesic-pi.conf
│   └── tor-amnesic-pi.conf
├── src/amnesic_pi/
│   ├── anon.py        # amnesic-pi-anon entry point
│   ├── fw.py          # amnesic-pi-firewall entry point
│   ├── cli.py         # amnesic-pi umbrella
│   ├── authority.py   # apply / verify / lockdown
│   ├── mac.py         # MAC generation + verified readback
│   ├── netif.py       # interface primitives
│   ├── nft.py         # nftables invocation and inspection
│   ├── sysctl.py      # forwarding state
│   ├── torpath.py     # post-Tor posture verification
│   ├── config.py
│   ├── firewall.py    # policy rendering
│   └── verify.py
├── image/
│   └── provision.sh
├── scripts/
│   └── check-amnesia.sh
└── tests/
    ├── test_anon.py               # MAC gate behaviour
    ├── test_authority.py          # transaction fail-closed
    ├── test_systemd.py            # resolved dependency graph
    ├── test_netns_fail_closed.py  # packet-level failure injection
    ├── test_torpath.py
    ├── test_config.py
    ├── test_firewall.py
    ├── test_torrc.py
    └── integration/
        └── fail_closed.sh
```

## Quick start

Use a **local console** during the first firewall deployment. A default-DROP firewall can lock out SSH if you apply it remotely.

```bash
git clone https://github.com/canstralian/amnesic-pi.git
cd amnesic-pi
less THREAT-MODEL.md
sudo ./image/provision.sh
```

Configure interface roles:

```bash
sudoedit /etc/amnesic-pi/network.env
```

Recommended Stage 1 values:

```ini
UPLINK_IF=eth0
CLIENT_IF=eth1
TRANS_PORT=9040
DNS_PORT=5353
SOCKS_PORT=9050
TOR_USER=debian-tor
IFACE_WAIT_SECONDS=20
```

Confirm each adapter accepts a runtime MAC change. This is the step that
exposes an unsupported USB-Ethernet adapter, and it must pass before the
appliance can boot:

```bash
sudo amnesic-pi-anon randomize-mac
sudo amnesic-pi-anon verify-zero-ip
```

Review the rendered policy before applying it:

```bash
sudo amnesic-pi render-firewall | less
```

Then, from a local console:

```bash
sudo amnesic-pi-firewall apply     # installs policy, verifies it, then grants forwarding
sudo amnesic-pi-firewall verify    # read-only re-check
sudo systemctl restart tor@default.service
sudo amnesic-pi-anon verify-tor-path
sudo nft list table inet amnesic_pi
```

`apply` fails closed *once the transaction starts*: if anything in it fails,
`apply` runs `lockdown` itself, and the message says whether that containment
completed (`appliance locked down`) or did not (`lockdown incomplete, posture
unproven`). Three failures exit *before* the transaction and deliberately change
nothing -- a non-root invocation, a malformed config (`configuration error:
...`), and a template that cannot be rendered (`... NOT locked down`) -- because
a parse failure must not flush a known-good ruleset. Forwarding is then left as
it was, which after an earlier successful `apply` means still on. Under systemd
the unit's `OnFailure=` closes that window; a run by hand has no such handler,
so fix the fault and re-run `apply`, or close the appliance down yourself:

```bash
sudo amnesic-pi-firewall lockdown
```

Only after manual validation succeeds:

```bash
sudo systemctl enable amnesic-pi-anon.service
sudo systemctl enable amnesic-pi-firewall.service
sudo systemctl enable tor@default.service
sudo systemctl enable amnesic-pi-posture.service
sudo systemctl enable amnesic-pi-ready.target
sudo reboot
```

> Stopping `amnesic-pi-firewall.service` now stops the network manager and Tor
> with it, and installs an unconditional deny posture. That is intentional:
> at a pre-ready security boundary, connectivity loss beats accidental clearnet
> forwarding. Keep a local console.

The complete installation, downstream client setup, leak tests, OverlayFS procedure, maintenance transition, and release gate are in **[BUILD.md](BUILD.md)**.

## Fail-closed test

Packet-level failure injection runs in CI, under real Linux network namespaces
rather than mocks:

```bash
sudo python -m pytest -m netns
```

Three namespaces (client, gateway, uplink) carry the real transaction against
the real policy template. For every pre-ready failure boundary, the uplink
namespace must observe zero packets from the client subnet. A positive control
runs first, so a detector that cannot see packets fails the suite rather than
passing it.

The repository also includes a root-only on-appliance scaffold:

```bash
sudo tests/integration/fail_closed.sh
```

The more important hardware test is performed from an actual downstream client:

1. verify TCP connectivity while Tor is running;
2. stop `tor@default.service`;
3. repeat the client request;
4. confirm it fails rather than falling back to ordinary routing;
5. restart Tor and confirm connectivity returns.

## Amnesic mode

After the base system and failure tests pass, enable Raspberry Pi OS OverlayFS:

```bash
sudo raspi-config
```

Navigate to:

```text
4 Performance Options
  -> P2 Overlay File System
```

The read-only root becomes the lower layer while runtime writes go to a temporary RAM-backed upper layer. Those ordinary runtime changes disappear on reboot.

Verify that behavior with:

```bash
sudo ./scripts/check-amnesia.sh arm
sudo reboot
```

After reboot:

```bash
sudo ./scripts/check-amnesia.sh verify
```

## Release gate

Do not describe a release as fail-closed until the candidate passes all of the following on target hardware:

```text
[x] unit/static tests                       (automated)
[x] resolved systemd dependency graph       (automated)
[x] systemd-analyze verify                  (automated)
[x] namespace packet-level fail-closed      (automated, root + netns)
[ ] nftables syntax validation on target
[ ] MAC randomization accepted by each adapter in use
[ ] Tor bootstrap validation
[ ] Tor-stop denial test
[ ] downstream clearnet-denial test
[ ] DNS leak test
[ ] UDP/QUIC leak test
[ ] IPv6 leak test
[ ] reboot-amnesia test
```

The checked items run in CI. The unchecked items require target hardware and
have not been performed.

## Threat boundary

Amnesic Pi is designed to reduce accidental network leakage and unintended runtime persistence. It does **not** solve browser/device fingerprinting, application-layer identity leaks, endpoint compromise, malicious firmware, physical attacks against powered hardware, malicious Tor exits, or global traffic correlation.

Read **[THREAT-MODEL.md](THREAT-MODEL.md)** before relying on the appliance.

## Development rule

Any change that broadens network authority must include a regression test demonstrating that its corresponding failure path remains closed.

See **[AGENTS.md](AGENTS.md)** for the contributor and agent invariants.

## License

MIT. See [LICENSE](LICENSE).
