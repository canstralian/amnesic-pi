# Amnesic Pi

<p align="center">
  <img src="assets/amnesic-pi-logo.jpg" alt="Amnesic Pi logo" width="512">
</p>

**Fail-closed ARM64 Tor gateway for Raspberry Pi with an ephemeral OverlayFS runtime.**

Amnesic Pi is an experimental Raspberry Pi security appliance. It combines Raspberry Pi OS Lite ARM64, Tor, nftables, systemd ordering, and Raspberry Pi's RAM-backed OverlayFS to create a small gateway where downstream TCP traffic is transparently routed through Tor and ordinary runtime filesystem changes disappear after reboot.

> **Status: experimental / pre-1.0.** Amnesic Pi is not Tails, is not affiliated with the Tails Project or Tor Project, and does not claim Tails-equivalent anonymity guarantees.

## Stage 1 objective

```text
BOOT -> FIREWALL DENY -> TOR -> VERIFY -> TOR-ONLY CLIENT CONNECTIVITY
                     \\-> any failure -> DENY
```

The core rule is simple:

> **Network authority is absent by default.** An application wanting a socket does not grant it authority to reach the Internet.

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
9. NetworkManager/systemd-networkd cannot start, and stop if already running, when the firewall service is not active.
10. IPv4 forwarding is enabled only by the firewall service itself, after a successful load, never unconditionally at boot.
11. Runtime root-filesystem changes disappear after reboot once OverlayFS is enabled.
12. Persistent storage is separate, opt-in, and outside the Stage 1 base system.

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

Pi 3 and Pi 4 should also be viable with current Raspberry Pi OS ARM64, but the release gate is hardware-tested primarily on Pi 5.

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
│   ├── amnesic-pi-firewall.service
│   ├── amnesic-pi-verify.service
│   └── tor-amnesic-pi.conf
├── src/amnesic_pi/
│   ├── cli.py
│   ├── config.py
│   ├── firewall.py
│   └── verify.py
├── image/
│   └── provision.sh
├── scripts/
│   └── check-amnesia.sh
└── tests/
    ├── test_config.py
    ├── test_firewall.py
    ├── test_systemd.py
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
```

Review the rendered policy before applying it:

```bash
sudo amnesic-pi render-firewall | less
```

Then, from a local console:

```bash
sudo amnesic-pi apply-firewall
sudo sysctl --system
sudo systemctl restart tor@default.service
sudo amnesic-pi verify
sudo nft list table inet amnesic_pi
```

Only after manual validation succeeds:

```bash
sudo systemctl enable amnesic-pi-firewall.service
sudo systemctl enable tor@default.service
sudo systemctl enable amnesic-pi-verify.service
sudo reboot
```

The complete installation, downstream client setup, leak tests, OverlayFS procedure, maintenance transition, and release gate are in **[BUILD.md](BUILD.md)**.

## Fail-closed test

The repository includes a root-only integration scaffold:

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
[ ] unit/static tests
[ ] nftables syntax validation
[ ] firewall boot-order validation
[ ] Tor bootstrap validation
[ ] Tor-stop denial test
[ ] downstream clearnet-denial test
[ ] DNS leak test
[ ] UDP/QUIC leak test
[ ] IPv6 leak test
[ ] reboot-amnesia test
```

## Threat boundary

Amnesic Pi is designed to reduce accidental network leakage and unintended runtime persistence. It does **not** solve browser/device fingerprinting, application-layer identity leaks, endpoint compromise, malicious firmware, physical attacks against powered hardware, malicious Tor exits, or global traffic correlation.

Read **[THREAT-MODEL.md](THREAT-MODEL.md)** before relying on the appliance.

## Development rule

Any change that broadens network authority must include a regression test demonstrating that its corresponding failure path remains closed.

See **[AGENTS.md](AGENTS.md)** for the contributor and agent invariants.

## License

MIT. See [LICENSE](LICENSE).
