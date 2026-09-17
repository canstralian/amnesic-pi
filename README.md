# Amnesic Pi

A fail-closed, ARM64 Tor gateway for Raspberry Pi with an ephemeral runtime.

Amnesic Pi is an experimental security appliance for Raspberry Pi 3, 4, and 5. It combines Raspberry Pi OS Lite ARM64, Tor, nftables, systemd ordering, and a RAM-backed OverlayFS to create a small gateway where downstream TCP traffic is transparently routed through Tor and ordinary runtime filesystem changes disappear after reboot.

Amnesic Pi is not Tails and does not claim Tails-equivalent anonymity.

Its design goal is narrower and testable:

BOOT
  │
  ▼
INSTALL FAIL-CLOSED POLICY
  │
  ├── failure ──────────────► DENY
  │
  ▼
ENABLE NETWORK STATE
  │
  ▼
START TOR
  │
  ├── failure ──────────────► DENY
  │
  ▼
VERIFY INVARIANTS
  │
  ├── failure ──────────────► DENY
  │
  ▼
TOR-ONLY CLIENT CONNECTIVITY

Core rule

«No network path exists merely because an application asks for one.»

Network authority is explicitly granted by policy.

In Stage 1, the Tor service account is the only normal process permitted outbound Internet TCP access.

Security invariants

1. Client traffic has no ordinary clearnet forwarding path.
2. "input", "forward", and "output" default to "DROP".
3. Tor is the sole normal Internet TCP principal.
4. Client TCP is redirected into Tor's transparent proxy.
5. Client DNS is redirected into Tor's DNS listener.
6. Arbitrary client UDP is denied.
7. IPv6 is disabled until equivalent leak controls exist.
8. Tor failure must result in loss of connectivity, not clearnet fallback.
9. Runtime filesystem changes are ephemeral once OverlayFS is enabled.
10. Persistent storage is separate and opt-in.

Architecture

                         INTERNET
                             │
                             │
                       ┌─────▼─────┐
                       │   eth0    │
                       │  UPLINK   │
                       └─────┬─────┘
                             │
                 ┌───────────▼───────────┐
                 │     nftables          │
                 │                       │
                 │  DEFAULT: DROP        │
                 │  explicit authority   │
                 └───────────┬───────────┘
                             │
                      ┌──────▼──────┐
                      │     Tor     │
                      │ TransPort   │
                      │ DNSPort     │
                      │ SOCKSPort   │
                      └──────┬──────┘
                             │
                 transparent interception
                             │
                       ┌─────▼─────┐
                       │   eth1    │
                       │  CLIENT   │
                       └─────┬─────┘
                             │
                    laptop / phone

The root filesystem becomes:

read-only Raspberry Pi OS
          +
RAM-backed writable OverlayFS
          =
ephemeral runtime root

Recommended Stage 1 hardware

- Raspberry Pi 5
- Raspberry Pi OS Lite 64-bit
- microSD card or USB/NVMe boot storage
- Ethernet uplink
- USB Ethernet adapter for the client network
- local keyboard/display during initial deployment

The first deployment deliberately avoids Wi-Fi AP mode. That becomes a later capability after the Tor and firewall boundaries are proven.

Repository layout

amnesic-pi/
├── README.md
├── BUILD.md
├── SECURITY.md
├── THREAT-MODEL.md
├── AGENTS.md
│
├── config/
│   ├── network.env.example
│   ├── torrc
│   └── 99-amnesic-pi.conf
│
├── network/
│   └── policy.nft.in
│
├── systemd/
│   ├── amnesic-pi-firewall.service
│   ├── amnesic-pi-verify.service
│   └── tor-amnesic-pi.conf
│
├── src/amnesic_pi/
│   ├── cli.py
│   ├── config.py
│   ├── firewall.py
│   └── verify.py
│
├── image/
│   └── provision.sh
│
├── scripts/
│   └── check-amnesia.sh
│
└── tests/
    ├── test_config.py
    ├── test_firewall.py
    ├── test_systemd.py
    ├── test_torrc.py
    └── integration/
        └── fail_closed.sh

Quick start

Start with a fresh Raspberry Pi OS Lite 64-bit installation.

git clone https://github.com/canstralian/amnesic-pi.git
cd amnesic-pi

Review the threat model before deployment:

less THREAT-MODEL.md

Provision:

sudo ./image/provision.sh

Configure interface roles:

sudoedit /etc/amnesic-pi/network.env

Recommended Stage 1 configuration:

UPLINK_IF=eth0
CLIENT_IF=eth1

TRANS_PORT=9040
DNS_PORT=5353
SOCKS_PORT=9050

TOR_USER=debian-tor

Inspect the generated firewall:

sudo amnesic-pi render-firewall | less

Apply it from a local console:

sudo amnesic-pi apply-firewall
sudo sysctl --system

Start Tor:

sudo systemctl restart tor@default.service

Verify:

sudo amnesic-pi verify
sudo nft list table inet amnesic_pi

Enable boot-time services only after those checks succeed:

sudo systemctl enable amnesic-pi-firewall.service
sudo systemctl enable tor@default.service
sudo systemctl enable amnesic-pi-verify.service

Then reboot:

sudo reboot

Fail-closed test

After successful operation:

sudo tests/integration/fail_closed.sh

The test stops Tor and confirms that ordinary local TCP connectivity does not become available.

A release still requires testing from an actual downstream client.

Amnesic mode

Only enable OverlayFS after the base system is working and fully updated:

sudo raspi-config

Select:

Performance Options
  └── Overlay File System
        ├── Enable overlay filesystem
        └── optionally write-protect boot partition

Reboot.

Create the amnesia probe:

sudo ./scripts/check-amnesia.sh arm
sudo reboot

After reboot:

sudo ./scripts/check-amnesia.sh verify

The marker must be absent.

Release gate

No release should be described as fail-closed until it has passed:

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

Threat model

Amnesic Pi is designed primarily to reduce:

- accidental clearnet fallback;
- DNS leakage;
- unsupported UDP escape paths;
- network authority accidentally granted to local applications;
- persistence of ordinary runtime state across reboots.

It does not protect against:

- root or kernel compromise;
- malicious firmware;
- compromised downstream clients;
- browser fingerprinting;
- application-layer identity disclosure;
- global traffic correlation;
- malicious Tor exits;
- physical attacks against powered hardware.

Read ""THREAT-MODEL.md"" (THREAT-MODEL.md) before relying on the system.

Project status

Experimental / pre-1.0.

This repository is a security engineering project, not an anonymity guarantee.

Every feature that expands network authority must come with a regression test proving that its failure path remains closed.
