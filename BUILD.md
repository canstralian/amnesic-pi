# Amnesic Pi Stage 1 Build Guide

This guide builds the Stage 1 Amnesic Pi appliance on Raspberry Pi 5 using a deterministic two-interface topology.

## 0. Target state

The finished appliance should satisfy this experimentally testable condition:

```text
A downstream client can reach TCP destinations through Tor.

If Tor stops, client Internet connectivity stops.

DNS, UDP, IPv6, and ordinary IP forwarding do not provide an
alternative Internet path.

After reboot, ordinary runtime root-filesystem changes disappear.
```

Do not treat installation success as proof. The release gate at the end is the proof boundary.

---

## 1. Hardware

Recommended Stage 1 setup:

- Raspberry Pi 5
- 4 GB or more RAM
- 16 GB or larger microSD, USB SSD, or NVMe
- adequate Pi 5 power supply
- one Ethernet cable for the uplink
- one USB-to-Ethernet adapter for the downstream network
- keyboard and display for the initial firewall deployment

Topology:

```text
Internet/router
      |
    eth0
      |
+-----v--------+
| Raspberry Pi |
| Amnesic Pi   |
+-----+--------+
      |
    eth1
      |
downstream client
```

Do not perform the first default-DROP firewall activation over SSH unless you have a separate recovery path.

---

## 2. Install Raspberry Pi OS Lite 64-bit

Use Raspberry Pi Imager and install the current Raspberry Pi OS Lite 64-bit image.

Boot the Pi and verify ARM64:

```bash
dpkg --print-architecture
```

Expected:

```text
arm64
```

Verify the hardware model:

```bash
tr -d '\0' </proc/device-tree/model
```

Update before enabling read-only mode:

```bash
sudo apt update
sudo apt full-upgrade -y
sudo reboot
```

---

## 3. Clone the repository

```bash
git clone https://github.com/canstralian/amnesic-pi.git
cd amnesic-pi
```

Read the boundaries before installing:

```bash
less THREAT-MODEL.md
less SECURITY.md
less AGENTS.md
```

---

## 4. Connect and identify interfaces

Connect the router/Internet side to the Pi's built-in Ethernet interface and the downstream cable to the USB Ethernet adapter.

Inspect interfaces:

```bash
ip -br link
ip -br addr
```

The reference configuration assumes:

```text
eth0 = uplink
eth1 = downstream client interface
```

Do not continue with guessed interface names.

---

## 5. Give the downstream interface a static address

Raspberry Pi OS uses NetworkManager on current releases. Check that `nmcli` is available:

```bash
command -v nmcli
```

Create a dedicated downstream profile:

```bash
sudo nmcli connection add \
  type ethernet \
  ifname eth1 \
  con-name amnesic-client \
  ipv4.method manual \
  ipv4.addresses 10.66.0.1/24 \
  ipv6.method disabled
```

Activate it:

```bash
sudo nmcli connection up amnesic-client
```

Verify:

```bash
ip -br addr show eth1
```

Expected IPv4 address:

```text
10.66.0.1/24
```

Stage 1 intentionally does not run DHCP. The downstream client will be configured manually later.

---

## 6. Provision Amnesic Pi

From the repository root:

```bash
sudo ./image/provision.sh
```

The provisioner checks for ARM64 Raspberry Pi hardware and installs the Stage 1 dependencies, CLI, firewall template, Tor configuration, sysctl policy, and systemd units.

It deliberately does **not** enable the security services automatically.

---

## 7. Configure interface roles

Edit:

```bash
sudoedit /etc/amnesic-pi/network.env
```

Use:

```ini
UPLINK_IF=eth0
CLIENT_IF=eth1

TRANS_PORT=9040
DNS_PORT=5353
SOCKS_PORT=9050

TOR_USER=debian-tor
```

The uplink and downstream interfaces must be distinct.

---

## 8. Validate Tor before changing firewall state

Check Tor syntax:

```bash
sudo tor --verify-config -f /etc/tor/torrc
```

Verify the service account exists:

```bash
id debian-tor
```

Stage 1 grants normal Internet TCP authority to that UID, not to arbitrary local processes.

---

## 9. Inspect the firewall before applying it

Render the candidate:

```bash
sudo amnesic-pi render-firewall | less
```

You should see:

```text
table inet amnesic_pi
```

and the filter chains should use `policy drop` for `input`, `forward`, and `output`.

The `forward` chain must contain no generic clearnet `accept` path.

Perform an nftables parser-only check without applying it:

```bash
sudo amnesic-pi render-firewall > /tmp/amnesic-pi.nft
sudo nft -c -f /tmp/amnesic-pi.nft
rm -f /tmp/amnesic-pi.nft
```

Do not continue if validation fails.

---

## 10. Apply the fail-closed policy

From the local console:

```bash
sudo amnesic-pi apply-firewall
```

Inspect the live table:

```bash
sudo nft list table inet amnesic_pi
```

The loader validates the candidate transaction before replacing the existing Amnesic Pi table. A malformed candidate should leave the known-good table untouched.

---

## 11. Apply kernel network policy

`sudo amnesic-pi apply-firewall` (step 10) already enabled IPv4 forwarding
itself, in the same process, immediately after confirming the nftables
transaction succeeded — that is the only place forwarding is ever turned on.
It is not set by `/etc/sysctl.d/99-amnesic-pi.conf`, and running
`sysctl --system` will not report a `net.ipv4.ip_forward` line originating
from that file. Still run it for the other hardening sysctls it does carry:

```bash
sudo sysctl --system
```

Verify forwarding:

```bash
sysctl net.ipv4.ip_forward
```

Expected:

```text
net.ipv4.ip_forward = 1
```

Verify Stage 1 IPv6 disablement:

```bash
sysctl net.ipv6.conf.all.disable_ipv6
sysctl net.ipv6.conf.default.disable_ipv6
```

Both should report `1`.

The intended sequencing is firewall first, IP forwarding second — and,
unlike earlier images, that sequencing is now enforced by the firewall's own
code path rather than by systemd ordering alone.

---

## 12. Start Tor

```bash
sudo systemctl restart tor@default.service
sudo systemctl status tor@default.service --no-pager
```

Inspect listeners:

```bash
sudo ss -lntup | grep -E ':(9040|5353|9050)\b'
```

Expected roles:

```text
9050  TCP  local SOCKS
9040  TCP  transparent proxy
5353  UDP  anonymous DNS resolver
```

`9050` should remain loopback-only. The transparent listeners accept redirected downstream packets, while nftables restricts access to the configured downstream interface.

---

## 13. Run the internal verifier

```bash
sudo amnesic-pi verify
```

The verifier should establish at least:

```text
PASS nft table
PASS input policy DROP
PASS forward policy DROP
PASS output policy DROP
PASS IPv4 forwarding
PASS IPv6 disabled
PASS Tor TransPort
PASS Tor DNSPort
```

A verifier failure is a deployment failure. Do not fix failures by simply removing the checks.

---

## 14. Enable the boot sequence

Only after manual validation succeeds:

```bash
sudo systemctl enable amnesic-pi-firewall.service
sudo systemctl enable tor@default.service
sudo systemctl enable amnesic-pi-verify.service
```

Check:

```bash
systemctl is-enabled amnesic-pi-firewall.service
systemctl is-enabled tor@default.service
systemctl is-enabled amnesic-pi-verify.service
```

Reboot:

```bash
sudo reboot
```

After reboot:

```bash
sudo amnesic-pi verify
sudo nft list table inet amnesic_pi
sudo systemctl status \
  amnesic-pi-firewall.service \
  tor@default.service \
  amnesic-pi-verify.service \
  --no-pager
```

### Recovery if the network stack does not come up

As of this release, `NetworkManager.service` and `systemd-networkd.service`
are each bound (`BindsTo=`) to `amnesic-pi-firewall.service`. If the
firewall fails to start, whichever of the two your image runs will not
start either — this is deliberate: no network stack authority without a
loaded firewall. Do this from the **local console** (HDMI + keyboard); do
not attempt first-time recovery over SSH, since SSH itself depends on the
network stack that may now be down.

Diagnose:

```bash
sudo systemctl status amnesic-pi-firewall.service --no-pager
sudo journalctl -u amnesic-pi-firewall.service --no-pager -n 50
```

Common causes: a bad `/etc/amnesic-pi/network.env` (re-check with
`sudo amnesic-pi render-firewall`), a missing `debian-tor` user, or an `nft`
validation failure. Fix the underlying cause, then bring the chain back up
in order — do not skip straight to starting the network unit, since it will
immediately fail again with nothing to bind to:

```bash
sudo systemctl restart amnesic-pi-firewall.service
sudo systemctl status amnesic-pi-firewall.service --no-pager
sudo systemctl restart NetworkManager.service   # or systemd-networkd.service
```

If you need network access purely to diagnose the firewall failure itself
(for example, to fetch a package), that is an explicit, local,
console-present, conscious decision to fail open — not something this
guide automates. Temporarily removing the drop-in and reloading systemd is
the mechanism:

```bash
sudo mv /etc/systemd/system/NetworkManager.service.d/10-amnesic-pi.conf /root/
sudo systemctl daemon-reload
sudo systemctl start NetworkManager.service
# ... diagnose and fix ...
sudo mv /root/10-amnesic-pi.conf /etc/systemd/system/NetworkManager.service.d/
sudo systemctl daemon-reload
sudo systemctl restart amnesic-pi-firewall.service
sudo systemctl restart NetworkManager.service
```

Re-run `sudo amnesic-pi verify` before considering the appliance restored.

---

## 15. Configure the downstream client

Connect the test machine directly to `eth1` and configure it manually:

```text
IPv4 address: 10.66.0.2
Netmask:      255.255.255.0
Gateway:      10.66.0.1
DNS server:   10.66.0.1
```

Do not configure a second gateway on that interface.

---

## 16. Test Tor connectivity

From the downstream client:

```bash
curl --max-time 30 https://check.torproject.org/
```

Ordinary TCP should succeed through Tor.

Use a separate non-Tor device/network when comparing public addresses. The Pi itself intentionally lacks general-purpose local clearnet TCP authority.

---

## 17. Prove Tor failure is closed

First run the repository integration scaffold:

```bash
sudo tests/integration/fail_closed.sh
```

Then perform the hardware test.

Stop Tor on the Pi:

```bash
sudo systemctl stop tor@default.service
```

From the downstream client:

```bash
curl --max-time 10 https://example.com/
```

Expected: timeout or connection failure.

**Any successful clearnet request is a release-blocking security failure.**

Restart Tor:

```bash
sudo systemctl start tor@default.service
```

The downstream TCP request should work again after Tor bootstraps.

---

## 18. Test DNS leakage

Install `tcpdump` before enabling OverlayFS:

```bash
sudo apt install -y tcpdump
```

Watch the uplink:

```bash
sudo tcpdump -ni eth0 'port 53 or port 853'
```

Generate normal DNS queries from the downstream client.

Direct downstream DNS must not emerge from the uplink as ordinary port 53/853 traffic.

---

## 19. Test UDP and QUIC leakage

Watch non-DHCP UDP on the uplink:

```bash
sudo tcpdump -ni eth0 'udp and not port 67 and not port 68'
```

Generate UDP/QUIC traffic from the client.

Generic downstream UDP must not be forwarded. Applications that support it may fall back from HTTP/3/QUIC to TCP.

---

## 20. Test IPv6

On the Pi:

```bash
ip -6 addr
sysctl net.ipv6.conf.all.disable_ipv6
```

Attempt an IPv6-only connection from the downstream test machine.

IPv6 must not provide an alternative path around the IPv4 Tor policy.

---

## 21. Enable the amnesic root filesystem

Do this only after the OS is updated and all preceding network tests pass.

Run:

```bash
sudo raspi-config
```

Navigate to:

```text
4 Performance Options
  -> P2 Overlay File System
```

Enable the root overlay. Optionally write-protect the boot partition according to your maintenance model.

Reboot when prompted.

Raspberry Pi's OverlayFS mechanism keeps the underlying root filesystem read-only and places ordinary runtime changes in a temporary RAM-backed upper layer. Those changes disappear after power-off or reboot.

---

## 22. Prove amnesia

From the repository:

```bash
sudo ./scripts/check-amnesia.sh arm
sudo reboot
```

After reboot:

```bash
cd ~/amnesic-pi
sudo ./scripts/check-amnesia.sh verify
```

The probe must be absent.

---

## 23. Maintenance/update transition

Once OverlayFS is active, ordinary package and configuration changes will not survive reboot. Treat updates as an explicit state transition:

```text
NORMAL READ-ONLY MODE
        |
        v
disable OverlayFS
        |
        v
reboot writable
        |
        v
update OS / Tor / Amnesic Pi
        |
        v
run tests
        |
        v
re-enable OverlayFS
        |
        v
reboot
        |
        v
run network + amnesia verification
        |
        v
NORMAL READ-ONLY MODE
```

Kernel, Tor, nftables, NetworkManager/systemd, and OverlayFS updates are security-sensitive because they can invalidate assumptions in the policy boundary.

---

## 24. Developer validation

Run unit tests:

```bash
python3 -m pytest -q
```

Compile Python:

```bash
python3 -m compileall -q src tests
```

Validate shell scripts:

```bash
bash -n image/provision.sh
bash -n tests/integration/fail_closed.sh
bash -n scripts/check-amnesia.sh
```

On Raspberry Pi OS with nftables installed, also run the rendered-policy syntax check and root integration test.

---

## 25. Release gate

Do **not** describe a release as fail-closed until the exact release candidate passes all of these on target hardware:

```text
[ ] clean Raspberry Pi OS Lite ARM64 installation
[ ] provisioning succeeds
[ ] Tor configuration validates
[ ] nftables candidate validates
[ ] input defaults to DROP
[ ] output defaults to DROP
[ ] forwarding defaults to DROP
[ ] Tor UID is the sole normal TCP egress principal
[ ] downstream TCP works through Tor
[ ] stopping Tor removes downstream Internet connectivity
[ ] no direct downstream DNS leakage
[ ] no generic downstream UDP/QUIC escape
[ ] no IPv6 escape path
[ ] boot ordering restores the firewall before network authority
[ ] stopping amnesic-pi-firewall.service also stops the active network manager
[ ] a forced firewall start failure (e.g. invalid network.env) leaves NetworkManager/systemd-networkd inactive
[ ] IP forwarding is never enabled independently of firewall success
[ ] amnesic-pi verify passes
[ ] OverlayFS is enabled
[ ] reboot-amnesia probe disappears
[ ] threat model reviewed against the release diff
```

Only after that evidence exists should the candidate be tagged as a Stage 1 release.

---

## Definition of done

Stage 1 is complete when the following statement is demonstrated, not merely intended:

```text
The downstream client has Tor-mediated TCP connectivity.
Tor failure produces network failure.
No tested DNS, UDP, IPv6, or forwarding path bypasses that boundary.
Runtime root changes disappear after reboot.
```
