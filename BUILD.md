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

## 10. Randomize the link-layer identity

This step runs before the firewall, and before anything may configure an
interface. It is also the step that exposes a USB-Ethernet adapter whose driver
ignores runtime MAC changes.

```bash
sudo amnesic-pi-anon randomize-mac
```

Expected, one line per interface:

```text
PASS  eth0  assigned 02:... (burned-in: b8:27:eb:...)
PASS  eth1  assigned 06:... (burned-in: 00:e0:4c:...)
```

A nonzero exit means the kernel did not report the address the command
generated. Do not work around it. Either the adapter is unsuitable, or it needs
longer to enumerate -- raise `IFACE_WAIT_SECONDS` in
`/etc/amnesic-pi/network.env` and retry. Record which adapter you used and
whether it passed.

If NetworkManager is holding the downstream profile from an earlier section, it
may reassert its own configuration on the interface. Take the profile down
first, then randomize, then bring it back up:

```bash
sudo nmcli connection down amnesic-client
sudo amnesic-pi-anon randomize-mac
sudo nmcli connection up amnesic-client
```

`verify-zero-ip` asserts the **pre-network** posture: no address configured
before the network manager runs. During this manual walkthrough the downstream
profile is already up, so run the check with it down:

```bash
sudo nmcli connection down amnesic-client
sudo amnesic-pi-anon verify-zero-ip
sudo nmcli connection up amnesic-client
```

At boot this ordering is enforced rather than arranged by hand:
`amnesic-pi-anon.service` runs before `network-pre.target`, and NetworkManager
is `BindsTo=amnesic-pi-firewall.service`, so neither can configure an address
ahead of the gate.

---

## 11. Apply the fail-closed policy

From the local console:

```bash
sudo amnesic-pi-firewall apply
```

This is a single transaction: it verifies topology, forces every forwarding
knob to 0, installs the policy, verifies the installed policy against the live
kernel, and only then grants IPv4 forwarding.

Three failures exit nonzero *before* the transaction starts and deliberately
change nothing: a non-root invocation, a malformed
`/etc/amnesic-pi/network.env` (which exits `configuration error: ...`), and a
policy template that cannot be rendered (which exits `... the appliance was NOT
locked down`). None of them runs `lockdown`, because a parse failure must not
flush a known-good ruleset. Forwarding is left exactly as it was -- after an
earlier successful `apply`, that means still enabled. As a systemd unit the
firewall's `OnFailure=` runs `amnesic-pi-lockdown.service` and closes that
window. Run by hand there is no such handler: correct the fault and re-run
`apply`, or close the appliance down yourself with
`sudo amnesic-pi-firewall lockdown`.

Once the transaction has begun touching the kernel, a nonzero exit means it
failed **and** already ran `lockdown`. The message says how far that containment
got, because these are not the same state:

| Message contains | What is true |
| --- | --- |
| `appliance locked down` | `lockdown` ran and every one of its checks passed: forwarding is off and an unconditional deny posture is installed. |
| `lockdown incomplete, posture unproven` | The transaction failed **and** the containment did not fully complete. Treat the posture as unproven. Work from a local console. |

A zero exit means the transaction completed **and** the final read-only
verification of the live posture passed. If that verification fails, the command
prints the failing checks and exits nonzero rather than reporting success.

Inspect the live table:

```bash
sudo nft list table inet amnesic_pi
```

The loader validates the candidate transaction before replacing the existing
Amnesic Pi table. A malformed candidate leaves the known-good table untouched.

---

## 12. Confirm the kernel forwarding state

There is deliberately **no** `sysctl --system` step here. `/etc/sysctl.d/99-amnesic-pi.conf`
pins forwarding to 0 and never grants it; the firewall transaction is the only
thing that turns it on. Running `sysctl --system` after a successful apply would
switch forwarding back off and break the appliance until the next apply.

Verify forwarding:

```bash
sysctl net.ipv4.ip_forward
```

Expected **after a successful apply**:

```text
net.ipv4.ip_forward = 1
```

Expected at any other time, including after a failed apply or a lockdown:

```text
net.ipv4.ip_forward = 0
```

Verify Stage 1 IPv6 disablement:

```bash
sysctl net.ipv6.conf.all.disable_ipv6
sysctl net.ipv6.conf.default.disable_ipv6
```

Both should report `1`.

The intended sequencing is firewall first, IP forwarding second.

---

## 13. Start Tor

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

## 14. Run the read-only posture verifier

```bash
sudo amnesic-pi-firewall verify
```

This command never mutates the system. It should establish at least:

```text
PASS  nft table
PASS  chain prerouting
PASS  chain input
PASS  chain forward
PASS  chain output
PASS  forward chain has no accept
PASS  client DNS -> Tor DNSPort 5353
PASS  client TCP -> Tor TransPort 9040
PASS  no unaccounted prerouting rule
PASS  Tor UID holds the uplink TCP grant
PASS  no unaccounted egress grant
PASS  no unauthorized forward hook
PASS  no source NAT of downstream traffic
PASS  IPv4 forwarding
```

A verifier failure is a deployment failure. Do not fix failures by removing the
checks.

---

## 15. Verify the Tor path

This runs **after** Tor, never before the firewall. Tor was started in the
previous section:

```bash
sudo amnesic-pi-anon verify-tor-path
```

Hard gates (`FAIL` blocks readiness): the firewall posture, the Tor listeners, a
completed SOCKS circuit, and Tor DNS resolution.

Observational telemetry prints as `WARN` and does not block. An unreachable echo
service is an outage, not proof of a clearnet leak. For a release run on
hardware you may promote it:

```bash
sudo amnesic-pi-anon verify-tor-path --require-observation
```

---

## 16. Enable the boot sequence

Only after manual validation succeeds:

```bash
sudo systemctl enable amnesic-pi-anon.service
sudo systemctl enable amnesic-pi-firewall.service
sudo systemctl enable tor@default.service
sudo systemctl enable amnesic-pi-posture.service
sudo systemctl enable amnesic-pi-ready.target
```

Check:

```bash
systemctl is-enabled \
  amnesic-pi-anon.service \
  amnesic-pi-firewall.service \
  tor@default.service \
  amnesic-pi-posture.service \
  amnesic-pi-ready.target
```

Confirm the authority relationships resolved as intended:

```bash
systemctl show -p BoundBy amnesic-pi-firewall.service
systemctl show -p BindsTo -p After systemd-networkd.service
systemctl show -p BindsTo -p After tor@default.service
```

`BoundBy` should name `systemd-networkd.service`, `tor@default.service` and
`amnesic-pi-posture.service`. If it does not, the drop-ins did not land -- stop
and fix that before rebooting.

Reboot:

```bash
sudo reboot
```

After reboot:

```bash
sudo amnesic-pi-firewall verify
sudo amnesic-pi-anon verify-tor-path
sudo nft list table inet amnesic_pi
systemctl is-active amnesic-pi-ready.target
sudo systemctl status \
  amnesic-pi-anon.service \
  amnesic-pi-firewall.service \
  tor@default.service \
  amnesic-pi-posture.service \
  --no-pager
```

`amnesic-pi-ready.target` being active is the readiness signal. Any earlier
stage failing means it is not reached.

---

## 17. Configure the downstream client

Connect the test machine directly to `eth1` and configure it manually:

```text
IPv4 address: 10.66.0.2
Netmask:      255.255.255.0
Gateway:      10.66.0.1
DNS server:   10.66.0.1
```

Do not configure a second gateway on that interface.

---

## 18. Test Tor connectivity

From the downstream client:

```bash
curl --max-time 30 https://check.torproject.org/
```

Ordinary TCP should succeed through Tor.

Use a separate non-Tor device/network when comparing public addresses. The Pi itself intentionally lacks general-purpose local clearnet TCP authority.

---

## 19. Prove Tor failure is closed

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

## 20. Test DNS leakage

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

## 21. Test UDP and QUIC leakage

Watch non-DHCP UDP on the uplink:

```bash
sudo tcpdump -ni eth0 'udp and not port 67 and not port 68'
```

Generate UDP/QUIC traffic from the client.

Generic downstream UDP must not be forwarded. Applications that support it may fall back from HTTP/3/QUIC to TCP.

---

## 22. Test IPv6

On the Pi:

```bash
ip -6 addr
sysctl net.ipv6.conf.all.disable_ipv6
```

Attempt an IPv6-only connection from the downstream test machine.

IPv6 must not provide an alternative path around the IPv4 Tor policy.

---

## 23. Enable the amnesic root filesystem

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

## 24. Prove amnesia

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

## 25. Maintenance/update transition

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

## 26. Developer validation

Run unit tests:

```bash
python3 -m pytest -q
```

Run the resolved systemd graph tests and `systemd-analyze verify`:

```bash
python3 -m pytest -q tests/test_systemd.py
```

Run the packet-level fail-closed suite. This needs root, `iproute2` and
`nftables`, and is the strongest automated evidence the repository produces:

```bash
sudo python3 -m pytest -q -m netns
```

It skips rather than fails when namespaces are unavailable, so confirm it
actually ran:

```bash
sudo python3 -m pytest -m netns --collect-only -q | tail -1
```

Lint:

```bash
ruff check src tests
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

On Raspberry Pi OS with nftables installed, also run the rendered-policy syntax
check and the root integration test.

---

## 27. Release gate

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
[ ] network manager and Tor show BindsTo=amnesic-pi-firewall.service
[ ] MAC randomization passes on every adapter in use
[ ] amnesic-pi-firewall verify passes
[ ] amnesic-pi-anon verify-tor-path passes
[ ] amnesic-pi-ready.target is reached
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
