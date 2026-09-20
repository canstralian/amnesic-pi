# Boot Chain, Ordering and Authority

## The distinction this design turns on

Ordering is not authority.

```ini
Before=network-pre.target
```

only says "run me first". If the unit fails, `network-pre.target` is still
reached and the network manager still starts. `network-pre.target` is a passive
synchronisation point and is **not** the security boundary.

The authority relationship is attached directly to the consumers:

```ini
# /etc/systemd/system/systemd-networkd.service.d/10-amnesic-pi.conf
[Unit]
BindsTo=amnesic-pi-firewall.service
After=amnesic-pi-firewall.service
```

`BindsTo=` is a lifetime relationship: if `amnesic-pi-firewall.service` becomes
inactive, systemd stops the units bound to it. `Requires=` alongside it would
be redundant -- `BindsTo=` already implies the stronger form.

## The pipeline

```text
amnesic-pi-anon.service          MAC randomization + readback, zero-IP posture
        |
        v
amnesic-pi-firewall.service      topology -> forwarding off -> policy ->
        |                        policy verify -> forwarding on -> verify
        v
systemd-networkd.service         (or NetworkManager.service)
        |
        v
tor@default.service
        |
        v
amnesic-pi-posture.service       Tor bootstrap + Tor-path verification
        |
        v
amnesic-pi-ready.target          READY
```

Every stage before READY fails closed.

## Phase separation

Phase 1 (pre-network) and Phase 2 (post-Tor) cannot be merged.

`amnesic-pi-anon randomize-mac` runs before the firewall, which runs before the
network manager, which runs before Tor. Tor therefore **cannot** be running
during Phase 1, so no Tor-dependent check may live there. An earlier design
tried to make one command verify both the MAC and Tor's egress; that is
unsatisfiable by construction.

Phase 2 is `amnesic-pi-anon verify-tor-path`, in `amnesic-pi-posture.service`,
after Tor.

## Forwarding authority

`/etc/sysctl.d/99-amnesic-pi.conf` sets every forwarding knob to **0** and never
grants forwarding. The previous arrangement had it set `net.ipv4.ip_forward=1`,
which produced this failure:

```text
firewall unit fails
        -> systemd-sysctl enables forwarding anyway
        -> clearnet forwarding remains possible
```

Forwarding is now granted only inside `amnesic-pi-firewall apply`, and only
after the installed nftables policy has been verified against the live kernel.
The firewall unit is ordered **after** `systemd-sysctl.service` so the baseline
can never overwrite the grant.

## Failure and teardown

Two directives are needed, and neither subsumes the other:

| Path | Covered by |
| --- | --- |
| unit enters a failed state | `OnFailure=amnesic-pi-lockdown.service` |
| `systemctl stop` | `ExecStop=` |
| dependency teardown | `ExecStop=` |
| shutdown | `ExecStop=` |

`OnFailure=` fires on failure only. For a `Type=oneshot` unit whose `ExecStart`
failed, systemd does **not** run `ExecStop` at all -- so `OnFailure=` is the
only cleanup on that path. Conversely an administrator `systemctl stop` is not
a failure, so `OnFailure=` never fires for it.

`lockdown` is idempotent and disables forwarding before it touches nftables, so
running it twice, or after a partial apply, is safe.

## Consequence of the lifetime binding

Stopping `amnesic-pi-firewall.service` stops `systemd-networkd`,
`NetworkManager` and Tor with it, and `lockdown` installs an unconditional deny
posture. The appliance loses connectivity. That is the intended trade: at a
pre-ready security boundary, connectivity loss beats accidental clearnet
forwarding.

Keep a local console during deployment.

## Validation

The resolved graph is asserted in `tests/test_systemd.py`, which lays the units
out as `image/provision.sh` installs them (per `systemd/install-map.tsv`),
merges drop-ins the way systemd does, and checks the resolved relationships
including the reverse `BoundBy=` edges. `systemd-analyze verify` is run over the
same layout.

Re-validate on each supported Raspberry Pi OS release: init and network-stack
changes can alter boot sequencing.
