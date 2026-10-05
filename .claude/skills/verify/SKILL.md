---
name: verify
description: Drive the Amnesic Pi CLI against a real kernel to verify a change at its surface. Use when verifying any change to src/amnesic_pi, systemd/, config/ or network/policy.nft.in — the authority model must be observed running, not inferred from tests.
---

# Verifying Amnesic Pi

The surface is the **CLI**, and the evidence is **packet counts in another
network namespace**. Tests passing is not verification here: three real
defects in this repo's history were invisible to a green unit suite and only
appeared once the installed binaries met a real kernel.

## Get a handle

```bash
apt-get install -y --no-install-recommends iproute2   # `ip` is often missing
pip install -q .                                      # installs the console scripts
ls /usr/local/bin/amnesic-pi*                         # the paths the units invoke
```

Install rather than running `python -m amnesic_pi.fw`: the systemd units call
`/usr/local/bin/amnesic-pi-{anon,firewall}`, and a console-script entry point
is a real part of the surface.

## Build the topology

Three namespaces — `client — gateway — uplink` — with veth pairs, the client
defaulting through the gateway, and the uplink routing the client subnet back
so a leak is observable rather than merely dropped. Put a counter in the
**uplink** namespace:

```
table inet observer {
  chain ingress {
    type filter hook prerouting priority -300; policy accept;
    ip saddr 10.77.0.0/24 counter
  }
}
```

**Always run a positive control first** — delete the policy, force
`ip_forward=1`, send client traffic, and confirm the counter moves. Without it
every "0 packets" result is unfalsifiable.

## Drive the pipeline in boot order

```bash
G() { ip netns exec <gw-ns> "$@"; }
G amnesic-pi-anon     --config $ENV randomize-mac      # verify MACs via sysfs afterwards
G amnesic-pi-anon     --config $ENV verify-zero-ip
# apply the shipped config/99-amnesic-pi.conf here, as systemd-sysctl would
G amnesic-pi-firewall --config $ENV --template network/policy.nft.in apply
G amnesic-pi-firewall --config $ENV verify             # ExecStartPost
G amnesic-pi-anon     --config $ENV verify-tor-path    # posture; fails without Tor, correctly
```

Then send client TCP+UDP and assert the uplink counter is 0.

## Probes worth repeating

- Rogue second table with `hook forward ... policy accept` → `verify` must FAIL.
- `masquerade` in any table → `verify` must FAIL.
- Edit the live ruleset's forward-chain priority → `verify` must FAIL.
- Bad config, and a config path that does not exist → `apply` refuses, but
  `lockdown` must still succeed and zero forwarding. Containment must not share
  a failure mode with what it contains.
- `lockdown` x3 (idempotent), then `apply` again (not a one-way door).
- Two `apply` runs concurrently → converges, `verify` passes, 0 leaked.

## Gotchas that cost time

- **A fresh netns inherits `net.ipv4.ip_forward` from the host.** On a Docker
  host it starts at 1. Apply the shipped sysctl baseline in the gateway ns, or
  you are measuring the host, not the appliance.
- **`nft reset counters` exits 0 but silently no-ops on anonymous counters.**
  Delete and reinstall the observer table to get a true zero.
- **`fwd` is a reserved nft keyword** — a probe chain named `fwd` fails to
  parse, and a rogue table that never installed will make a check look like it
  passed.
- Interface names must be ≤15 chars and match the config regex, or config
  validation fires *before* the code path you meant to exercise.
- `ethtool` is optional (permanent MAC unknown without it); `ip` and `nft` are
  not. veth devices expose no `permaddr`.
