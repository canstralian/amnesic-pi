#!/bin/bash
# Root-only, on-appliance fail-closed scaffold.
#
# Scope: this proves the HOST does not gain ordinary egress when Tor stops. It
# does NOT prove the downstream-client path -- run that from a real client
# before calling a release fail-closed. See docs/verification.md.
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "SKIP/REFUSE: run as root on target hardware." >&2
  exit 2
fi

command -v nft >/dev/null
command -v systemctl >/dev/null
command -v amnesic-pi-firewall >/dev/null

if ! systemctl is-active --quiet amnesic-pi-firewall.service; then
  echo "REFUSE: firewall service is not active." >&2
  exit 2
fi

# The posture must be provably correct before any conclusion is drawn from a
# denial: a denial under a broken policy proves nothing about the policy.
if ! amnesic-pi-firewall verify; then
  echo "REFUSE: live posture verification failed; fix that before testing denial." >&2
  exit 2
fi

forwarding=$(cat /proc/sys/net/ipv4/ip_forward)
echo "IPv4 forwarding: $forwarding (granted by the firewall transaction, not by sysctl.d)"

restore=0
if systemctl is-active --quiet tor@default.service; then
  restore=1
  systemctl stop tor@default.service
fi
trap 'if [[ $restore -eq 1 ]]; then systemctl start tor@default.service; fi' EXIT

sleep 1

# Root has no special nftables bypass in the output chain. A direct TCP attempt should fail.
if timeout 4 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "FAIL: direct TCP egress succeeded with Tor stopped." >&2
  exit 1
fi

echo "PASS: local direct TCP egress remained denied with Tor stopped."
echo "NOTE: run the downstream-client denial test before release; this script does not prove that path."
