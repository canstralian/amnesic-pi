#!/bin/bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "SKIP/REFUSE: run as root on target hardware." >&2
  exit 2
fi

command -v nft >/dev/null
command -v systemctl >/dev/null
command -v amnesic-pi >/dev/null

if ! systemctl is-active --quiet amnesic-pi-firewall.service; then
  echo "REFUSE: firewall service is not active." >&2
  exit 2
fi

# This test proves the local host itself does not gain ordinary egress when Tor stops.
# A full release test must ALSO be run from a downstream client.
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
