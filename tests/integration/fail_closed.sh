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

# A later firewall failure/stop must take the active network manager down
# with it, not merely have preceded it at boot. Detect whichever of
# NetworkManager/systemd-networkd this image actually runs; skip cleanly if
# neither is installed rather than silently declaring the check satisfied.
net_unit=""
for candidate in NetworkManager.service systemd-networkd.service; do
  if systemctl list-unit-files --no-legend "$candidate" >/dev/null 2>&1 \
    && systemctl list-unit-files --no-legend "$candidate" | grep -q "$candidate"; then
    net_unit="$candidate"
    break
  fi
done

if [[ -z "$net_unit" ]]; then
  echo "SKIP: neither NetworkManager.service nor systemd-networkd.service is installed on this image." >&2
else
  if ! systemctl is-active --quiet "$net_unit"; then
    echo "SKIP: $net_unit is not active; cannot prove BindsTo stop-propagation from an inactive baseline." >&2
  else
    systemctl stop amnesic-pi-firewall.service
    sleep 1
    if systemctl is-active --quiet "$net_unit"; then
      echo "FAIL: $net_unit remained active after amnesic-pi-firewall.service was stopped." >&2
      systemctl start amnesic-pi-firewall.service
      exit 1
    fi
    echo "PASS: stopping amnesic-pi-firewall.service also stopped $net_unit."
    systemctl start amnesic-pi-firewall.service
    systemctl start "$net_unit"
  fi
fi
