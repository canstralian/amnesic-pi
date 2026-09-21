#!/bin/bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "provision.sh must run as root" >&2
  exit 2
fi

arch=$(dpkg --print-architecture 2>/dev/null || true)
if [[ "$arch" != "arm64" ]]; then
  echo "Refusing target architecture '$arch'; Stage 1 supports Raspberry Pi OS ARM64 only." >&2
  exit 2
fi

if [[ ! -r /proc/device-tree/model ]] || ! tr -d '\0' </proc/device-tree/model | grep -qi 'Raspberry Pi'; then
  echo "This provisioner is intended for Raspberry Pi hardware." >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends tor nftables python3 python3-venv iproute2 ethtool ca-certificates

install -d -m 0755 /opt/amnesic-pi /etc/amnesic-pi /usr/share/amnesic-pi
cp -a "$repo_root/src" "$repo_root/pyproject.toml" "$repo_root/README.md" /opt/amnesic-pi/

python3 -m venv /opt/amnesic-pi/.venv
/opt/amnesic-pi/.venv/bin/pip install --no-deps /opt/amnesic-pi
ln -sfn /opt/amnesic-pi/.venv/bin/amnesic-pi /usr/local/bin/amnesic-pi

# The three stage commands are console scripts from the venv. The old
# /usr/local/sbin shim is removed so a stale copy cannot be invoked by a unit
# file that has not been updated.
for script in amnesic-pi-anon amnesic-pi-firewall; do
  ln -sfn "/opt/amnesic-pi/.venv/bin/$script" "/usr/local/bin/$script"
done
rm -f /usr/local/sbin/amnesic-pi-firewall

install -m 0644 "$repo_root/network/policy.nft.in" /usr/share/amnesic-pi/policy.nft.in

# Baseline sysctl: forwarding is 0 here. Only the firewall transaction grants
# it, and only after the nftables policy has been verified.
install -m 0644 "$repo_root/config/99-amnesic-pi.conf" /etc/sysctl.d/99-amnesic-pi.conf

install -d -m 0755 /usr/share/doc/amnesic-pi
install -m 0644 "$repo_root/docs/boot-chain.md" "$repo_root/docs/verification.md" \
  /usr/share/doc/amnesic-pi/

if [[ ! -e /etc/amnesic-pi/network.env ]]; then
  install -m 0600 "$repo_root/config/network.env.example" /etc/amnesic-pi/network.env
fi

# Keep a backup before replacing Tor's default config.
if [[ -e /etc/tor/torrc && ! -e /etc/tor/torrc.pre-amnesic-pi ]]; then
  cp -a /etc/tor/torrc /etc/tor/torrc.pre-amnesic-pi
fi
install -m 0644 "$repo_root/config/torrc" /etc/tor/torrc

# Units are installed from systemd/install-map.tsv, which the systemd
# dependency tests also read. Keeping one map means a drop-in cannot land on a
# different unit here than the one CI proved the graph for.
while IFS=$'\t' read -r source destination; do
  case "$source" in ''|'#'*) continue ;; esac
  install -d -m 0755 "/etc/systemd/system/$(dirname "$destination")"
  install -m 0644 "$repo_root/systemd/$source" "/etc/systemd/system/$destination"
done < "$repo_root/systemd/install-map.tsv"

# Superseded by amnesic-pi-posture.service, which runs after Tor rather than
# alongside it. Left behind it would re-run the pre-split verification.
rm -f /etc/systemd/system/amnesic-pi-verify.service

systemctl daemon-reload

cat <<'EOF'

Provisioning complete, but services were NOT enabled automatically.

Before enabling them:
  1. confirm /etc/amnesic-pi/network.env interface roles;
  2. keep a local-console recovery path;
  3. run: sudo amnesic-pi render-firewall | less
  4. render to a temporary file and validate with nft -c before applying;
  5. confirm each interface accepts a MAC change:
       sudo amnesic-pi-anon randomize-mac
     A USB-Ethernet adapter whose driver ignores address changes fails here.

Then enable, in pipeline order:
  systemctl enable amnesic-pi-anon.service
  systemctl enable amnesic-pi-firewall.service
  systemctl enable tor@default.service
  systemctl enable amnesic-pi-posture.service
  systemctl enable amnesic-pi-ready.target

Note: systemd-networkd, NetworkManager and Tor are now bound to
amnesic-pi-firewall.service. If that unit stops or fails, they stop too, and
the appliance loses connectivity rather than forwarding clearnet traffic.

After runtime validation, enable Raspberry Pi OS OverlayFS manually with raspi-config.
EOF
