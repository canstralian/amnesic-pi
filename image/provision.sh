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
apt-get install -y --no-install-recommends tor nftables python3 python3-venv iproute2 ca-certificates

install -d -m 0755 /opt/amnesic-pi /etc/amnesic-pi /usr/share/amnesic-pi
cp -a "$repo_root/src" "$repo_root/pyproject.toml" "$repo_root/README.md" /opt/amnesic-pi/

python3 -m venv /opt/amnesic-pi/.venv
/opt/amnesic-pi/.venv/bin/pip install --no-deps /opt/amnesic-pi
ln -sfn /opt/amnesic-pi/.venv/bin/amnesic-pi /usr/local/bin/amnesic-pi

install -m 0755 "$repo_root/bin/amnesic-pi-firewall" /usr/local/sbin/amnesic-pi-firewall
install -m 0644 "$repo_root/network/policy.nft.in" /usr/share/amnesic-pi/policy.nft.in
install -m 0644 "$repo_root/config/99-amnesic-pi.conf" /etc/sysctl.d/99-amnesic-pi.conf

if [[ ! -e /etc/amnesic-pi/network.env ]]; then
  install -m 0600 "$repo_root/config/network.env.example" /etc/amnesic-pi/network.env
fi

# Keep a backup before replacing Tor's default config.
if [[ -e /etc/tor/torrc && ! -e /etc/tor/torrc.pre-amnesic-pi ]]; then
  cp -a /etc/tor/torrc /etc/tor/torrc.pre-amnesic-pi
fi
install -m 0644 "$repo_root/config/torrc" /etc/tor/torrc

install -m 0644 "$repo_root/systemd/amnesic-pi-firewall.service" /etc/systemd/system/amnesic-pi-firewall.service
install -m 0644 "$repo_root/systemd/amnesic-pi-verify.service" /etc/systemd/system/amnesic-pi-verify.service
install -d -m 0755 /etc/systemd/system/tor@default.service.d
install -m 0644 "$repo_root/systemd/tor-amnesic-pi.conf" /etc/systemd/system/tor@default.service.d/10-amnesic-pi.conf

systemctl daemon-reload

cat <<'EOF'

Provisioning complete, but services were NOT enabled automatically.

Before enabling them:
  1. confirm /etc/amnesic-pi/network.env interface roles;
  2. keep a local-console recovery path;
  3. run: sudo amnesic-pi render-firewall | less
  4. render to a temporary file and validate with nft -c before applying.

Then enable:
  systemctl enable amnesic-pi-firewall.service tor@default.service amnesic-pi-verify.service

After runtime validation, enable Raspberry Pi OS OverlayFS manually with raspi-config.
EOF
