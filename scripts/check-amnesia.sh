#!/bin/bash
set -euo pipefail

marker=/etc/amnesic-pi/.amnesia-probe
case ${1:-} in
  arm)
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
      echo "run as root" >&2; exit 2
    fi
    printf 'probe-created=%s\n' "$(date -u +%FT%TZ)" > "$marker"
    sync
    echo "Marker created at $marker. Reboot, then run: sudo $0 verify"
    ;;
  verify)
    if [[ -e "$marker" ]]; then
      echo "FAIL: marker survived reboot; root amnesia is not proven." >&2
      exit 1
    fi
    echo "PASS: marker is absent. If this is the same boot media after an intervening reboot, the probe did not persist."
    ;;
  *)
    echo "usage: $0 {arm|verify}" >&2
    exit 2
    ;;
esac
