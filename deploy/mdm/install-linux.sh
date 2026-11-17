#!/bin/sh
# Installs the Enterplace device agent on Linux: the binary in /usr/local/bin, the enrolment token in
# /etc/enterplace/device-token (mode 0600) and the systemd unit enterplace-device, enabled and started.
#
#   sudo ENTERPLACE_DEVICE_TOKEN=enterplace_dev_... deploy/mdm/install-linux.sh https://enterplace.example.com [binary]
#   sudo deploy/mdm/install-linux.sh --uninstall
#
# Without ENTERPLACE_DEVICE_TOKEN a token file already on the machine is kept. Run it from your device management tool
# (Ansible, Fleet, Intune for Linux) or by hand.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT=/etc/systemd/system/enterplace-device.service
TOKEN=/etc/enterplace/device-token

[ "$(id -u)" = 0 ] || { echo "run as root: it writes /usr/local/bin, /etc/enterplace and a systemd unit." >&2; exit 2; }
command -v systemctl >/dev/null || { echo "systemctl not found: this script needs systemd. Run enterplace device from your own init instead." >&2; exit 2; }

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now enterplace-device 2>/dev/null || true
  rm -f "$UNIT" "$TOKEN" /usr/local/bin/enterplace
  systemctl daemon-reload
  echo "removed the Enterplace device agent. Tool settings it wrote in each home stay as they are."
  exit 0
fi

CP="${1:?usage: install-linux.sh <control plane URL> [binary] | --uninstall}"
BIN="${2:-$HERE/../../target/release/enterplace-enterprise}"
case "$CP" in
  https://*) ;;
  *) echo "the control plane URL is the gateway's https address, such as https://enterplace.example.com. Got $CP." >&2; exit 2 ;;
esac
case "$CP" in
  *[!A-Za-z0-9.:/_-]*) echo "the control plane URL holds a character an address does not: $CP." >&2; exit 2 ;;
esac
[ -x "$BIN" ] || { echo "no binary at $BIN: pass its path as the second argument." >&2; exit 2; }

install -m 0755 "$BIN" /usr/local/bin/enterplace
install -d -m 0700 /etc/enterplace
if [ -n "${ENTERPLACE_DEVICE_TOKEN:-}" ]; then
  (umask 077 && printf '%s' "$ENTERPLACE_DEVICE_TOKEN" > "$TOKEN")
elif [ ! -s "$TOKEN" ]; then
  echo "no enrolment token: set ENTERPLACE_DEVICE_TOKEN, or put it in $TOKEN (mode 0600) first." >&2; exit 2
fi
sed "s|CONTROL_PLANE_URL|$CP|" "$HERE/enterplace-device.service" > "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable --now enterplace-device
systemctl restart enterplace-device
echo "installed /usr/local/bin/enterplace and $UNIT. Its log: journalctl -u enterplace-device"
