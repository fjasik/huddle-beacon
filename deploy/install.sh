#!/usr/bin/env bash
# Installs or upgrades huddle-beacon on a Raspberry Pi (Bookworm, Python 3.11+). Run as root, from the folder that
# tools/provision.py copied over:  sudo bash install.sh huddle-beacon.tar.gz [--no-service]
#
#   /opt/huddle-beacon/venv     the code, in its own Python environment
#   /etc/huddle-beacon/         config, certificates and the beacon's key (provision.py fills it)
#   /var/lib/huddle-beacon/     the database
#
# The service is enabled here but only started by provision.py, once the config is in place. --no-service leaves
# systemd alone (and disables a service installed before), for running the beacon by hand.
#
# Bluetooth (phones over BLE): the service user joins the bluetooth group (to register with BlueZ), and BlueZ gets
# EATT off (Channels = 1: with EATT, clients missed notifications) and Experimental on (so it honours the advert
# interval the beacon asks for). bluetoothd restarts only if its config changed.
set -euo pipefail

PACKAGE=$(realpath "${1:?usage: install.sh <huddle-beacon.tar.gz> [--no-service]}")
WITH_SERVICE=$([ "${2:-}" = "--no-service" ] && echo no || echo yes)
HERE=$(dirname "$(realpath "$0")")
APP=/opt/huddle-beacon
CONF=/etc/huddle-beacon
DATA=/var/lib/huddle-beacon
SERVICE_USER=huddle-beacon

python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { echo "huddle-beacon needs Python 3.11 or newer" >&2; exit 1; }

id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o root -g "$SERVICE_USER" -m 750 "$CONF"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA"

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
# Same version number as before, so force the new code (and its metadata) in first, then add what it needs.
"$APP/venv/bin/pip" install --quiet --force-reinstall --no-deps "$PACKAGE"
"$APP/venv/bin/pip" install --quiet "huddle-beacon[ble] @ file://$PACKAGE"

BLUEZ=/etc/bluetooth/main.conf
if [ -f "$BLUEZ" ]; then
    usermod -aG bluetooth "$SERVICE_USER"
    before=$(md5sum "$BLUEZ")
    sed -i -E 's/^#?Channels = .*/Channels = 1/; s/^#?Experimental = .*/Experimental = true/' "$BLUEZ"
    if [ "$before" != "$(md5sum "$BLUEZ")" ]; then
        systemctl restart bluetooth
        sleep 2
    fi
    bluetoothctl power on >/dev/null || true
fi

if [ "$WITH_SERVICE" = yes ]; then
    install -m 644 "$HERE/huddle-beacon.service" /etc/systemd/system/huddle-beacon.service
    systemctl daemon-reload
    systemctl enable huddle-beacon.service
elif [ -f /etc/systemd/system/huddle-beacon.service ]; then
    systemctl disable --now huddle-beacon.service
fi
echo "installed: $("$APP/venv/bin/python" -m beacon --version)"
