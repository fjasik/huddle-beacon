#!/usr/bin/env bash
# Installs or upgrades huddle-beacon on a Raspberry Pi (Bookworm, Python 3.11+). Run as root, from the folder that
# tools/provision.py copied over:  sudo bash install.sh huddle-beacon.tar.gz
#
#   /opt/huddle-beacon/venv     the code, in its own Python environment
#   /etc/huddle-beacon/         config, certificates and the beacon's key (provision.py fills it)
#   /var/lib/huddle-beacon/     the database
#
# The service is enabled here but only started by provision.py, once the config is in place.
set -euo pipefail

PACKAGE=$(realpath "${1:?usage: install.sh <huddle-beacon.tar.gz>}")
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
"$APP/venv/bin/pip" install --quiet "$PACKAGE"
# Same version number as before, so force the new code in.
"$APP/venv/bin/pip" install --quiet --force-reinstall --no-deps "$PACKAGE"

install -m 644 "$HERE/huddle-beacon.service" /etc/systemd/system/huddle-beacon.service
systemctl daemon-reload
systemctl enable huddle-beacon.service
echo "installed: $("$APP/venv/bin/python" -m beacon --version)"
