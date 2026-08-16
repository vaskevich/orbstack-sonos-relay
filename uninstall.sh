#!/bin/sh
set -eu

LABEL="io.github.vaskevich.orbstack-sonos-relay"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALL_DIR="/usr/local/libexec/orbstack-sonos-relay"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root (for example: sudo ./uninstall.sh)." >&2
    exit 1
fi

launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
rm -rf "$INSTALL_DIR"

echo "Removed $LABEL and $INSTALL_DIR"
echo "Log files in /var/log were preserved; remove them manually if desired."
