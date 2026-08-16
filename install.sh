#!/bin/sh
set -eu

LABEL="io.github.vaskevich.orbstack-sonos-relay"
INSTALL_DIR="/usr/local/libexec/orbstack-sonos-relay"
PROGRAM="$INSTALL_DIR/orbstack-sonos-relay.py"
PLIST="/Library/LaunchDaemons/$LABEL.plist"

LAN_IFACE="${LAN_IFACE:-en0}"
ORB_IFACE="${ORB_IFACE:-bridge100}"
HA_IP="${HA_IP:-auto}"
EVENT_PORTS="${EVENT_PORTS:-1400-1499}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (for example: sudo ./install.sh)." >&2
    exit 1
fi

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This LaunchDaemon installer supports macOS only." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE="$SCRIPT_DIR/orbstack-sonos-relay.py"

if [ ! -f "$SOURCE" ]; then
    echo "Missing daemon source: $SOURCE" >&2
    exit 1
fi

if [ ! -x "$PYTHON_BIN" ]; then
    echo "Python is not executable at PYTHON_BIN=$PYTHON_BIN" >&2
    exit 1
fi

# These values are inserted into XML. Restrict them to their expected syntax.
case "$LAN_IFACE:$ORB_IFACE" in
    *[!A-Za-z0-9._:-]*) echo "LAN_IFACE and ORB_IFACE contain unsupported characters." >&2; exit 1 ;;
esac
case "$PYTHON_BIN" in
    /*) ;;
    *) echo "PYTHON_BIN must be an absolute path." >&2; exit 1 ;;
esac
case "$PYTHON_BIN" in
    *[!A-Za-z0-9._/+:-]*) echo "PYTHON_BIN contains unsupported characters." >&2; exit 1 ;;
esac
case "$EVENT_PORTS" in
    *[!0-9,-]*) echo "EVENT_PORTS must contain only ports, commas, and ranges." >&2; exit 1 ;;
esac
case "$HA_IP" in
    *[!A-Za-z0-9.]*) echo "HA_IP must be 'auto' or an IPv4 address." >&2; exit 1 ;;
esac

"$PYTHON_BIN" "$SOURCE" --ha-ip "$HA_IP" --event-ports "$EVENT_PORTS" --check-config

install -d -o root -g wheel -m 755 "$INSTALL_DIR"
install -o root -g wheel -m 755 "$SOURCE" "$PROGRAM"

PLIST_TMP=$(mktemp "/tmp/$LABEL.plist.XXXXXX")
trap 'rm -f "$PLIST_TMP"' EXIT HUP INT TERM

cat > "$PLIST_TMP" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$PROGRAM</string>
        <string>--lan</string>
        <string>$LAN_IFACE</string>
        <string>--orb</string>
        <string>$ORB_IFACE</string>
        <string>--ha-ip</string>
        <string>$HA_IP</string>
        <string>--event-ports</string>
        <string>$EVENT_PORTS</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StandardOutPath</key>
    <string>/var/log/orbstack-sonos-relay.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/orbstack-sonos-relay.err.log</string>
</dict>
</plist>
EOF

plutil -lint "$PLIST_TMP" >/dev/null
install -o root -g wheel -m 644 "$PLIST_TMP" "$PLIST"

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
launchctl kickstart -k "system/$LABEL"

echo "Installed $LABEL"
echo "  LAN interface:      $LAN_IFACE"
echo "  OrbStack interface: $ORB_IFACE"
echo "  HA address:         $HA_IP"
echo "  Callback ports:     $EVENT_PORTS"
echo
echo "Status: sudo launchctl print system/$LABEL"
echo "Logs:   sudo tail -f /var/log/orbstack-sonos-relay.log /var/log/orbstack-sonos-relay.err.log"
echo "Stop:   sudo launchctl bootout system/$LABEL"
