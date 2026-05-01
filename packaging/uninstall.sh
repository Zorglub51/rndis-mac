#!/usr/bin/env bash
set -euo pipefail

PLIST_DST="/Library/LaunchDaemons/com.rndis-mac.plist"
BIN_DST="/usr/local/bin/rndis-up"

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

launchctl bootout system "$PLIST_DST" 2>/dev/null || true
rm -f "$PLIST_DST"
rm -f "$BIN_DST"

echo "Uninstalled. (Log file at /var/log/rndis-mac.log left in place.)"
