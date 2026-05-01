#!/usr/bin/env bash
# Install rndis-mac as a system LaunchDaemon. Runs as root, starts at boot,
# auto-restarts. After install you no longer need to launch rndis-up by hand.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="$REPO_DIR/target/release/rndis-up"
BIN_DST="/usr/local/bin/rndis-up"
PLIST_SRC="$REPO_DIR/packaging/com.rndis-mac.plist"
PLIST_DST="/Library/LaunchDaemons/com.rndis-mac.plist"
LOG_FILE="/var/log/rndis-mac.log"

if [[ $EUID -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

if [[ ! -x "$BIN_SRC" ]]; then
    echo "Building release binary..."
    (cd "$REPO_DIR" && sudo -u "$SUDO_USER" cargo build --release --bin rndis-up)
fi

echo "Installing $BIN_SRC -> $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"

echo "Installing $PLIST_SRC -> $PLIST_DST"
install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DST"

touch "$LOG_FILE"
chown root:wheel "$LOG_FILE"
chmod 0644 "$LOG_FILE"

# If already loaded, bootout first so we pick up any new plist contents.
launchctl bootout system "$PLIST_DST" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable system/com.rndis-mac
launchctl kickstart -k system/com.rndis-mac

echo
echo "Installed. Logs: tail -f $LOG_FILE"
echo "Status:           launchctl print system/com.rndis-mac | head -20"
echo "Uninstall:        sudo $REPO_DIR/packaging/uninstall.sh"
