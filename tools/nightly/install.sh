#!/usr/bin/env bash
#
# install.sh — install (or remove) the nightly oracle check as a launchd agent.
#
# Authorized / own-machine research only (SECURITY.md).
#
# Usage:
#   tools/nightly/install.sh [--repo PATH] [--at HH:MM]   install / update
#   tools/nightly/install.sh --run-now                     start a run now
#   tools/nightly/install.sh --uninstall                   remove it
#
# The script is copied out of the repository (a nightly run switches its own
# worktree, and bash must not read a script that changes underneath it).
#
# NOTE: stock macOS /bin/bash 3.2 compatible.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="com.ios-research.nightly"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
SUPPORT="$HOME/Library/Application Support/ios-research"
LOGDIR="$HOME/Library/Logs/ios-research"
DOMAIN="gui/$(id -u)"

repo="$(git -C "$HERE" rev-parse --path-format=absolute --git-common-dir)"
repo="$(dirname "$repo")"
at="05:15"
action="install"
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo="$2"; shift ;;
    --at) at="$2"; shift ;;
    --run-now) action="run" ;;
    --uninstall) action="uninstall" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$action" in
  uninstall)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$PLIST" "$SUPPORT/nightly.sh"
    echo "removed $LABEL"
    exit 0 ;;
  run)
    launchctl kickstart "$DOMAIN/$LABEL"
    echo "started; log: $LOGDIR/nightly-latest.json when done"
    exit 0 ;;
esac

case "$at" in [0-2][0-9]:[0-5][0-9]) ;; *) echo "--at wants HH:MM" >&2; exit 2 ;; esac
hour=$((10#${at%%:*})); minute=$((10#${at##*:}))
[ -x "$repo/.venv/bin/python" ] || { echo "no venv at $repo/.venv" >&2; exit 3; }

mkdir -p "$SUPPORT" "$LOGDIR" "$(dirname "$PLIST")"
cp "$HERE/nightly.sh" "$SUPPORT/nightly.sh"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$SUPPORT/nightly.sh</string>
    <string>$repo</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>$hour</integer><key>Minute</key><integer>$minute</integer></dict>
  <key>StandardOutPath</key><string>$LOGDIR/launchd.out</string>
  <key>StandardErrorPath</key><string>$LOGDIR/launchd.err</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST" > /dev/null
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "installed $LABEL: daily at $at for $repo"
echo "logs: $LOGDIR   run now: $0 --run-now   remove: $0 --uninstall"
