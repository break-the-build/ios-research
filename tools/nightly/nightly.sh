#!/usr/bin/env bash
#
# nightly.sh — nightly health check of the research oracle on this Mac.
#
# Authorized / own-machine research only (SECURITY.md).
#
# In a dedicated worktree pinned to origin/main (.worktrees/nightly, so no
# campaign's binaries are touched): build every harness, run the detection
# canary for every framework under the default and MALLOC_PROTECT_BEFORE
# oracles, and run the native test suite. On failure, post a macOS
# notification. Logs go to ~/Library/Logs/ios-research/.
#
# Usage: nightly.sh <path to the ios-research repository>
# Installed by tools/nightly/install.sh as a launchd agent.
#
# NOTE: stock macOS /bin/bash 3.2 compatible.
set -u

REPO="${1:?usage: nightly.sh <repo>}"
WT="$REPO/.worktrees/nightly"
PY="$REPO/.venv/bin/python"
LOGDIR="$HOME/Library/Logs/ios-research"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOG="$LOGDIR/nightly-$STAMP.log"
mkdir -p "$LOGDIR"
exec > "$LOG" 2>&1

notify() {
  osascript -e "display notification \"$1\" with title \"ios-research nightly\"" \
    > /dev/null 2>&1 || true
}

step() {   # step <name> <command...>: run, record PASS/FAIL
  local name="$1"
  shift
  echo "=== $name ($(date +%H:%M:%S))"
  if "$@"; then
    echo "--- $name: PASS"
    return 0
  fi
  echo "--- $name: FAIL"
  failed="$failed $name"
  return 1
}

sync_worktree() {
  if [ ! -d "$WT" ]; then
    git -C "$REPO" worktree add -q --detach "$WT" origin/main || return 1
  fi
  git -C "$WT" fetch -q origin && git -C "$WT" switch -q --detach origin/main \
    && git -C "$WT" log --oneline -1
}

build_all() {
  local fw
  for fw in imageio coretext audiotoolbox coregraphics videotoolbox selftest; do
    bash "$WT/tools/harness/build.sh" "$fw" > /dev/null || return 1
  done
}

canary() {
  ORACLES="default before" PY="$PY" bash "$WT/tools/mac_campaign/canary_all.sh"
}

native_tests() {
  (cd "$WT" && PYTHONPATH=src "$PY" -m pytest -p no:cacheprovider -m native -q -rs)
}

failed=""
caffeinate -i -w $$ &
step sync sync_worktree && {
  step build build_all
  step canary canary
  step native-tests native_tests
}

STATUS="PASS"
[ -z "$failed" ] || STATUS="FAIL:$failed"
echo "=== nightly $STATUS"
printf '{"stamp": "%s", "status": "%s", "log": "%s"}\n' "$STAMP" "$STATUS" "$LOG" \
  > "$LOGDIR/nightly-latest.json"
# Keep two weeks of logs.
find "$LOGDIR" -name 'nightly-2*.log' -mtime +14 -delete 2>/dev/null
if [ -n "$failed" ]; then
  notify "FAILED:$failed — see $LOG"
  exit 1
fi
exit 0
