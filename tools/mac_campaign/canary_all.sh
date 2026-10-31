#!/usr/bin/env bash
#
# canary_all.sh — run the detection canary (ios_research.targets.canary) for
# every mac framework under every Guard Malloc oracle, and print a table.
# Exits 1 if any combination fails. Run it after a macOS update or a harness
# rebuild, or nightly.
#
# Authorized / own-machine research only (SECURITY.md).
#
# Usage: [ORACLES="default before"] tools/mac_campaign/canary_all.sh [framework ...]
#   default frameworks: imageio coretext audiotoolbox coregraphics
#   default ORACLES:    default before strict
# On macOS 26.x, strict (MALLOC_STRICT_SIZE) crashes the imageio, audiotoolbox
# and coregraphics harnesses on valid input, so those rows fail; leave strict
# out of ORACLES for a nightly that should stay green.
#
# NOTE: stock macOS /bin/bash 3.2 compatible.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${PY:-python3}"
ORACLES="${ORACLES:-default before strict}"
[ $# -gt 0 ] || set -- imageio coretext audiotoolbox coregraphics

failed=0
printf "%-13s %-8s %s\n" framework oracle verdict
for fw in "$@"; do
  for oracle in $ORACLES; do
    case "$oracle" in
      default) envs="" ;;
      before)  envs="MALLOC_PROTECT_BEFORE=1" ;;
      strict)  envs="MALLOC_STRICT_SIZE=1" ;;
      *) echo "unknown oracle: $oracle (want: default before strict)" >&2; exit 2 ;;
    esac
    # shellcheck disable=SC2086
    line="$(env $envs PYTHONPATH="$REPO/src" "$PY" "$HERE/run.py" \
              --target "mac:$fw" --canary-only 2>&1 | grep -E '^(canary|error):' | tail -1)"
    case "$line" in "canary: PASS"*) ;; *) failed=1 ;; esac
    printf "%-13s %-8s %s\n" "$fw" "$oracle" "${line:-no output}"
  done
done
exit "$failed"
