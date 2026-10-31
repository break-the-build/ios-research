#!/usr/bin/env bash
#
# jackalope.sh — bounded coverage-guided campaign with coverage measured INSIDE
# the Apple framework (Jackalope + TinyInst binary instrumentation), driving the
# harness's persistent iosr_fuzz_file() entry point.
#
# Authorized / own-machine research only (SECURITY.md).
#
# Why: the harness's own SanitizerCoverage only sees harness code, so it cannot
# tell the fuzzer it reached new framework code. TinyInst instruments the
# precompiled framework itself (measured: ~15.9k ImageIO code offsets in 60 s).
#
# Two-stage pipeline (Jackalope and Guard Malloc interfere when combined:
# measured ~21,000 vs 72 executions/minute), so:
#   1. tools/harness/jackalope.sh <fw> <seconds>       grow a coverage corpus
#   2. python tools/mac_campaign/run.py --target mac:<fw> \
#          --seed-dir <out>/samples --cases N          replay + mutate it under
#                                                      the Guard Malloc harness
#
# Usage:
#   tools/harness/jackalope.sh <framework> <seconds> [threads] [-- extra fuzzer args]
#   frameworks: imageio | coretext | audiotoolbox | coregraphics
#
# Environment:
#   JACKALOPE        path to Jackalope's `fuzzer` (default ~/dev/Jackalope/build/fuzzer)
#   JACKALOPE_OUT    output directory (default tools/harness/jackalope-out/<fw>);
#                    the run builds its own harness copy in <out>/bin
#   JACKALOPE_MODULES  override the instrumented modules (space-separated)
#
# Requires: Jackalope built from https://github.com/googleprojectzero/Jackalope
# (cmake .. -DCMAKE_POLICY_VERSION_MINIMUM=3.5 with CMake 4). The harness is
# ad-hoc signed with debuggable.entitlements (get-task-allow) so the same-user
# fuzzer can attach without root.
#
# NOTE: stock macOS /bin/bash 3.2 compatible (no associative arrays).
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
JACKALOPE="${JACKALOPE:-$HOME/dev/Jackalope/build/fuzzer}"

# Libraries where each framework's parsing actually happens (observed loaded
# while decoding real files): fonts parse in libFontParser, AAC/MP3 decode in
# AudioCodecs, PDF lives in CoreGraphics.
modules_for() {
  case "$1" in
    imageio)      echo "ImageIO AppleJPEG" ;;
    coretext)     echo "libFontParser.dylib CoreText" ;;
    audiotoolbox) echo "AudioToolboxCore AudioCodecs" ;;
    coregraphics) echo "CoreGraphics" ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '2,32p' "$HERE/jackalope.sh" | sed 's/^# \{0,1\}//'
  exit 2
}

# stop_jackalope <jackalope pid> <harness path> [target pid ...]
#
# Stops Jackalope and ONLY the target processes it spawned, targets first.
# TinyInst leaves the framework's original code non-executable inside each
# target; a target that outlives Jackalope executes that code with nobody to
# handle the fault and dies with SIGBUS KERN_PROTECTION_FAILURE at its own PC.
# Each such death wrote a convincing but fake framework crash report (23 of them
# sent a whole scan chasing a bug that did not exist). Freezing Jackalope first
# stops it respawning targets; SIGKILL writes no crash report. Matching by
# harness path (the old `pkill -f`) also killed any run.py campaign using the
# same harness binary, so a PID is killed only if it is still running $harness.
stop_jackalope() {
  local pid="$1" harness="$2"
  shift 2
  kill -STOP "$pid" 2>/dev/null || true
  local t
  for t in "$@" $(pgrep -P "$pid" 2>/dev/null || true); do
    case "$(ps -o command= -p "$t" 2>/dev/null)" in
      "$harness"*) kill -9 "$t" 2>/dev/null || true ;;
    esac
  done
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

main() {
  [ $# -ge 2 ] || usage
  local fw="$1" secs="$2" threads="${3:-4}"
  shift 2
  [ $# -gt 0 ] && shift
  [ "${1:-}" = "--" ] && shift
  local modules
  modules="$(modules_for "$fw")" || {
    echo "unknown framework: $fw (want: imageio coretext audiotoolbox coregraphics)" >&2
    exit 2
  }
  modules="${JACKALOPE_MODULES:-$modules}"
  case "$secs" in ''|*[!0-9]*) echo "seconds must be a positive integer" >&2; exit 2 ;; esac
  [ -x "$JACKALOPE" ] || { echo "Jackalope fuzzer not found at $JACKALOPE (set JACKALOPE)" >&2; exit 3; }

  local out="${JACKALOPE_OUT:-$HERE/jackalope-out/$fw}"
  # A private copy of the harness, so this run never rebuilds or re-signs the
  # binary a run.py campaign is exec'ing (a half-written or re-signed harness
  # dies mid-campaign), and stop_jackalope can only match its own targets.
  local harness="$out/bin/${fw}_fuzzer"
  IOSR_BUILD_DIR="$out/bin" bash "$HERE/build.sh" "$fw" >/dev/null
  codesign -s - -f --entitlements "$HERE/debuggable.entitlements" "$harness" 2>/dev/null

  mkdir -p "$out/in"
  if [ -z "$(ls -A "$out/in")" ]; then
    PYTHONPATH="$REPO/src" python3 - "$fw" "$out/in" <<'PY'
import sys
from ios_research.targets import _mac_seeds, _mac_real_seeds
key, dest = sys.argv[1], sys.argv[2]
seeds = _mac_seeds.seeds(key) + _mac_real_seeds.real_file_seeds(key, limit=100, max_bytes=64 * 1024)
for i, data in enumerate(seeds):
    with open(f"{dest}/seed{i:04d}", "wb") as fh:
        fh.write(data)
print(f"jackalope.sh: {len(seeds)} seeds -> {dest}")
PY
  fi

  local inst=""
  for m in $modules; do inst="$inst -instrument_module $m"; done
  echo "jackalope.sh: $fw for ${secs}s, $threads threads, instrumenting: $modules"
  # Guard Malloc stays OFF here (it collapses throughput under TinyInst); the
  # harness must not re-exec itself because Jackalope owns the process.
  # -generate_unwind: ImageIO and friends throw C++ exceptions internally and
  # catch them; without unwind info for instrumented code every throw became
  # "terminating due to uncaught exception of type int" -- a fake crash that
  # also discarded every input reaching an error path.
  # shellcheck disable=SC2086
  IOSR_GMALLOC_REEXEC=0 "$JACKALOPE" -in "$out/in" -out "$out/out" -t 3000 -t1 15000 \
    -delivery file $inst -target_module "${fw}_fuzzer" -target_method _iosr_fuzz_file \
    -nargs 1 -iterations 1000 -persist -loop -cmp_coverage -generate_unwind \
    -nthreads "$threads" "$@" \
    -- "$harness" @@ > "$out/fuzzer.log" 2>&1 &
  local pid=$! n=0 targets=""
  while kill -0 "$pid" 2>/dev/null && [ "$n" -lt "$((secs * 2))" ]; do
    sleep 0.5; n=$((n + 1))
    # Remember the live targets: if Jackalope dies on its own, its orphans are
    # reparented to launchd and can no longer be found through it.
    targets="$(pgrep -P "$pid" 2>/dev/null || true)"
  done
  stop_jackalope "$pid" "$harness" $targets

  echo "jackalope.sh: final stats ($out/fuzzer.log):"
  grep -E "Total execs|Unique samples|Crashes|Hangs|Offsets|ABORT" "$out/fuzzer.log" | tail -5
  echo "next: python tools/mac_campaign/run.py --target mac:$fw --seed-dir $out/out/samples --cases 200000"
  echo "      (crashes in $out/out/crashes are candidates: replay each in $harness under Guard Malloc)"
}

main "$@"
