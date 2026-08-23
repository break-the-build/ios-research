#!/usr/bin/env bash
#
# build.sh — compile the macOS libFuzzer/ASan harness for one framework.
#
# Authorized / own-machine research only (see SECURITY.md). Requires an Apple
# clang with the fuzzer + sanitizer runtimes (the Xcode / Command Line Tools
# toolchain). CI does NOT run this — the mac:<framework> targets are opt-in.
#
# Usage:
#   tools/harness/build.sh [imageio|audiotoolbox|coregraphics] ...
#   tools/harness/build.sh all
#
# Output: tools/harness/build/<framework>_fuzzer
# The mac:<framework> target auto-discovers that path, or set:
#   export IOS_RESEARCH_MAC_HARNESS=/path/to/imageio_fuzzer
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/mac_fuzz_harness.c"
OUT_DIR="$HERE/build"
CC="${CC:-clang}"

SANITIZE="-fsanitize=fuzzer,address,undefined"
CFLAGS="${CFLAGS:-} -g -O1 -fno-omit-frame-pointer $SANITIZE"

declare -A DEFINE=(
  [imageio]="-DHARNESS_TARGET_IMAGEIO"
  [audiotoolbox]="-DHARNESS_TARGET_AUDIOTOOLBOX"
  [coregraphics]="-DHARNESS_TARGET_COREGRAPHICS"
)

build_one() {
  local key="$1"
  local def="${DEFINE[$key]:-}"
  if [[ -z "$def" ]]; then
    echo "unknown framework key: $key (want: ${!DEFINE[*]})" >&2
    return 2
  fi
  mkdir -p "$OUT_DIR"
  local out="$OUT_DIR/${key}_fuzzer"
  echo ">> building $key -> $out"
  # -ldl for dlopen/dlsym (usually implicit on macOS but explicit is safe).
  # shellcheck disable=SC2086
  "$CC" $CFLAGS "$def" "$SRC" -o "$out"
  echo ">> built $out"
}

main() {
  if [[ $# -eq 0 ]]; then
    echo "usage: $0 [imageio|audiotoolbox|coregraphics|all] ..." >&2
    exit 2
  fi
  local targets=("$@")
  if [[ "${1:-}" == "all" ]]; then
    targets=(imageio audiotoolbox coregraphics)
  fi
  for t in "${targets[@]}"; do
    build_one "$t"
  done
}

main "$@"
