#!/usr/bin/env bash
#
# build.sh — compile the macOS ASan harness for one or more frameworks.
#
# Authorized / own-machine research only (see SECURITY.md). CI does NOT run this
# — the mac:<framework> targets are opt-in.
#
# Two modes:
#   --driver     (DEFAULT) standalone ASan/UBSan driver. Builds on the STOCK
#                Apple toolchain — Apple clang ships ASan/UBSan but NOT the
#                libFuzzer runtime. Recommended for most machines.
#   --libfuzzer  build a libFuzzer binary (-fsanitize=fuzzer,...). Requires a
#                clang that ships libclang_rt.fuzzer_osx.a, e.g.:
#                   brew install llvm && CC=$(brew --prefix llvm)/bin/clang
#
# Usage:
#   tools/harness/build.sh [--driver|--libfuzzer] <framework> [<framework> ...]
#   tools/harness/build.sh all
#   frameworks: imageio | audiotoolbox | coregraphics | all
#
# Output: tools/harness/build/<framework>_fuzzer
# The mac:<framework> target auto-discovers that path, or set:
#   export IOS_RESEARCH_MAC_HARNESS=/path/to/imageio_fuzzer
#
# NOTE: intentionally avoids bash-4 features (associative arrays) so it runs on
# the stock macOS /bin/bash 3.2.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/mac_fuzz_harness.c"
OUT_DIR="$HERE/build"
MODE="driver"

# Prefer the active toolchain's clang (xcrun). The Command Line Tools clang ships
# an ASan runtime that CHECK-fails (asan_init_is_running) when the harness
# dlopens a system framework, so warn if that's what's active.
if [ -z "${CC:-}" ]; then
  if CC="$(xcrun -f clang 2>/dev/null)" && [ -n "$CC" ]; then :; else CC="clang"; fi
fi
_devdir="$(xcode-select -p 2>/dev/null || true)"
case "$_devdir" in
  *CommandLineTools*)
    echo "WARNING: active developer dir is Command Line Tools ($_devdir)." >&2
    echo "  Its ASan runtime is known to fail at runtime (asan_init_is_running)" >&2
    echo "  when dlopening system frameworks. Use a full Xcode or Homebrew LLVM:" >&2
    echo "    sudo xcode-select -s /Applications/Xcode.app/Contents/Developer" >&2
    echo "  or:  CC=\$(brew --prefix llvm)/bin/clang tools/harness/build.sh ..." >&2
    ;;
esac

# -DHARNESS_TARGET_* for a framework key (bash 3.2 compatible; no assoc arrays).
define_for() {
  case "$1" in
    imageio)      echo "-DHARNESS_TARGET_IMAGEIO" ;;
    audiotoolbox) echo "-DHARNESS_TARGET_AUDIOTOOLBOX" ;;
    coregraphics) echo "-DHARNESS_TARGET_COREGRAPHICS" ;;
    selftest)     echo "-DHARNESS_TARGET_SELFTEST" ;;
    *) return 1 ;;
  esac
}

sanitize_flags() {
  if [ "$MODE" = "libfuzzer" ]; then
    echo "-fsanitize=fuzzer,address,undefined"
  else
    echo "-fsanitize=address,undefined -DHARNESS_STANDALONE"
  fi
}

# Resolve the macOS SDK so <stdio.h> etc. are found (needed on some setups).
sdk_flags() {
  local sdk
  if sdk="$(xcrun --show-sdk-path 2>/dev/null)" && [ -n "$sdk" ]; then
    echo "-isysroot $sdk"
  fi
}

build_one() {
  local key="$1" def out
  if ! def="$(define_for "$key")"; then
    echo "unknown framework key: $key (want: imageio audiotoolbox coregraphics)" >&2
    return 2
  fi
  mkdir -p "$OUT_DIR"
  out="$OUT_DIR/${key}_fuzzer"
  echo ">> building $key ($MODE) -> $out"
  # shellcheck disable=SC2046,SC2086
  "$CC" -g -O1 -fno-omit-frame-pointer $(sanitize_flags) $(sdk_flags) \
    ${CFLAGS:-} "$def" "$SRC" -o "$out"
  echo ">> built $out"
}

main() {
  local args=()
  local a
  for a in "$@"; do
    case "$a" in
      --driver)    MODE="driver" ;;
      --libfuzzer) MODE="libfuzzer" ;;
      --help|-h)
        sed -n '2,30p' "$HERE/build.sh" | sed 's/^# \{0,1\}//'
        exit 0 ;;
      *) args+=("$a") ;;
    esac
  done

  if [ "${#args[@]}" -eq 0 ]; then
    echo "usage: $0 [--driver|--libfuzzer] <imageio|audiotoolbox|coregraphics|all> ..." >&2
    exit 2
  fi
  if [ "${args[0]}" = "all" ]; then
    args=(imageio audiotoolbox coregraphics)
  fi
  for a in "${args[@]}"; do
    build_one "$a"
  done
}

main "$@"
