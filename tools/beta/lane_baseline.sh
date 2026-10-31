#!/usr/bin/env bash
#
# lane_baseline.sh — record the research lanes' binaries from one iOS build,
# so a beta can be diffed against it (tools/beta/lane_diff.py).
#
# Authorized / own-machine research only (SECURITY.md).
#
# Usage:
#   tools/beta/lane_baseline.sh <IPSW | OTA | dyld_shared_cache_arm64e> <out-dir>
#
# For each lane image (lane_diff.py's LANES): the extracted dylib, its exported
# symbols, its function starts, and a staticscan format-token fingerprint, in
# <out-dir>/<build>/<image>/. The dyld shared cache itself (~7.5 GB) is
# extracted to a temporary directory and deleted afterwards, so only one cache
# is ever on disk; extraction refuses to start with under 15 GB free.
#
# NOTE: stock macOS /bin/bash 3.2 compatible.
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${PY:-$REPO/.venv/bin/python}"
[ -x "$PY" ] || PY="$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)/../.venv/bin/python"
MIN_FREE_GB=15
IMAGES="RawCamera ImageIO CMPhoto AppleJPEG AppleJPEGXL CoreSVG
AudioToolboxCore AudioToolbox AudioCodecs CoreAudio CoreMedia MediaToolbox
CoreGraphics
libFontParser.dylib CoreText FontServices libType1Scaler.dylib OTSVG"

[ $# -eq 2 ] || { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
src="$1"; out="$2"
command -v ipsw > /dev/null || { echo "ipsw not installed (brew install blacktop/tap/ipsw)" >&2; exit 3; }
mkdir -p "$out"

tmp=""
cleanup() { [ -n "$tmp" ] && rm -rf "$tmp"; }
trap cleanup EXIT

case "$(basename "$src")" in
  dyld_shared_cache_arm64e) dsc="$src" ;;
  *)
    free_gb="$(df -g "$out" | tail -1 | awk '{print $4}')"
    if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
      echo "only ${free_gb} GB free under $out; need ${MIN_FREE_GB} GB for the cache" >&2
      exit 4
    fi
    tmp="$(mktemp -d "$out/.dsc.XXXXXX")"
    echo "extracting the dyld shared cache from $src ..."
    # Betas arrive as OTAs (AssetData/ payloads), releases as IPSWs.
    if unzip -l "$src" 2>/dev/null | grep -q " AssetData/"; then
      ipsw ota extract "$src" --dyld --dyld-arch arm64e --confirm --output "$tmp" \
        > "$tmp/extract.log" 2>&1 || { tail -5 "$tmp/extract.log" >&2; exit 1; }
    else
      ipsw extract --dyld --dyld-arch arm64e -o "$tmp" "$src" > "$tmp/extract.log" 2>&1 \
        || { tail -5 "$tmp/extract.log" >&2; exit 1; }
    fi
    dsc="$(find "$tmp" -name dyld_shared_cache_arm64e | head -1)"
    [ -n "$dsc" ] || { echo "no arm64e dyld shared cache in $src" >&2; exit 1; }
    ;;
esac

build="$(basename "$(dirname "$dsc")")"          # e.g. 24B119__iPhone14,2
dest="$out/$build"
mkdir -p "$dest"
found=""; missing=""
for image in $IMAGES; do
  d="$dest/$image"
  mkdir -p "$d"
  if ! ipsw dyld extract "$dsc" "$image" -o "$d" > /dev/null 2>&1; then
    missing="$missing $image"; rm -rf "$d"; continue
  fi
  ipsw dyld symaddr "$dsc" --image "$image" 2>/dev/null | sort > "$d/exports.txt"
  ipsw dyld macho "$dsc" "$image" --starts 2>/dev/null > "$d/starts.txt"
  dylib="$(find "$d" -type f -name "${image%.dylib}*" ! -name '*.txt' | head -1)"
  PYTHONPATH="$REPO/src" "$PY" -m ios_research staticscan fingerprint "$dylib" --json \
    > "$d/fingerprint.json" 2>/dev/null || true
  found="$found $image"
done
printf '{"source": "%s", "build": "%s", "ipsw": "%s", "recorded": "%s",\n "images": "%s", "missing": "%s"}\n' \
  "$src" "$build" "$(ipsw version 2>/dev/null | head -1)" "$(date -u +%Y-%m-%dT%H:%MZ)" \
  "${found# }" "${missing# }" > "$dest/manifest.json"
echo "recorded $build in $dest"
echo "  images:${found}"
[ -z "$missing" ] || echo "  missing:${missing}"
