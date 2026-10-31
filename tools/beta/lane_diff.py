#!/usr/bin/env python3
"""Diff two lane baselines (tools/beta/lane_baseline.sh) and rank the lanes.

New code is the least-fuzzed code: when a beta lands, this says which lane's
binaries changed and how, so the generators are aimed at it first. Per image:

* exported symbols added and removed;
* functions: count, and an estimate of how many changed size (function sizes
  come from the gaps between function starts; sizes present in one build and
  not the other are matched as a multiset, so code that merely moved does not
  count, while a patched function does);
* format tokens (staticscan fingerprint) added and removed: new tokens are the
  strongest sign of a new or newly reachable parser.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/beta/lane_diff.py <old-baseline-dir> <new-baseline-dir> \\
        [--json diff.json] > diff.md
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter

# The research lanes (research/plans/GO-FORWARD-STRATEGY.md) and the iOS
# images where their parsing runs. ImageIO's codecs live inside ImageIO on iOS.
LANES = {
    "1 DNG / camera RAW": ("RawCamera", "ImageIO", "CMPhoto"),
    "2 audio codecs": ("AudioToolboxCore", "AudioToolbox", "AudioCodecs", "CoreAudio",
                       "CoreMedia", "MediaToolbox"),
    "3 PDF": ("CoreGraphics",),
    "4 ImageIO formats": ("ImageIO", "AppleJPEG", "AppleJPEGXL", "CMPhoto", "CoreSVG"),
    "5 fonts": ("libFontParser.dylib", "CoreText", "FontServices", "libType1Scaler.dylib",
                "OTSVG"),
}
SHOW = 15


def _exports(d: pathlib.Path) -> set[str]:
    path = d / "exports.txt"
    if not path.exists():
        return set()
    return {ln.split()[-1] for ln in path.read_text().splitlines() if ln.strip()}


def _sizes(d: pathlib.Path) -> list[int]:
    path = d / "starts.txt"
    if not path.exists():
        return []
    starts = sorted({int(t, 16) for t in path.read_text().split() if t.startswith("0x")})
    return [b - a for a, b in zip(starts, starts[1:])]


def _tokens(d: pathlib.Path) -> set[str]:
    path = d / "fingerprint.json"
    try:
        matches = json.loads(path.read_text())["data"].get("matches", {})
    except (OSError, ValueError, KeyError, TypeError):
        return set()
    return {f"{fam}:{t['token'] if isinstance(t, dict) else t}"
            for fam, toks in matches.items() for t in toks}


def diff_image(old: pathlib.Path, new: pathlib.Path) -> dict:
    eo, en = _exports(old), _exports(new)
    so, sn = Counter(_sizes(old)), Counter(_sizes(new))
    to, tn = _tokens(old), _tokens(new)
    unmatched = sum((so - sn).values()) + sum((sn - so).values())
    return {
        "exports_added": sorted(en - eo), "exports_removed": sorted(eo - en),
        "functions": [sum(so.values()), sum(sn.values())],
        "functions_changed_est": unmatched // 2 + unmatched % 2,
        "tokens_added": sorted(tn - to), "tokens_removed": sorted(to - tn),
        "present": [old.is_dir(), new.is_dir()],
    }


def build_dir(path: pathlib.Path) -> pathlib.Path:
    """A baseline dir holds one <build>/ subdir; accept either level."""
    if (path / "manifest.json").exists():
        return path
    subs = [p for p in path.iterdir() if (p / "manifest.json").exists()]
    if len(subs) != 1:
        raise SystemExit(f"{path}: expected exactly one recorded build, found {len(subs)}")
    return subs[0]


def diff(old_dir: pathlib.Path, new_dir: pathlib.Path) -> dict:
    old_dir, new_dir = build_dir(old_dir), build_dir(new_dir)
    images = sorted({i for imgs in LANES.values() for i in imgs})
    per_image = {i: diff_image(old_dir / i, new_dir / i) for i in images}
    lanes = []
    for lane, imgs in LANES.items():
        score = sum(per_image[i]["functions_changed_est"] + 10 * len(per_image[i]["tokens_added"])
                    + len(per_image[i]["exports_added"]) for i in imgs)
        lanes.append({"lane": lane, "score": score, "images": list(imgs)})
    lanes.sort(key=lambda r: -r["score"])
    return {"old": old_dir.name, "new": new_dir.name, "lanes": lanes, "images": per_image}


def markdown(result: dict) -> str:
    out = [f"# Lane diff: {result['old']} → {result['new']}", "",
           "Score = changed functions (est.) + new exports + 10 × new format tokens.", "",
           "| Lane | Score |", "|---|---|"]
    out += [f"| {r['lane']} | {r['score']} |" for r in result["lanes"]]
    for name, d in result["images"].items():
        if not any(d["present"]):
            continue
        f_old, f_new = d["functions"]
        out += ["", f"## {name}", "",
                f"- functions: {f_old} → {f_new}; changed (est.): {d['functions_changed_est']}"]
        if not all(d["present"]):
            out.append(f"- present in old/new: {d['present'][0]}/{d['present'][1]}")
        for key, label in (("exports_added", "exports added"),
                           ("exports_removed", "exports removed"),
                           ("tokens_added", "format tokens added"),
                           ("tokens_removed", "format tokens removed")):
            items = d[key]
            if items:
                more = f" (+{len(items) - SHOW} more)" if len(items) > SHOW else ""
                out.append(f"- {label} ({len(items)}): " + ", ".join(items[:SHOW]) + more)
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", type=pathlib.Path)
    ap.add_argument("new", type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path, default=None, help="also write JSON here")
    args = ap.parse_args(argv)
    result = diff(args.old, args.new)
    if args.json:
        args.json.write_text(json.dumps(result, indent=2))
    sys.stdout.write(markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
