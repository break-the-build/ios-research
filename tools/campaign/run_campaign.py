"""Campaign runner: libFuzzer in-process loop -> CrashStore records.

Usage:
  .venv/bin/python tools/campaign/run_campaign.py --target imageio \
      --experiment exp_X [--duration 600] [--workers 7] [--rounds 4] \
      [--summary PATH]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from ios_research.workspace import Workspace          # noqa: E402
from ios_research.crashes import CrashStore           # noqa: E402
from ios_research.targets.mac import MacFuzzTarget    # noqa: E402

BASE = Path("/var/folders/lt/vm36m4590d92wclk432q9ttr0000gn/T/opencode")

SEED_GLOBS = {
    "imageio": [
        "/System/Library/Desktop Pictures/**/*.heic",
        "/System/Library/Desktop Pictures/*.heic",
        "/System/Library/Desktop Pictures/**/*.png",
        "/Library/Application Support/com.apple.idleassetsd/Customer/**/*",
        "/System/Library/CoreServices/DefaultDesktop.heic",
        "/System/Library/PrivateFrameworks/AssistantServices.framework/Versions/A/Resources/*png",
        "/System/Library/CoreServices/DefaultDesktopPlus*.heic",
    ],
    "coregraphics": [
        "/Library/Documentation/**/*.pdf",
        "/System/Library/PrivateFrameworks/HelpData.framework/**/*.pdf",
        "/usr/share/**/*.pdf",
        "/Applications/*.app/Contents/Resources/**/*.pdf",
    ],
    "audiotoolbox": [
        "/System/Library/Sounds/*.aiff",
        "/System/Library/Sounds/*.caf",
        "/System/Library/CoreServices/**/*.aif*",
        "/Applications/*.app/Contents/Resources/**/*.m4a",
        "/System/Library/PrivateFrameworks/AggregateDictionary.framework/**/*.caf",
    ],
    "coretext": [
        "/System/Library/Fonts/**/*.ttf",
        "/System/Library/Fonts/**/*.otf",
        "/System/Library/Fonts/**/*.ttc",
        "/Library/Fonts/**/*.ttf",
        "/Library/Fonts/**/*.otf",
        "/System/Library/Fonts/Supplemental/*.ttf",
        "/System/Library/AssetsV2/com.apple.MobileAsset.*Font*/**/*.ttf",
    ],
}

def _dict(tokens: list[str]) -> str:
    return "\n".join('"%s"' % t for t in tokens) + "\n"

DICTIONARIES = {
    "imageio": _dict([
        "PNG", "\\x89PNG\\x0d\\x0a\\x1a\\x0a", "IHDR", "IDAT", "IEND",
        "PLTE", "tRNS", "gAMA", "iCCP", "tEXt", "zTXt", "acTL", "fcTL",
        "fdAT", "\\xff\\xd8\\xff", "Exif", "JFIF", "\\xff\\xdb",
        "\\xff\\xc4", "\\xff\\xda", "\\xff\\xd9", "ftyp", "heic", "mif1",
        "meta", "mdat", "iloc", "iinf", "iprp", "ipco", "hvcC", "ispe",
        "GIF89a", "GIF87a", "II*\\x00", "MM\\x00*", "RIFF", "WEBP",
        "VP8 ", "VP8L", "VP8X",
    ]),
    "coregraphics": _dict([
        "%PDF-1.7", "%PDF-2.0", "obj", "endobj", "stream", "endstream",
        "xref", "trailer", "startxref", "Catalog", "Pages", "Page",
        "Contents", "Resources", "Font", "XObject", "Image", "Form",
        "/Filter", "/FlateDecode", "/DCTDecode", "/JPXDecode",
        "/CCITTFaxDecode", "/Type3", "/Widths", "/ToUnicode",
        "/EmbeddedFile", "/JavaScript", "/OpenAction", "/Launch", "/Names",
        "/AcroForm", "/Shading", "/Pattern", "/ExtGState", "/SMask",
        "/Group", "/Annots",
    ]),
    "audiotoolbox": _dict([
        "RIFF", "WAVE", "fmt ", "data", "fact", "LIST", "FORM", "AIFF",
        "AIFC", "COMM", "SSND", "caff", "desc", "chan", "info", "ftyp",
        "M4A ", "mp42", "moov", "trak", "mdia", "minf", "stbl", "stsd",
        "mp4a", "alac", "samr", ".mp3", "esds", "ID3 ", "LAME", "LAME3",
        "\\xff\\xfb", "\\xff\\xf3", "\\xff\\xe2", "TAG", "apPL",
    ]),
    "coretext": _dict([
        "\\x00\\x01\\x00\\x00\\x00", "true", "OTTO", "ttcf", "glyf", "loca",
        "head", "hhea", "hmtx", "maxp", "name", "post", "CFF ", "CFF2",
        "cmap", "fvar", "gvar", "avar", "GSUB", "GPOS", "GDEF", "kern",
        "morx", "mort", "sbix", "CBDT", "CBLC", "COLR", "CPAL", "SVG ",
        "DSIG", "VORG", "FEAT", "lcar", "fdsc", "Zapf", "sfnt",
    ]),
}


def harvest_seeds(key: str, cap: int = 60, max_bytes: int = 262144) -> list[bytes]:
    out: list[bytes] = []
    for pat in SEED_GLOBS.get(key, []):
        for p in sorted(glob.glob(pat, recursive=True)):
            try:
                if not os.path.isfile(p) or os.path.getsize(p) == 0:
                    continue
                sz = os.path.getsize(p)
                with open(p, "rb") as fh:
                    data = fh.read(min(sz, max_bytes))
                if len(data) >= 16:
                    out.append(data)
            except OSError:
                continue
            if len(out) >= cap:
                return out
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True,
                    choices=["imageio", "audiotoolbox", "coregraphics",
                             "coretext"])
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--duration", type=int, default=600,
                    help="wall-clock seconds per libFuzzer round")
    ap.add_argument("--workers", type=int, default=7)
    ap.add_argument("--runs", type=int, default=2_000_000_000,
                    help="libFuzzer -runs cap; effectively unbounded so "
                         "--duration governs")
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--value-profile", action="store_true")
    ap.add_argument("--extra-dict", default=None,
                    help="path to an additional dictionary (e.g. a "
                         "staticscan evidence dictionary); merged with "
                         "the built-in per-target dictionary")
    ap.add_argument("--summary", default=None)
    args = ap.parse_args()

    ws = Workspace(REPO / ".ios-research")
    store = CrashStore(ws)
    tgt = MacFuzzTarget(args.target)
    harness = tgt.resolve_harness()
    if harness is None or not tgt.is_libfuzzer():
        print(json.dumps({"ok": False, "error":
                          f"harness for mac:{args.target} missing/not libFuzzer"}))
        return 3

    corpus_dir = BASE / f"lf-corpus-{args.target}"
    art_dir = BASE / f"lf-artifacts-{args.target}"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    art_dir.mkdir(parents=True, exist_ok=True)

    dict_path = BASE / f"dict-{args.target}.dict"
    lines = list(DICTIONARIES[args.target].splitlines())
    if args.extra_dict:
        extra = Path(args.extra_dict).read_text(encoding="utf-8")
        for ln in extra.splitlines():
            if ln.strip() and ln.strip() not in lines:
                lines.append(ln.strip())
    dict_path.write_text("\n".join(lines) + "\n")
    print(f"[{tgt.target_id}] dictionary: {len(lines)} tokens "
          f"({'+' + str(len(lines) - len(DICTIONARIES[args.target].splitlines()))}"
          f" from {args.extra_dict})" if args.extra_dict else
          f"[{tgt.target_id}] dictionary: {len(lines)} tokens",
          file=sys.stderr)

    seeds = harvest_seeds(args.target)
    print(f"[{tgt.target_id}] harvested {len(seeds)} real-format seeds "
          f"(sizes {[len(s) for s in seeds[:8]]})", file=sys.stderr)

    max_len = {"coregraphics": 131072, "audiotoolbox": 65536,
               "imageio": 65536, "coretext": 262144}[args.target]

    totals = {"target": tgt.target_id, "experiment": args.experiment,
              "seeds_harvested": len(seeds), "crash_records": [],
              "rounds": []}
    for rnd in range(1, args.rounds + 1):
        unique, stats = tgt.fuzz_corpus(
            seeds, runs=args.runs, max_total_time=float(args.duration),
            workers=args.workers, artifact_dir=str(art_dir),
            value_profile=args.value_profile, dictionary=str(dict_path),
            max_len=max_len, corpus_dir=str(corpus_dir))
        stats["round"] = rnd
        totals["rounds"].append(stats)

        for data, res in unique:
            rec = store.record(experiment_id=args.experiment,
                               target=tgt.target_id,
                               fmt=(tgt.formats[0] if tgt.formats else "raw"),
                               data=data, exec_result=res,
                               lineage={"source": "libfuzzer-inprocess",
                                        "round": rnd})
            totals["crash_records"].append(
                {"crash_id": rec.id, "signature": rec.signature,
                 "classification": rec.classification,
                 "detail": res.detail[:300]})
        print(f"[{tgt.target_id}] round {rnd}: runs={stats.get('runs')} "
              f"elapsed={stats.get('elapsed_s')}s artifacts={stats.get('artifacts')} "
              f"unique={len(unique)} hangs={stats.get('unique_timeouts', 0)} "
              f"recorded={len(totals['crash_records'])}",
              file=sys.stderr)

    totals["timeouts_confirmed"] = sum(
        s.get("unique_timeouts", 0) for s in totals["rounds"])

    summary_path = args.summary or str(BASE / f"results-{args.target}.json")
    Path(summary_path).parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as fh:
        json.dump(totals, fh, indent=1)
    print(json.dumps({"ok": True, "target": totals["target"],
                      "crashes_recorded": len(totals["crash_records"]),
                      "timeouts_confirmed": totals["timeouts_confirmed"],
                      "corpus_size": len(list(corpus_dir.glob("*"))),
                      "artifacts": len(list(art_dir.glob('*'))),
                      "summary": summary_path}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
