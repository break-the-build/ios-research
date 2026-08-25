"""Static-analysis scout (#223): binary surface census, parser fingerprinting,
and Ghidra call-graph export.

The scout answers *where to aim*; the dynamic pipeline produces the evidence.
Three capabilities, all offline and deterministic:

1. **Native census** — symbols (nm), linked libraries (otool -L), and
   constant strings (strings) from any loose Mach-O, or directly from a
   dyld shared cache (constant strings are stored contiguously in the
   cache, so fingerprinting works without extraction).
2. **Parser fingerprinting** — match known format constants (magic bytes,
   chunk names, section tags) against the extracted strings to identify
   which parser families a binary contains, with per-token evidence.
   Evidence-backed tokens become libFuzzer dictionaries: the exact magic
   bytes the binary compares, not our guesses.
3. **Ghidra call-graph export** — normalize a Ghidra headless export into
   the call-graph document shape ``directed.load_callgraph()`` consumes,
   and identify *parser focus functions*: functions that reference format
   constants, i.e. the targets a directed campaign should walk toward.

Apple-platform note: system framework paths under /System/Library are
broken symlinks on modern macOS/iOS — the real binaries live inside the
dyld shared cache (cryptex). ``locate_framework`` reports this and
``scan`` accepts a cache file directly for strings-based fingerprinting.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .errors import NotFoundError, ValidationError
from .ids import make_id
from .clock import now_iso

SCAN_SCHEMA_VERSION = 1

#: Known dyld shared cache locations (macOS cryptex era).
DSC_PATHS = (
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/"
    "dyld_shared_cache_arm64e",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/"
    "dyld_shared_cache_arm64",
    "/System/Library/dyld/dyld_shared_cache_arm64e",
    "/System/Library/dyld/dyld_shared_cache_arm64",
)

#: Roots searched for loose framework binaries.
FRAMEWORK_BASES = (
    "/System/Library/Frameworks",
    "/System/Library/PrivateFrameworks",
)

#: Format constants that identify parser families, per campaign target.
#: Tokens are matched as literal byte substrings of the binary's constant
#: strings. Order matters only for display; matching is family-scoped.
FORMAT_SIGNATURES: dict[str, tuple[str, ...]] = {
    "imageio": (
        "PNG", "IHDR", "IDAT", "IEND", "PLTE", "tRNS", "gAMA", "iCCP",
        "GIF87a", "GIF89a", "ftyp", "heic", "mif1", "avif", "Exif",
        "JFIF", "II*", "MM\0*", "acTL", "fcTL",
    ),
    "coregraphics": (
        "%PDF-", "endobj", "endstream", "startxref", "xref", "trailer",
        "FlateDecode", "DCTDecode", "JPXDecode", "CCITTFaxDecode",
        "Type3", "AcroForm", "OpenAction",
    ),
    "audiotoolbox": (
        "ID3", "RIFF", "WAVE", "fmt ", "FORM", "AIFF", "AIFC",
        "COMM", "SSND", "caff", "mp4a", "moov", "stbl", ".mp3", "LAME",
        "esds",
    ),
    "coretext": (
        "\x00\x01\x00\x00", "OTTO", "true", "ttcf", "glyf", "loca",
        "hhea", "hmtx", "maxp", "cmap", "post", "CFF ", "CFF2", "fvar",
        "gvar", "GSUB", "GPOS", "morx", "sbix",
    ),
}


# --- native scan (thin subprocess edges + pure parsers) ----------------------

def _run(cmd: list[str], timeout: float = 120.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(f"scan tool failed: {cmd[0]}: {exc}") from exc
    return (proc.stdout + proc.stderr).decode("utf-8", "replace")


def _run_status(cmd: list[str], timeout: float = 120.0) -> tuple[int, str]:
    """Like ``_run`` but also returns the exit code (for optional tools)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError(f"tool failed: {cmd[0]}: {exc}") from exc
    return proc.returncode, (proc.stdout + proc.stderr).decode(
        "utf-8", "replace")


def parse_nm_symbols(text: str) -> dict[str, dict]:
    """Parse ``nm`` output into ``{name: {address, type}}`` (tolerant)."""
    symbols: dict[str, dict] = {}
    for raw in text.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) == 3 and all(c in "0123456789abcdef" for c in
                                   parts[0].lower()):
            symbols[parts[2].split("(")[0].strip()] = {
                "address": parts[0], "type": parts[1]}
    return symbols


def parse_otool_libraries(text: str) -> list[str]:
    """Parse ``otool -L`` output into linked dylib install names."""
    libs = []
    for raw in text.splitlines()[1:]:
        line = raw.strip()
        if line:
            name = line.split("(", 1)[0].strip()
            if name.endswith(".dylib") or name.startswith("/"):
                libs.append(name)
    return libs


def parse_strings(text: str, min_len: int = 4) -> list[str]:
    """Split ``strings``-style output into candidate constant strings."""
    return [ln for ln in text.splitlines() if len(ln) >= min_len]


def scan_binary(path: str, *, min_len: int = 4) -> dict:
    """Census a loose Mach-O or a dyld shared cache (with its subcaches).

    A dyld shared cache's main file is a stub header; the content lives in
    numbered sibling files (``.01``, ``.02``, ...). All siblings are
    scanned for constant strings (they are stored contiguously), which is
    sufficient for fingerprinting without extraction.
    """
    target = Path(path)
    if not target.is_file():
        raise NotFoundError(f"no such file: {path}")
    is_cache = "dyld_shared_cache" in target.name
    record: dict[str, Any] = {
        "path": str(target.resolve()),
        "size_bytes": target.stat().st_size,
        "is_dyld_shared_cache": is_cache,
    }
    files = [target]
    if is_cache:
        parent = target.parent
        subcaches = sorted(p for p in parent.glob(target.name + ".*")
                           if p.is_file()
                           and not p.name.endswith((".map", ".atlas")))
        files.extend(subcaches)
        record["subcaches"] = [str(p.name) for p in subcaches]
        record["size_bytes"] = sum(f.stat().st_size for f in files)
    strings: list[str] = []
    for f in files:
        strings_text = _run(["strings", "-n", str(min_len), str(f)],
                            timeout=600.0)
        strings.extend(parse_strings(strings_text, min_len))
    record["strings"] = strings
    if is_cache:
        record["symbols"] = {}
        record["libraries"] = []
    else:
        symbols = parse_nm_symbols(_run(["nm", str(target)]))
        record["symbols"] = symbols
        record["libraries"] = parse_otool_libraries(
            _run(["otool", "-L", str(target)]))
    return record


# --- fingerprinting -----------------------------------------------------------

def fingerprint(strings: list[str],
                signatures: dict[str, tuple[str, ...]] | None = None
                ) -> dict[str, list[dict]]:
    """Match format constants against constant strings.

    Returns ``{family: [{token, hits}]}`` for families with at least one
    hit, hits sorted by descending count then token (deterministic).
    """
    sigs = signatures or FORMAT_SIGNATURES
    blob = "\n".join(strings)
    out: dict[str, list[dict]] = {}
    for family, tokens in sigs.items():
        matches = []
        for token in tokens:
            hits = blob.count(token)
            if hits:
                matches.append({"token": token, "hits": hits})
        if matches:
            out[family] = sorted(matches, key=lambda m: (-m["hits"],
                                                         m["token"]))
    return out


def build_dictionary(matches: dict[str, list[dict]],
                     families: set[str] | None = None,
                     max_per_family: int = 48) -> str:
    """Render fingerprint evidence as a libFuzzer dictionary.

    Tokens are escaped C-style; the exact bytes the binary compares, so
    coverage guidance can jump the format gates they guard.
    """
    def esc(token: str) -> str:
        out = []
        for ch in token:
            if ch == "\\":
                out.append("\\\\")
            elif ch == '"':
                out.append('\\"')
            elif 32 <= ord(ch) < 127:
                out.append(ch)
            else:
                out.append("\\x%02x" % ord(ch))
        return "".join(out)

    lines = []
    for family in sorted(matches):
        if families and family not in families:
            continue
        for m in matches[family][:max_per_family]:
            lines.append('"%s"' % esc(m["token"]))
    return "\n".join(lines) + ("\n" if lines else "")


# --- Ghidra export normalization ---------------------------------------------

def parse_ghidra_export(raw: dict) -> dict:
    """Validate + normalize a Ghidra headless export.

    Expected shape (produced by tools/staticscan/ghidra_export.py):
      {"functions": [{"name": str}, ...],
       "edges": [{"from": str, "to": str}, ...],
       "strings": [{"data": str, "references": [function name, ...]}]}
    """
    if not isinstance(raw, dict):
        raise ValidationError("ghidra export must be a JSON object")
    functions = raw.get("functions")
    edges = raw.get("edges")
    strings = raw.get("strings")
    if not isinstance(functions, list) or \
            not all(isinstance(f, dict) and isinstance(f.get("name"), str)
                    for f in functions):
        raise ValidationError("export 'functions' must be a list of "
                              "{name} objects")
    if not isinstance(edges, list) or \
            not all(isinstance(e, dict) and isinstance(e.get("from"), str)
                    and isinstance(e.get("to"), str) for e in edges):
        raise ValidationError("export 'edges' must be a list of "
                              "{from, to} objects")
    if not isinstance(strings, list):
        strings = []
    return {
        "functions": [f["name"] for f in functions],
        "edges": [[e["from"], e["to"]] for e in edges],
        "strings": [s for s in strings
                    if isinstance(s, dict) and isinstance(s.get("data"), str)],
    }


def to_callgraph_doc(normalized: dict) -> dict:
    """Export the directed-compatible call-graph document."""
    nodes = list(normalized["functions"])
    known = set(nodes)
    edges = [[f, t] for f, t in normalized["edges"]
             if f in known and t in known]
    return {"nodes": nodes, "edges": edges}


def parser_focus_functions(normalized: dict,
                           signatures: dict[str, tuple[str, ...]] | None
                           = None) -> list[dict]:
    """Functions that reference format constants: directed-fuzzing targets.

    A function referencing an sfnt tag inside CoreText is, with high
    probability, part of the font-parsing path — walking the call graph
    toward these functions focuses a campaign orders of magnitude faster
    than uniform exploration.
    """
    sigs = signatures or FORMAT_SIGNATURES
    token_to_family: dict[str, str] = {}
    for family, tokens in sigs.items():
        for token in tokens:
            token_to_family.setdefault(token, family)
    focus: dict[str, dict] = {}
    for entry in normalized["strings"]:
        data = entry["data"]
        refs = [r for r in entry.get("references", [])
                if isinstance(r, str)]
        if not refs:
            continue
        for token, family in token_to_family.items():
            if token and token in data:
                for fn in refs:
                    slot = focus.setdefault(fn, {"function": fn,
                                                 "families": set(),
                                                 "tokens": set()})
                    slot["families"].add(family)
                    slot["tokens"].add(token)
    return [{"function": s["function"],
             "families": sorted(s["families"]),
             "tokens": sorted(s["tokens"])}
            for s in sorted(focus.values(), key=lambda s: s["function"])]


# --- fingerprint diffing (#228 beta-window hunting) ----------------------------

def diff_fingerprints(old_matches: dict[str, list[dict]],
                      new_matches: dict[str, list[dict]]) -> dict:
    """Diff two fingerprint results (``{family: [{token, hits}]}``).

    New format tokens in a shipped binary are evidence of newly added or
    newly reachable parsers — the highest-EV directed-campaign targets during
    an OS beta window (+50% bounty bonus). Returns deterministic per-family
    ``added``/``removed`` token sets plus a flat ``directed_targets`` list
    (families with additions, sorted).
    """
    def token_sets(matches: dict[str, list[dict]]
                   ) -> dict[str, set[str]]:
        return {family: {m["token"] for m in entries}
                for family, entries in matches.items()}

    old_tokens = token_sets(old_matches)
    new_tokens = token_sets(new_matches)
    families = sorted(set(old_tokens) | set(new_tokens))
    per_family: dict[str, dict] = {}
    directed_targets: list[dict] = []
    for family in families:
        added = sorted(new_tokens.get(family, set())
                       - old_tokens.get(family, set()))
        removed = sorted(old_tokens.get(family, set())
                         - new_tokens.get(family, set()))
        if added or removed:
            per_family[family] = {"added": added, "removed": removed}
        if added:
            directed_targets.append({"family": family,
                                     "new_tokens": added})
    unchanged = sum(len(new_tokens.get(f, set()) & old_tokens.get(f, set()))
                    for f in families)
    return {
        "families_compared": len(families),
        "changed_families": len(per_family),
        "per_family": per_family,
        "added_token_count": sum(len(v["added"])
                                 for v in per_family.values()),
        "removed_token_count": sum(len(v["removed"])
                                   for v in per_family.values()),
        "unchanged_token_count": unchanged,
        "directed_targets": directed_targets,
    }


# --- framework location --------------------------------------------------------

def locate_framework(name: str) -> dict:
    """Locate a framework binary: loose path or dyld shared cache.

    System framework paths are broken symlinks on cryptex-era macOS/iOS;
    the real code lives in the shared cache, where constant strings are
    directly fingerprintable without extraction.
    """
    if not name or "/" in name or name.startswith("."):
        raise ValidationError("framework name must be a bare name, e.g. "
                              "'AudioToolbox'")
    for base in FRAMEWORK_BASES:
        candidate = (Path(base) / (name + ".framework") / "Versions"
                     / "Current" / name)
        if candidate.exists():
            return {"framework": name, "path": str(candidate),
                    "in_dyld_shared_cache": False, "cache_path": None}
    for cache in DSC_PATHS:
        if Path(cache).exists():
            return {"framework": name, "path": None,
                    "in_dyld_shared_cache": True, "cache_path": cache}
    raise NotFoundError(f"framework '{name}' not found loose or in any "
                        "known dyld shared cache")


# --- workspace record ----------------------------------------------------------

@dataclass
class ScanRecord:
    id: str
    kind: str
    schema_version: int
    created_at: str
    binary: dict
    fingerprint: dict = field(default_factory=dict)
    callgraph: dict | None = None
    focus_functions: list[dict] = field(default_factory=list)
    dictionary: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def make_scan_record(binary: dict, matches: dict,
                     *, callgraph: dict | None = None,
                     focus: list[dict] | None = None,
                     dictionary: str | None = None) -> ScanRecord:
    return ScanRecord(
        id=make_id("staticscan", binary.get("path", ""), len(matches)),
        kind="staticscan",
        schema_version=SCAN_SCHEMA_VERSION,
        created_at=now_iso(),
        binary=binary,
        fingerprint=matches,
        callgraph=callgraph,
        focus_functions=focus or [],
        dictionary=dictionary,
    )


# --- dyld shared cache extraction ------------------------------------------------

def extract_framework(name: str, out_dir: str,
                      ipsw_bin: str = "ipsw") -> dict:
    """Extract a framework's dylib from the dyld shared cache via ipsw.

    Call-graph analysis needs the real Mach-O; strings-based
    fingerprinting does not. Returns the extracted dylib path ready for
    Ghidra headless import.
    """
    if not name or "/" in name or name.startswith("."):
        raise ValidationError("framework name must be a bare name, e.g. "
                              "'CoreText'")
    loc = locate_framework(name)
    if not loc["in_dyld_shared_cache"]:
        return {"framework": name, "path": loc["path"],
                "extracted": False, "note": "loose binary; no extraction "
                "needed"}
    cache = loc["cache_path"]
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    install_names = [
        f"/System/Library/Frameworks/{name}.framework/{name}",
        f"/System/Library/PrivateFrameworks/{name}.framework/{name}",
    ]
    last_err = ""
    for install_name in install_names:
        code, blob = _run_status([ipsw_bin, "dyld", "extract", cache,
                           install_name, "-o", str(out), "--slide"],
                          timeout=1800.0)
        if code == 0:
            produced = sorted(out.glob(f"*{name}*"))
            produced = [p for p in produced if p.is_file()]
            if produced:
                return {"framework": name,
                        "path": str(produced[-1].resolve()),
                        "extracted": True,
                        "install_name": install_name,
                        "cache_path": cache}
            last_err = f"ipsw reported success but no file matched *{name}*"
        else:
            last_err = blob.strip().splitlines()[-1] if blob.strip() \
                else f"exit {code}"
    raise NotFoundError(f"extraction failed for '{name}': {last_err}")
