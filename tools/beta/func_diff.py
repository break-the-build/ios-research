#!/usr/bin/env python3
"""Function- and string-level diff of two lane baselines (tools/beta/lane_baseline.sh).

lane_diff.py says *how many* functions of each image changed size; this says
*which* functions changed, including same-size, in-place edits that a symbol
or size diff misses, and which strings were added. A security fix typically
shows up as both: a new compare-and-branch in a parser and, often, a new error
or log string next to it.

Per image (the dylib each baseline extracted, with its starts.txt / exports.txt):

* every function's instructions are normalized -- PC-relative fields masked
  (branches, ADR/ADRP, literal loads, and the page offset that follows an
  ADRP) so that code which merely moved compares equal -- and hashed;
* the two builds' functions are aligned in address order (the shared cache
  keeps link order between point releases), so even stripped images such as
  RawCamera get matched; unmatched runs are changed, added or removed code;
* C strings (__cstring, __oslogstring) are compared as sets.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/beta/func_diff.py <old-baseline> <new-baseline> \\
        [--image CoreGraphics ...] [--json diff.json] > func-diff.md
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import pathlib
import re
import struct
import sys
from dataclasses import dataclass

_MH_MAGIC_64 = 0xFEEDFACF
_LC_SEGMENT_64 = 0x19
_STRING_SECTIONS = ("__cstring", "__oslogstring")
_MIN_STRING = 4
SHOW_FUNCS = 60
SHOW_STRINGS = 40
_SYMBOL = re.compile(r"^(0x[0-9a-fA-F]+):\s+\(([^)]*)\)\s+(\S+)")
_LOCAL_SUFFIX = re.compile(r"\.\d+$")       # compiler-numbered local symbols: foo.123
# Source paths baked into assertions: they name the build directory, so every
# one of them changes in every build.
_BUILD_PATH = re.compile(r"/AppleInternal/|/BuildRoots/|com\.apple\.xbs")


@dataclass(frozen=True)
class Section:
    segname: str
    sectname: str
    addr: int
    size: int
    offset: int


@dataclass(frozen=True)
class Function:
    addr: int
    size: int
    name: str      # "" when the image has no symbol at this address
    code: bytes    # normalized instructions

    @property
    def digest(self) -> str:
        return hashlib.sha1(self.code).hexdigest()[:16]


def parse_sections(data: bytes) -> list[Section]:
    """The sections of a 64-bit Mach-O image."""
    if len(data) < 32 or struct.unpack_from("<I", data)[0] != _MH_MAGIC_64:
        raise ValueError("not a 64-bit little-endian Mach-O image")
    ncmds = struct.unpack_from("<I", data, 16)[0]
    pos, out = 32, []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, pos)
        if cmd == _LC_SEGMENT_64:
            nsects = struct.unpack_from("<I", data, pos + 64)[0]
            sp = pos + 72
            for _s in range(nsects):
                sect, seg = (data[sp:sp + 16].rstrip(b"\0").decode("latin-1"),
                             data[sp + 16:sp + 32].rstrip(b"\0").decode("latin-1"))
                addr, size, offset = struct.unpack_from("<QQI", data, sp + 32)
                out.append(Section(seg, sect, addr, size, offset))
                sp += 80
        if cmdsize <= 0:
            break
        pos += cmdsize
    return out


_ADRP_REACH = 16      # instructions an ADRP's page register is assumed to stay live


def normalize(code: bytes) -> bytes:
    """AArch64 instructions with their PC-relative fields masked.

    Masked: B/BL imm26; B.cond, CBZ/CBNZ and LDR-literal imm19; TBZ/TBNZ imm14;
    ADR/ADRP immediates; and the imm12 of an ADD or LDR/STR whose base is a
    register an ADRP set shortly before (the page offset of the same address).
    Everything else -- registers, immediates, compares, conditions -- is kept,
    so a new bounds check or a changed constant still shows.
    """
    words = list(struct.unpack_from(f"<{len(code) // 4}I", code))
    pages: dict[int, int] = {}                                # register -> ADRP index
    for i, w in enumerate(words):
        base = (w >> 5) & 0x1F
        if (w & 0x7C000000) == 0x14000000:                    # B, BL
            words[i] = w & 0xFC000000
        elif (w & 0xFF000010) == 0x54000000:                  # B.cond
            words[i] = w & 0xFF00001F
        elif (w & 0x7E000000) in (0x34000000, 0x36000000):    # CBZ/CBNZ, TBZ/TBNZ
            words[i] = w & (0xFF00001F if (w & 0x02000000) == 0 else 0xFFF8001F)
        elif (w & 0x1F000000) == 0x10000000:                  # ADR, ADRP
            words[i] = w & 0x9F00001F
            if w & 0x80000000:
                pages[w & 0x1F] = i
        elif (w & 0x3B000000) == 0x18000000:                  # LDR (literal)
            words[i] = w & 0xFF00001F
        elif i - pages.get(base, -_ADRP_REACH - 1) <= _ADRP_REACH and (
                (w & 0x7F800000) == 0x11000000                # ADD (immediate)
                or (w & 0x3B000000) == 0x39000000):           # LDR/STR (unsigned imm)
            words[i] = w & 0xFFC003FF
    return struct.pack(f"<{len(words)}I", *words)


def _is_check(w: int) -> bool:
    """A compare (CMP/CMN/TST/CCMP) or a conditional branch."""
    rd31 = (w & 0x1F) == 0x1F
    return ((w & 0xFF000010) == 0x54000000                     # B.cond
            or (w & 0x7C000000) == 0x34000000                  # CBZ/CBNZ, TBZ/TBNZ
            or (w & 0x3FE00000) == 0x3A400000                  # CCMP/CCMN
            or (rd31 and ((w & 0x3F800000) == 0x31000000       # ADDS/SUBS imm
                          or (w & 0x3F200000) == 0x2B000000    # ADDS/SUBS shifted reg
                          or (w & 0x3FE00000) == 0x2B200000    # ADDS/SUBS extended reg
                          or (w & 0x7F800000) == 0x72000000    # ANDS imm (TST)
                          or (w & 0x7F200000) == 0x6A000000)))  # ANDS shifted (TST)


def profile(code: bytes) -> dict[str, int]:
    """Counts that make a fix visible: checks, traps (BRK) and calls (BL)."""
    words = struct.unpack_from(f"<{len(code) // 4}I", code)
    return {"checks": sum(_is_check(w) for w in words),
            "traps": sum((w & 0xFFE0001F) == 0xD4200000 for w in words),
            "calls": sum((w & 0xFC000000) == 0x94000000 for w in words)}


def operands_only(a: bytes, b: bytes) -> bool:
    """Same instructions, differing only in operands (offsets, constants,
    registers): typically a struct layout change, not new logic."""
    return len(a) == len(b) and all(a[i + 3] == b[i + 3] for i in range(0, len(a), 4))


def _names(image_dir: pathlib.Path) -> dict[int, str]:
    path = image_dir / "exports.txt"
    names: dict[int, str] = {}
    if not path.exists():
        return names
    for line in path.read_text(errors="replace").splitlines():
        m = _SYMBOL.match(line)
        if m and int(m.group(1), 16) and "undefined" not in m.group(2):
            names.setdefault(int(m.group(1), 16), m.group(3))
    return names


def _dylib(image_dir: pathlib.Path) -> pathlib.Path:
    files = [p for p in image_dir.iterdir()
             if p.is_file() and p.suffix not in (".txt", ".json")]
    if len(files) != 1:
        raise SystemExit(f"{image_dir}: expected one extracted image, found {len(files)}")
    return files[0]


def load_image(image_dir: pathlib.Path) -> tuple[list[Function], set[str]]:
    """Functions (in address order) and C strings of one baseline image."""
    data = _dylib(image_dir).read_bytes()
    sections = parse_sections(data)
    text = next(s for s in sections if (s.segname, s.sectname) == ("__TEXT", "__text"))
    starts = sorted({int(t, 16) for t in (image_dir / "starts.txt").read_text().split()
                     if t.startswith("0x")})
    starts = [a for a in starts if text.addr <= a < text.addr + text.size]
    names = _names(image_dir)
    funcs = []
    for a, b in zip(starts, starts[1:] + [text.addr + text.size]):
        off = text.offset + (a - text.addr)
        code = data[off:off + ((b - a) & ~3)]
        funcs.append(Function(a, b - a, names.get(a, ""), normalize(code)))
    strings: set[str] = set()
    for s in sections:
        if s.sectname in _STRING_SECTIONS:
            blob = data[s.offset:s.offset + s.size]
            strings |= {s for s in (t.decode("utf-8", "replace") for t in blob.split(b"\0")
                                    if len(t) >= _MIN_STRING)
                        if not _BUILD_PATH.search(s)}
    return funcs, strings


def _label(f: Function) -> str:
    return _LOCAL_SUFFIX.sub("", f.name) if f.name else f"sub_{f.addr:x}"


def _change(o: Function, n: Function) -> dict:
    po, pn = profile(o.code), profile(n.code)
    return {"name": _label(n) if n.name else _label(o),
            "old_addr": hex(o.addr), "new_addr": hex(n.addr),
            "old_size": o.size, "new_size": n.size,
            "operands_only": operands_only(o.code, n.code),
            **{f"{k}_delta": pn[k] - po[k] for k in po}}


def _rank(c: dict) -> tuple:
    """Code changes first; among them, most new checks, traps, then growth."""
    return (c["operands_only"], -c["checks_delta"], -c["traps_delta"],
            -abs(c["new_size"] - c["old_size"]))


def diff_functions(old: list[Function], new: list[Function]) -> dict:
    """Align by normalized digest in address order; report what did not match."""
    sm = difflib.SequenceMatcher(None, [f.digest for f in old], [f.digest for f in new],
                                 autojunk=False)
    changed, added, removed = [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        pairs = min(i2 - i1, j2 - j1) if tag == "replace" else 0
        changed += [_change(old[i1 + k], new[j1 + k]) for k in range(pairs)]
        removed += [{"name": _label(f), "old_addr": hex(f.addr), "old_size": f.size}
                    for f in old[i1 + pairs:i2]]
        added += [{"name": _label(f), "new_addr": hex(f.addr), "new_size": f.size,
                   **profile(f.code)}
                  for f in new[j1 + pairs:j2]]
    return {"functions": [len(old), len(new)], "changed": sorted(changed, key=_rank),
            "added": added, "removed": removed}


def diff_image(old_dir: pathlib.Path, new_dir: pathlib.Path) -> dict:
    (fo, so), (fn, sn) = load_image(old_dir), load_image(new_dir)
    out = diff_functions(fo, fn)
    out["strings_added"] = sorted(sn - so)
    out["strings_removed"] = sorted(so - sn)
    return out


def _code_changes(d: dict) -> list[dict]:
    return [c for c in d["changed"] if not c["operands_only"]]


def _image_section(name: str, d: dict) -> list[str]:
    code = _code_changes(d)
    out = ["", f"## {name}", "",
           (f"functions {d['functions'][0]} → {d['functions'][1]}; "
            f"{len(code)} code changes, {len(d['changed']) - len(code)} operand-only "
            f"(offsets/constants: usually a struct layout change), "
            f"{len(d['added'])} added, {len(d['removed'])} removed")]
    if d["strings_added"]:
        out += ["", "Strings added:", ""]
        out += [f"- `{s[:160]}`" for s in d["strings_added"][:SHOW_STRINGS]]
        if len(d["strings_added"]) > SHOW_STRINGS:
            out.append(f"- (+{len(d['strings_added']) - SHOW_STRINGS} more)")
    rows = ([("changed", c["name"], c["new_addr"], f"{c['old_size']} → {c['new_size']}",
              f"{c['checks_delta']:+d}", f"{c['traps_delta']:+d}", f"{c['calls_delta']:+d}")
             for c in code]
            + [("added", a["name"], a["new_addr"], str(a["new_size"]),
                str(a["checks"]), str(a["traps"]), str(a["calls"])) for a in d["added"]]
            + [("removed", r["name"], r["old_addr"], str(r["old_size"]), "", "", "")
               for r in d["removed"]])
    if rows:
        out += ["", "| | Function | Address | Size | Checks | Traps | Calls |",
                "|---|---|---|---|---|---|---|"]
        out += ["| " + " | ".join((k, f"`{n}`", *rest)) + " |"
                for k, n, *rest in rows[:SHOW_FUNCS]]
        if len(rows) > SHOW_FUNCS:
            out.append(f"| | (+{len(rows) - SHOW_FUNCS} more in the JSON) | | | | | |")
    return out


def markdown(old: str, new: str, images: dict[str, dict]) -> str:
    out = [f"# Function diff: {old} → {new}", "",
           ("Code changes are ranked by added checks (compares and conditional "
            "branches), then traps, then growth: a bounds fix adds checks."), "",
           "| Image | Code changes | +checks | Operand-only | Added | Removed | Strings added |",
           "|---|---|---|---|---|---|---|"]
    order = sorted(images, key=lambda k: -(len(_code_changes(images[k]))
                                           + len(images[k]["strings_added"])))
    for name in order:
        d = images[name]
        code = _code_changes(d)
        out.append(f"| {name} | {len(code)} | "
                   f"{sum(max(c['checks_delta'], 0) for c in code)} | "
                   f"{len(d['changed']) - len(code)} | {len(d['added'])} | "
                   f"{len(d['removed'])} | {len(d['strings_added'])} |")
    for name in order:
        d = images[name]
        if d["changed"] or d["added"] or d["removed"] or d["strings_added"]:
            out += _image_section(name, d)
    return "\n".join(out) + "\n"


def _build_dir(path: pathlib.Path) -> pathlib.Path:
    if (path / "manifest.json").exists():
        return path
    subs = [p for p in path.iterdir() if (p / "manifest.json").exists()]
    if len(subs) != 1:
        raise SystemExit(f"{path}: expected exactly one recorded build, found {len(subs)}")
    return subs[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", type=pathlib.Path)
    ap.add_argument("new", type=pathlib.Path)
    ap.add_argument("--image", action="append", default=[],
                    help="only this image (repeatable); default: every image in both")
    ap.add_argument("--json", type=pathlib.Path, default=None, help="also write JSON here")
    args = ap.parse_args(argv)
    old, new = _build_dir(args.old), _build_dir(args.new)
    names = args.image or sorted(p.name for p in old.iterdir()
                                 if p.is_dir() and (new / p.name).is_dir())
    images = {n: diff_image(old / n, new / n) for n in names}
    if args.json:
        args.json.write_text(json.dumps({"old": old.name, "new": new.name, "images": images},
                                        indent=2))
    sys.stdout.write(markdown(old.name, new.name, images))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
