#!/usr/bin/env python3
"""Font variant generator for lane 5 (CoreText / FontParser).

Two structured mutators over real sfnt fonts (TrueType/OpenType; the first
font of a collection), both keeping the file well-formed enough that the
parser goes past the table directory:

* **table**: change bytes inside one table only (boundary values in aligned
  2- and 4-byte fields, bit flips, truncation by 1-8 bytes), then fix that
  table's directory length and checksum.
* **hint**: disassemble the TrueType bytecode in ``fpgm``, ``prep`` and the
  glyph programs, edit whole instructions (insert, delete, duplicate,
  replace, boundary push values including the font's own ``maxp`` limits and
  the glyph's point count ±1), and reassemble, rebuilding ``glyf``/``loca``
  when a glyph program changes length. The interpreter then runs past the
  first edited instruction instead of rejecting the bytecode. (Anchor:
  CVE-2023-41990, a TrueType instruction in FontParser, exploited in the
  wild.)

The CoreText harness draws glyph IDs 0-31 plus 32 more spread across the
font, so glyph programs are picked from those IDs first.

Authorized / own-machine research only (SECURITY.md).

Usage:
    python tools/gen/fonts.py FONT ... --out DIR [--table 40] [--hint 300] [--seed 1]
"""

from __future__ import annotations

import argparse
import pathlib
import random
import struct
import sys

# ---------------------------------------------------------------- sfnt I/O

HEAD_ADJUST_OFFSET = 8


def checksum(data: bytes) -> int:
    padded = data + b"\0" * (-len(data) % 4)
    return sum(struct.unpack(f">{len(padded) // 4}I", padded)) & 0xFFFFFFFF


def parse_sfnt(data: bytes) -> tuple[bytes, list[str], dict[str, bytes]]:
    """(sfnt version, table order, tables) of a font or a collection's first font."""
    base = 0
    if data[:4] == b"ttcf":
        base = struct.unpack_from(">I", data, 12)[0]
    version = data[base:base + 4]
    (num,) = struct.unpack_from(">H", data, base + 4)
    order, tables = [], {}
    for i in range(num):
        tag, _cs, off, length = struct.unpack_from(">4sIII", data, base + 12 + 16 * i)
        name = tag.decode("latin-1")
        order.append(name)
        tables[name] = data[off:off + length]
    return version, order, tables


def build_sfnt(version: bytes, order: list[str], tables: dict[str, bytes]) -> bytes:
    """Serialize with a fresh directory: offsets, lengths, checksums, head adjust."""
    num = len(order)
    entry_sel = max(num.bit_length() - 1, 0)
    search = (1 << entry_sel) * 16
    header = version + struct.pack(">HHHH", num, search, entry_sel, num * 16 - search)
    offset = 12 + 16 * num
    directory, body = b"", b""
    for tag in order:
        data = tables[tag]
        if tag == "head" and len(data) >= 12:
            data = data[:HEAD_ADJUST_OFFSET] + b"\0\0\0\0" + data[12:]
        directory += struct.pack(">4sIII", tag.encode("latin-1"), checksum(data),
                                 offset + len(body), len(data))
        body += data + b"\0" * (-len(data) % 4)
    font = bytearray(header + directory + body)
    if "head" in tables and len(tables["head"]) >= 12:
        at = 12 + 16 * num + sum(len(tables[t]) + (-len(tables[t]) % 4)
                                 for t in order[:order.index("head")])
        struct.pack_into(">I", font, at + HEAD_ADJUST_OFFSET,
                         (0xB1B0AFBA - checksum(bytes(font))) & 0xFFFFFFFF)
    return bytes(font)


# ---------------------------------------------------------------- table mutator

def _boundaries(width: int, orig: int) -> list[int]:
    top = (1 << (8 * width)) - 1
    vals = [0, 1, top, top >> 1, (top >> 1) + 1, orig - 1, orig + 1, orig * 2]
    return [v & top for v in vals if v != orig]


def mutate_table(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return data
    op = rng.choice(("int16", "int32", "flip", "truncate"))
    buf = bytearray(data)
    if op == "truncate":
        return bytes(buf[:max(0, len(buf) - rng.randint(1, 8))])
    if op == "flip":
        i = rng.randrange(len(buf))
        buf[i] ^= 1 << rng.randrange(8)
        return bytes(buf)
    width = 2 if op == "int16" else 4
    if len(buf) < width:
        return bytes(buf)
    at = rng.randrange(len(buf) // width) * width
    fmt = ">H" if width == 2 else ">I"
    (orig,) = struct.unpack_from(fmt, buf, at)
    struct.pack_into(fmt, buf, at, rng.choice(_boundaries(width, orig)))
    return bytes(buf)


# ---------------------------------------------------------------- TrueType bytecode

def disassemble(code: bytes) -> list[bytes]:
    """Split bytecode into instructions (push instructions keep their operands)."""
    out, i = [], 0
    while i < len(code):
        op = code[i]
        if op == 0x40:                                   # NPUSHB n, n bytes
            n = 2 + (code[i + 1] if i + 1 < len(code) else 0)
        elif op == 0x41:                                 # NPUSHW n, n words
            n = 2 + 2 * (code[i + 1] if i + 1 < len(code) else 0)
        elif 0xB0 <= op <= 0xB7:                         # PUSHB[k]: k+1 bytes
            n = 1 + (op - 0xAF)
        elif 0xB8 <= op <= 0xBF:                         # PUSHW[k]: k+1 words
            n = 1 + 2 * (op - 0xB7)
        else:
            n = 1
        out.append(code[i:i + n])
        i += n
    return out


def _is_push(ins: bytes) -> bool:
    return ins[0] in (0x40, 0x41) or 0xB0 <= ins[0] <= 0xBF


# Non-push opcodes (0x00-0x8F minus the two NPUSH forms, plus MDRP/MIRP).
_PLAIN_OPS = [op for op in range(0x90) if op not in (0x40, 0x41)] + list(range(0xC0, 0x100))


def _set_push_value(ins: bytes, value: int, rng: random.Random) -> bytes:
    buf = bytearray(ins)
    op = ins[0]
    words = op == 0x41 or 0xB8 <= op <= 0xBF
    first = 2 if op in (0x40, 0x41) else 1
    width = 2 if words else 1
    count = (len(buf) - first) // width
    if count <= 0:
        return ins
    at = first + rng.randrange(count) * width
    if words:
        struct.pack_into(">H", buf, at, value & 0xFFFF)
    else:
        buf[at] = value & 0xFF
    return bytes(buf)


def mutate_program(code: bytes, rng: random.Random, interesting: list[int]) -> bytes:
    ins = disassemble(code)
    pushes = [i for i, x in enumerate(ins) if _is_push(x)]
    ops = ["insert"] + (["delete", "duplicate", "replace"] if ins else []) + (["push"] if pushes else [])
    op = rng.choice(ops)
    if op == "insert":
        ins.insert(rng.randint(0, len(ins)), bytes([rng.choice(_PLAIN_OPS)]))
    elif op == "delete":
        del ins[rng.randrange(len(ins))]
    elif op == "duplicate":
        i = rng.randrange(len(ins))
        ins.insert(i, ins[i])
    elif op == "replace":
        i = rng.randrange(len(ins))
        ins[i] = bytes([rng.choice(_PLAIN_OPS)])
    else:
        i = rng.choice(pushes)
        ins[i] = _set_push_value(ins[i], rng.choice(interesting), rng)
    return b"".join(ins)


# ---------------------------------------------------------------- glyf / loca

def _maxp_limits(maxp: bytes) -> list[int]:
    if len(maxp) < 32:
        return []
    # maxZones .. maxSizeOfInstructions (offsets 14-26), maxPoints (6)
    return [struct.unpack_from(">H", maxp, off)[0] for off in (6, 14, 16, 18, 20, 22, 24, 26)]


def split_glyphs(tables: dict[str, bytes]) -> list[bytes] | None:
    head, maxp, loca, glyf = (tables.get(t) for t in ("head", "maxp", "loca", "glyf"))
    if not (head and maxp and loca and glyf) or len(head) < 54:
        return None
    (n,) = struct.unpack_from(">H", maxp, 4)
    long_fmt = struct.unpack_from(">h", head, 50)[0] == 1
    if long_fmt:
        offs = list(struct.unpack_from(f">{n + 1}I", loca)) if len(loca) >= 4 * (n + 1) else None
    else:
        offs = ([2 * o for o in struct.unpack_from(f">{n + 1}H", loca)]
                if len(loca) >= 2 * (n + 1) else None)
    if offs is None:
        return None
    return [glyf[a:b] for a, b in zip(offs, offs[1:])]


def join_glyphs(tables: dict[str, bytes], glyphs: list[bytes]) -> dict[str, bytes]:
    """Rebuild glyf and loca (long format when short offsets would overflow)."""
    body, offs = b"", []
    for g in glyphs:
        offs.append(len(body))
        body += g + b"\0" * (-len(g) % 4)
    offs.append(len(body))
    long_fmt = offs[-1] > 0x1FFFE
    loca = (struct.pack(f">{len(offs)}I", *offs) if long_fmt
            else struct.pack(f">{len(offs)}H", *(o // 2 for o in offs)))
    head = bytearray(tables["head"])
    struct.pack_into(">h", head, 50, 1 if long_fmt else 0)
    return {**tables, "glyf": body, "loca": loca, "head": bytes(head)}


def glyph_program(g: bytes) -> tuple[int, int, int] | None:
    """(start of the length field, program length, point count) or None."""
    if len(g) < 10:
        return None
    (contours,) = struct.unpack_from(">h", g, 0)
    if contours >= 0:
        at = 10 + 2 * contours
        if len(g) < at + 2:
            return None
        points = struct.unpack_from(">H", g, at - 2)[0] + 1 if contours else 0
        (length,) = struct.unpack_from(">H", g, at)
        return (at, length, points) if len(g) >= at + 2 + length else None
    at, flags = 10, 0x20
    while flags & 0x20:                                  # MORE_COMPONENTS
        if len(g) < at + 4:
            return None
        (flags,) = struct.unpack_from(">H", g, at)
        at += 4 + (4 if flags & 0x01 else 2)
        at += 2 if flags & 0x08 else 4 if flags & 0x40 else 8 if flags & 0x80 else 0
    if not flags & 0x100 or len(g) < at + 2:             # WE_HAVE_INSTRUCTIONS
        return None
    (length,) = struct.unpack_from(">H", g, at)
    return (at, length, 0) if len(g) >= at + 2 + length else None


def drawn_glyph_ids(count: int) -> list[int]:
    """The IDs the CoreText harness draws: 0-31, then 32 spread across the rest."""
    ids = list(range(min(32, count)))
    if count > 64:
        ids += [32 + k * (count - 32) // 32 for k in range(32)]
    else:
        ids += list(range(32, count))
    return ids


def mutate_hinting(tables: dict[str, bytes], rng: random.Random) -> tuple[str, dict[str, bytes]] | None:
    limits = _maxp_limits(tables.get("maxp", b""))
    base = [0, 1, 0xFFFF, 0x7FFF, 0x8000] + [v + d for v in limits for d in (-1, 0, 1)]
    glyphs = split_glyphs(tables)
    candidates = [t for t in ("fpgm", "prep") if tables.get(t)]
    hinted = []
    if glyphs:
        hinted = [i for i in drawn_glyph_ids(len(glyphs))
                  if i < len(glyphs) and (p := glyph_program(glyphs[i])) and p[1] > 0]
    if hinted:
        candidates.append("glyf")
    if not candidates:
        return None
    which = rng.choice(candidates)
    if which != "glyf":
        return which, {**tables, which: mutate_program(tables[which], rng, base)}
    gid = rng.choice(hinted)
    g = glyphs[gid]
    at, length, points = glyph_program(g)
    code = mutate_program(g[at + 2:at + 2 + length], rng, base + [points - 1, points, points + 1])
    new = list(glyphs)
    new[gid] = g[:at] + struct.pack(">H", len(code) & 0xFFFF) + code + g[at + 2 + length:]
    return f"glyph{gid}", join_glyphs(tables, new)


# ---------------------------------------------------------------- driver

def variants(font: bytes, rng: random.Random, n_table: int, n_hint: int):
    """Yield (name, bytes) variants of one font."""
    version, order, tables = parse_sfnt(font)
    for tag in order:
        safe = "".join(c if c.isalnum() else "_" for c in tag.strip())   # OS/2 -> OS_2
        for k in range(n_table):
            yield f"tbl-{safe}-{k}", build_sfnt(
                version, order, {**tables, tag: mutate_table(tables[tag], rng)})
    for k in range(n_hint):
        res = mutate_hinting(tables, rng)
        if res is None:
            return
        where, new = res
        yield f"hint-{where}-{k}", build_sfnt(version, order, new)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fonts", nargs="+", type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--table", type=int, default=40, help="variants per table (default 40)")
    ap.add_argument("--hint", type=int, default=300, help="hinting variants per font (default 300)")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    total = 0
    for path in args.fonts:
        rng = random.Random(f"{args.seed}:{path.name}")
        try:
            items = list(variants(path.read_bytes(), rng, args.table, args.hint))
        except (struct.error, IndexError, ValueError) as exc:
            print(f"skip {path}: not a parseable sfnt ({exc})", file=sys.stderr)
            continue
        for name, data in items:
            (args.out / f"{path.stem}-{name}.ttf").write_bytes(data)
        total += len(items)
        print(f"{path.name}: {len(items)} variants", file=sys.stderr)
    print(f"wrote {total} variants to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
