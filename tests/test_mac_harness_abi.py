"""ABI lint for tools/harness/mac_fuzz_harness.c (no toolchain needed; runs in CI).

The harness reaches Apple frameworks through dlsym'd function pointers whose
prototypes are hand-written, so the compiler cannot check them against the
SDK. Every bug below shipped once and failed SILENTLY -- the deep stage simply
never ran, and campaigns reported clean results:

* CGContextDrawImage took its CGRect as a pointer -> 0 pixels ever decoded.
* CTFramesetterCreateFrame took its CFRange as a pointer -> frame never laid out.
* AudioFileReadPacketData took ioNumPackets by value -> buffer size used as an
  address; the format property was 'asbd' (not a property) instead of 'dfmt';
  CoreAudio structs were 4-packed while the SDK uses natural alignment.
* CMVideoFormatDescriptionCreateFrom*ParameterSets counts were uint32_t, not
  size_t (upper register half unspecified on arm64).
* bool/Boolean results were read as int: only the low byte of w0 is defined.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = (REPO / "tools" / "harness" / "mac_fuzz_harness.c").read_text()

_PROTO_RE = re.compile(
    r"static\s+[^;{}]*?\(\s*\*\s*p_(?P<name>\w+)\s*\)\s*\((?P<args>[^;]*?)\)\s*=\s*NULL\s*;", re.DOTALL)


def _strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _prototypes() -> dict[str, list[list[str]]]:
    """name -> list of argument-type lists (a name may be declared per target)."""
    out: dict[str, list[list[str]]] = {}
    for m in _PROTO_RE.finditer(_strip_comments(SRC)):
        args = [" ".join(a.split()) for a in m.group("args").split(",")]
        out.setdefault(m.group("name"), []).append(args)
    return out


PROTOS = _prototypes()

# (function, argument index, required type) straight from the SDK headers.
REQUIRED_ARG_TYPES = [
    ("CGContextDrawImage", 1, "IOSR_CGRect"),                 # CGRect rect (by value)
    ("CTFramesetterCreateFrame", 1, "IOSR_CFRange"),          # CFRange stringRange (by value)
    ("CGPathAddRect", 2, "IOSR_CGRect"),                      # CGRect rect (by value)
    ("AudioFileReadPacketData", 2, "UInt32 *"),               # UInt32 *ioNumBytes
    ("AudioFileReadPacketData", 5, "UInt32 *"),               # UInt32 *ioNumPackets
    ("CMVideoFormatDescriptionCreateFromH264ParameterSets", 1, "size_t"),
    ("CMVideoFormatDescriptionCreateFromHEVCParameterSets", 1, "size_t"),
    ("CTFontCreateWithFontDescriptor", 1, "double"),          # CGFloat size (in d0)
    ("CGContextSetTextPosition", 1, "double"),                # CGFloat x (by value)
    ("CGContextSetTextPosition", 2, "double"),                # CGFloat y (by value)
    ("CTFontDescriptorCreateCopyWithVariation", 2, "double"), # CGFloat variationValue
    ("CTFontDrawGlyphs", 2, "const IOSR_CGPoint *"),          # const CGPoint positions[]
    ("CTFontDrawGlyphs", 3, "size_t"),                        # size_t count
    ("CFNumberGetValue", 1, "CFIndex"),                       # CFNumberType is a CFIndex
]
ARG_COUNTS = {
    "CGContextDrawImage": 3, "CTFramesetterCreateFrame": 4, "CGPathAddRect": 3,
    "AudioFileReadPacketData": 7, "AudioConverterFillComplexBuffer": 6,
    "AudioConverterSetProperty": 4, "CTFontDrawGlyphs": 5, "CTLineDraw": 2,
    "CGContextSetTextPosition": 3, "CTFontDescriptorCreateCopyWithVariation": 3,
    "CFNumberGetValue": 3, "CFDataCreateWithBytesNoCopy": 4, "AudioFileStreamOpen": 5,
    "AudioFileStreamParseBytes": 4, "AudioFileStreamClose": 1,
    "CGContextSetShouldAntialias": 2, "CGContextSetShouldSmoothFonts": 2,
}
# SDK parameters that are C ARRAYS of a small struct, where a pointer is right.
ARRAY_PARAMS = {("CTFontDrawGlyphs", 2)}                      # const CGPoint positions[]
# Functions the SDK declares as returning bool / Boolean (one byte).
BOOL_RETURNS = ["CTFontGetGlyphsForCharacters", "CGPDFScannerScan",
                "CGPDFScannerPopNumber", "CGPDFScannerPopName", "CFNumberGetValue"]
_RETURN_RE = re.compile(r"static\s+(?P<ret>[^;{}()=]*?)\(\s*\*\s*p_(?P<name>\w+)\s*\)\s*\(")


def test_lint_finds_the_prototypes():
    assert len(PROTOS) > 40
    for name in ("CGContextDrawImage", "CTFramesetterCreateFrame", "AudioFileReadPacketData"):
        assert name in PROTOS, name


@pytest.mark.parametrize("name,index,required", REQUIRED_ARG_TYPES)
def test_struct_and_pointer_parameters_match_the_sdk(name, index, required):
    for args in PROTOS[name]:
        assert args[index] == required, f"{name} arg {index}: {args[index]!r} != {required!r}"


@pytest.mark.parametrize("name,count", sorted(ARG_COUNTS.items()))
def test_argument_counts_match_the_sdk(name, count):
    for args in PROTOS[name]:
        assert len(args) == count, f"{name}: {len(args)} args, SDK has {count}"


def test_no_by_value_struct_is_ever_declared_as_a_pointer():
    """Apple passes CGRect/CFRange/CGSize/CGPoint by value in every API used here,
    except where the SDK parameter is an array of them (ARRAY_PARAMS)."""
    for name, decls in PROTOS.items():
        for args in decls:
            for i, a in enumerate(args):
                if (name, i) in ARRAY_PARAMS:
                    continue
                assert not re.search(r"IOSR_(CGRect|CFRange|CGSize|CGPoint)\s*\*", a), (name, a)


@pytest.mark.parametrize("name", BOOL_RETURNS)
def test_bool_results_are_read_as_one_byte(name):
    """A bool/Boolean result defines only the low byte of w0; reading it as int
    can turn false into true."""
    rets = [m.group("ret").strip() for m in _RETURN_RE.finditer(_strip_comments(SRC))
            if m.group("name") == name]
    assert rets, f"{name} not declared"
    assert all(r == "unsigned char" for r in rets), (name, rets)


def _fourcc(code: str) -> int:
    return int.from_bytes(code.encode("ascii"), "big")


# Property IDs exactly as in AudioFile.h / AudioConverter.h.
SDK_PROPERTY_IDS = {
    "IOSR_AT_PROP_FORMAT": "dfmt",     # kAudioFilePropertyDataFormat
    "IOSR_AT_PROP_COOKIE": "mgic",     # kAudioFilePropertyMagicCookieData
    "IOSR_AC_PROP_COOKIE": "dmgc",     # kAudioConverterDecompressionMagicCookie
}


@pytest.mark.parametrize("macro,code", sorted(SDK_PROPERTY_IDS.items()))
def test_audio_property_ids_match_the_sdk(macro, code):
    m = re.search(rf"#define {macro} (0x[0-9a-fA-F]+)UL\s*/\* '(\w{{4}})'", SRC)
    assert m, f"{macro} not defined"
    value, comment = int(m.group(1), 16), m.group(2)
    assert value == _fourcc(code), f"{macro} = {value:#x}, SDK '{code}' = {_fourcc(code):#x}"
    assert comment == code


def test_fourcc_comments_agree_with_their_values():
    """A '#define X 0x... /* 'abcd'' must encode exactly 'abcd'."""
    for m in re.finditer(r"#define (\w+) (0x[0-9a-fA-F]{8})UL\s*/\* '(\w{4})'", SRC):
        assert int(m.group(2), 16) == _fourcc(m.group(3)), m.group(1)


def test_coreaudio_types_are_not_packed():
    """CoreAudioBaseTypes.h uses natural alignment; packing moved mBuffers."""
    assert "#pragma pack" not in _strip_comments(SRC)


def test_imageio_decodes_into_an_inspectable_buffer():
    """The pixel-count depth metric needs our own bitmap, not a NULL-backed context."""
    body = SRC.split("#if defined(HARNESS_TARGET_IMAGEIO)", 1)[1].split("#elif", 1)[0]
    assert "p_CGBitmapContextCreate(\n                    pixels," in body
    assert 'g_depth_name = "pixels"' in body


def test_coretext_rasterizes_into_an_inspectable_buffer():
    """Outlines alone never reach bitmap/color glyphs: glyphs must be DRAWN into
    our own canvas, and the metric must count the ink."""
    body = SRC.split("#elif defined(HARNESS_TARGET_CORETEXT)", 1)[1].split("#else", 1)[0]
    assert "p_CGBitmapContextCreate(c->px," in body
    assert "p_CTFontDrawGlyphs(font, glyphs, pos, n, ctx)" in body
    assert "p_CTLineDraw(line, canvas)" in body
    assert 'g_depth_name = "pixels"' in body
    assert "p_CFRelease(descs)" in body          # the +1 descriptor array is released


def test_imageio_repairs_png_crcs_before_decoding():
    body = SRC.split("#if defined(HARNESS_TARGET_IMAGEIO)", 1)[1].split("#elif", 1)[0]
    assert "png_repaired_copy(data, size)" in body
    assert 'getenv("IOSR_PNG_CRC_FIXUP")' in body and 'getenv("IOSR_SAVE_INPUT")' in body
