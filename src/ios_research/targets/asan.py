"""Parse real AddressSanitizer / UBSan / libFuzzer reports into ``Diagnostics``.

The macOS in-process fuzzing target (:mod:`ios_research.targets.mac`) runs a
native ``-fsanitize=fuzzer,address,undefined`` harness over one input. When the
sanitizer catches a defect it prints a textual report to stderr. This module
turns that report into the same normalized :class:`~ios_research.targets.base.Diagnostics`
that the rest of the pipeline (triage, minimize, analyze, differential, report)
already consumes.

Unlike :mod:`ios_research.targets.diagnostics` (which *synthesizes* deterministic
diagnostics for mock targets), this module reads *real* faulting addresses,
registers, stack frames, and modules out of the sanitizer output.

Symbolication and formatting vary by OS build and sanitizer version, so parsing
is deliberately defensive: every field is optional and a report we do not fully
recognize still yields a usable ``Diagnostics`` with a stable signature.
"""

from __future__ import annotations

import hashlib
import re

from .base import Diagnostics

# Map an ASan/UBSan error kind (lower-case, as printed) to the framework's
# stable classification vocabulary (shared with targets/diagnostics.py).
_ERROR_CLASS = {
    "heap-buffer-overflow": "OUT_OF_BOUNDS",       # refined by access type below
    "stack-buffer-overflow": "OUT_OF_BOUNDS",
    "global-buffer-overflow": "OUT_OF_BOUNDS",
    "stack-buffer-underflow": "OUT_OF_BOUNDS",
    "dynamic-stack-buffer-overflow": "OUT_OF_BOUNDS",
    "heap-use-after-free": "USE_AFTER_FREE",
    "use-after-poison": "USE_AFTER_FREE",
    "double-free": "DOUBLE_FREE",
    "attempting-free-on-address": "DOUBLE_FREE",
    "stack-use-after-return": "USE_AFTER_FREE",
    "stack-use-after-scope": "USE_AFTER_FREE",
    "segv": "SEGV",                                # refined to NULL/OOB below
    "null-deref": "NULL_DEREFERENCE",
    "float-cast-overflow": "INTEGER_ERROR",
    "signed-integer-overflow": "INTEGER_ERROR",
    "unsigned-integer-overflow": "INTEGER_ERROR",
    "integer-divide-by-zero": "INTEGER_ERROR",
    "divide-by-zero": "INTEGER_ERROR",
    "shift": "INTEGER_ERROR",
    "allocation-size-too-big": "ALLOCATION_ERROR",
    "requested-allocation-size": "ALLOCATION_ERROR",
    "out-of-memory": "ALLOCATION_ERROR",
    "deadly-signal": "SEGV",
    "abrt": "ASSERTION",
    "unknown": "UNKNOWN",
}

# Exception/signal profile for each classification (mirrors mock diagnostics so
# downstream classifiers see a consistent shape regardless of source).
_CLASS_PROFILE = {
    "NULL_DEREFERENCE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "OUT_OF_BOUNDS_READ": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "OUT_OF_BOUNDS_WRITE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "OUT_OF_BOUNDS": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "USE_AFTER_FREE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "DOUBLE_FREE": ("EXC_BAD_ACCESS", "SIGABRT"),
    "SEGV": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "INTEGER_ERROR": ("EXC_ARITHMETIC", "SIGFPE"),
    "ALLOCATION_ERROR": ("EXC_RESOURCE", "SIGABRT"),
    "ASSERTION": ("EXC_CRASH", "SIGABRT"),
    "UNKNOWN": ("EXC_BAD_ACCESS", "SIGSEGV"),
}

_NULL_PAGE_LIMIT = 0x1000  # addresses below this are treated as null-page derefs

# --- line patterns ---------------------------------------------------------
_ERR_RE = re.compile(
    r"ERROR:\s*(?:AddressSanitizer|libFuzzer|UndefinedBehaviorSanitizer)?:?\s*"
    r"(?P<kind>[A-Za-z0-9_-]+)")
_UBSAN_RE = re.compile(r"runtime error:\s*(?P<msg>.+)")
_ADDR_ON_RE = re.compile(r"on (?:unknown )?address\s*(?P<addr>0x[0-9a-fA-F]+)")
# Broader address match for UBSan wording ("store to address 0x...", "load of
# address 0x...", or a bare "address 0x...").
_ADDR_ANY_RE = re.compile(r"address\s*(?P<addr>0x[0-9a-fA-F]+)")
_PC_RE = re.compile(r"\bpc\s*(?P<pc>0x[0-9a-fA-F]+)")
_ACCESS_RE = re.compile(r"\b(?P<acc>READ|WRITE)\b\s+of\s+size", re.IGNORECASE)
_SIGNAL_ACCESS_RE = re.compile(
    r"caused by a\s+(?P<acc>READ|WRITE)\s+memory access", re.IGNORECASE)
_HINT_ZERO_RE = re.compile(r"address points to the zero page")
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w+Sanitizer:\s*(?P<kind>[A-Za-z0-9_-]+)")
# A backtrace frame:  "    #3 0x... in symbol (Module:arch+0x..)"  or "... file.c:42"
_FRAME_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+(?P<pc>0x[0-9a-fA-F]+)\s+in\s+(?P<rest>.+?)\s*$")
# module reference inside a frame:  "(ImageIO:x86_64+0x2a3b4)"  or "file.dylib+0x1"
_MODULE_PAREN_RE = re.compile(r"\(([^():]+?)(?::[^)+]+)?\+0x[0-9a-fA-F]+\)")


def _norm_addr(value: str) -> str:
    """Normalize a hex address string to fixed 16-digit form."""
    try:
        return f"0x{int(value, 16):016x}"
    except (ValueError, TypeError):
        return ""


def _refine_class(kind: str, access: str, addr_int: int | None) -> str:
    base = _ERROR_CLASS.get(kind, "UNKNOWN")
    if base == "OUT_OF_BOUNDS":
        if access == "write":
            return "OUT_OF_BOUNDS_WRITE"
        if access == "read":
            return "OUT_OF_BOUNDS_READ"
        return "OUT_OF_BOUNDS_READ"
    if base == "SEGV":
        if addr_int is not None and addr_int < _NULL_PAGE_LIMIT:
            return "NULL_DEREFERENCE"
        return "OUT_OF_BOUNDS_WRITE" if access == "write" else "OUT_OF_BOUNDS_READ"
    return base


def _classify_ubsan(msg: str) -> tuple[str, str]:
    """Classify a UBSan ``runtime error:`` message -> (classification, access).

    UBSan can fire before ASan on a bug both detect (e.g. an out-of-bounds
    store is both undefined behavior and a heap overflow); when it does, this
    recovers a specific classification from its wording instead of UNKNOWN.
    """
    m = msg.lower()
    # Null-pointer deref first (so "load of null pointer" is not read as OOB),
    # excluding UBSan's "non-null pointer" pointer-overflow wording.
    if ("null pointer" in m and "non-null" not in m) \
            or "member access within null" in m:
        return "NULL_DEREFERENCE", "read"
    if "store to" in m or ("insufficient space" in m and "store" in m):
        return "OUT_OF_BOUNDS_WRITE", "write"
    if "load of" in m or ("insufficient space" in m and "load" in m):
        return "OUT_OF_BOUNDS_READ", "read"
    if ("overflow" in m or "cannot be represented" in m or "shift" in m
            or "divide by zero" in m or "division by zero" in m):
        return "INTEGER_ERROR", "none"
    if "misaligned address" in m:
        return "OUT_OF_BOUNDS_READ", "read"
    return "UNKNOWN", "none"


def _extract_symbol(rest: str) -> str:
    """Pull a clean symbol name out of the ``in <rest>`` part of a frame."""
    # rest looks like:  "CGImageSourceCreateWithData (ImageIO:x86_64+0x2a)"
    #               or  "decode_frame file.c:42:5"
    sym = rest.split(" (", 1)[0]
    sym = re.sub(r"\s+\S+:\d+(:\d+)?$", "", sym)  # trailing file:line:col
    return sym.strip() or rest.strip()


def is_crash_report(text: str) -> bool:
    """True if ``text`` contains a recognizable sanitizer crash report."""
    if not text:
        return False
    return bool(
        _ERR_RE.search(text) or _SUMMARY_RE.search(text)
        or _UBSAN_RE.search(text)
        or "AddressSanitizer" in text or "libFuzzer" in text)


def parse(text: str, *, module: str = "") -> Diagnostics:
    """Parse a sanitizer report ``text`` into normalized :class:`Diagnostics`.

    ``module`` is the framework/library under test (e.g. ``"ImageIO"``); it is
    used as a fallback module and to tag the signature.
    """
    text = text or ""

    kind = ""
    m = _ERR_RE.search(text)
    if m:
        kind = m.group("kind").lower()
    if not kind:
        ms = _SUMMARY_RE.search(text)
        if ms:
            kind = ms.group("kind").lower()
    if not kind and _UBSAN_RE.search(text):
        kind = "undefined-behavior"
    if not kind:
        kind = "unknown"

    # access type
    access = ""
    ma = _ACCESS_RE.search(text) or _SIGNAL_ACCESS_RE.search(text)
    if ma:
        access = ma.group("acc").lower()

    # faulting address
    faulting = ""
    addr_int: int | None = None
    maddr = _ADDR_ON_RE.search(text) or _ADDR_ANY_RE.search(text)
    if maddr:
        faulting = _norm_addr(maddr.group("addr"))
        try:
            addr_int = int(maddr.group("addr"), 16)
        except ValueError:
            addr_int = None
    if _HINT_ZERO_RE.search(text) and not faulting:
        faulting = "0x0000000000000000"
        addr_int = 0

    # instruction pointer
    instr = ""
    mpc = _PC_RE.search(text)
    if mpc:
        instr = _norm_addr(mpc.group("pc"))

    classification = _refine_class(kind, access, addr_int)
    # A UBSan report (only, or "undefined-behavior" summary) carries no ASan
    # error kind; recover a specific classification from its message.
    if classification == "UNKNOWN":
        um = _UBSAN_RE.search(text)
        if um:
            ub_class, ub_access = _classify_ubsan(um.group("msg"))
            if ub_class != "UNKNOWN":
                classification = ub_class
                access = access or ub_access
    if not access:
        # infer access from refined classification for downstream consistency
        if classification == "OUT_OF_BOUNDS_WRITE":
            access = "write"
        elif classification in ("OUT_OF_BOUNDS_READ", "USE_AFTER_FREE",
                                "NULL_DEREFERENCE"):
            access = "read"
        else:
            access = "none"

    exc, sig = _CLASS_PROFILE.get(classification, _CLASS_PROFILE["UNKNOWN"])

    # backtrace + modules
    frames: list[str] = []
    modules: list[str] = []
    seen_modules: set[str] = set()
    first_pc = ""
    for line in text.splitlines():
        fm = _FRAME_RE.match(line)
        if not fm:
            continue
        pc = _norm_addr(fm.group("pc"))
        if not first_pc:
            first_pc = pc
        rest = fm.group("rest")
        sym = _extract_symbol(rest)
        mod_m = _MODULE_PAREN_RE.search(rest)
        mod = mod_m.group(1) if mod_m else ""
        if mod and mod not in seen_modules:
            seen_modules.add(mod)
            modules.append(mod)
        prefix = f"{mod}`" if mod else ""
        frames.append(f"{prefix}{sym}")

    if not instr and first_pc:
        instr = first_pc
    if module and module not in seen_modules:
        modules.insert(0, module)

    registers: dict[str, str] = {}
    if instr:
        registers["pc"] = instr
    if faulting:
        registers["x0"] = faulting

    # A signature keyed on classification + top frames, stable across the
    # jittering addresses in the report (so dedup groups matching crashes).
    top = "|".join(frames[:5])
    signature = "asan_" + hashlib.sha256(
        (classification + "|" + (module or "") + "|" + top).encode()
    ).hexdigest()[:16]

    return Diagnostics(
        exception_type=exc,
        signal=sig,
        faulting_address=faulting,
        instruction_address=instr,
        access_type=access,
        registers=registers,
        stack_trace=frames,
        modules=modules or ([module] if module else []),
        thread={"id": 0, "name": "libFuzzer", "crashed": True},
        signature=signature,
        classification_hint=classification,
    )
