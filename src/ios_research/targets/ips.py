"""Parse iOS ``.ips`` crash reports into normalized ``Diagnostics``.

The on-device black-box target (:mod:`ios_research.targets.device`) cannot
instrument memory on a stock retail iPhone — sanitizers, debugger attach to
system processes, and sandbox escape are all blocked. The *only* signal a stock
device yields is the platform crash reporter's ``.ips`` file. This module turns
that file into the same normalized :class:`~ios_research.targets.base.Diagnostics`
that the rest of the pipeline (triage, minimize, analyze, differential, report)
already consumes.

Two on-disk shapes are handled:

* **Modern JSON** (iOS 14+): a one-line JSON *header* followed by a JSON *body*
  (``exception``, ``threads``, ``usedImages`` …). ``idevicecrashreport`` and
  Xcode both emit this.
* **Legacy text** (``Exception Type:`` / ``Thread N Crashed:`` / ``Binary
  Images:``): still produced by some subsystems and older OS builds.

By construction this is **confirmation, not analysis**: a stock device reports
no registers describing an out-of-bounds access, no sanitizer classification,
and no read/write discrimination. So the classification is deliberately coarse
(null-page deref vs. abort vs. arithmetic vs. unknown) and honest about what a
black-box crash log can and cannot tell you. Contrast with
:mod:`ios_research.targets.asan`, which reads *real* access types and OOB
metadata out of an instrumented macOS run.

Parsing is defensive: every field is optional and an unrecognized report still
yields a usable ``Diagnostics`` with a stable signature.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .base import Diagnostics

# Map a top-level Mach exception to the framework's coarse, honest black-box
# classification vocabulary (shared with targets/diagnostics.py + triage). On a
# stock device we cannot distinguish OOB-read from OOB-write from UAF, so a bad
# access that is not a null-page deref stays UNKNOWN rather than guessing.
_EXCEPTION_CLASS = {
    "EXC_BAD_ACCESS": "UNKNOWN",          # refined to NULL_DEREFERENCE below
    "EXC_BAD_INSTRUCTION": "ASSERTION",   # trap/__builtin_trap/Swift precondition
    "EXC_ARITHMETIC": "INTEGER_ERROR",
    "EXC_CRASH": "ASSERTION",             # SIGABRT (assert/abort/uncaught)
    "EXC_GUARD": "ASSERTION",
    "EXC_RESOURCE": "TIMEOUT",            # watchdog/CPU/memory resource kill
    "EXC_BREAKPOINT": "ASSERTION",
}

# Exception/signal profile per classification (mirrors the mock + asan shapes so
# downstream classifiers see one consistent structure regardless of source).
_CLASS_PROFILE = {
    "NULL_DEREFERENCE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "OUT_OF_BOUNDS_READ": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "OUT_OF_BOUNDS_WRITE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "USE_AFTER_FREE": ("EXC_BAD_ACCESS", "SIGSEGV"),
    "INTEGER_ERROR": ("EXC_ARITHMETIC", "SIGFPE"),
    "ASSERTION": ("EXC_CRASH", "SIGABRT"),
    "TIMEOUT": ("EXC_RESOURCE", "SIGKILL"),
    "UNKNOWN": ("EXC_BAD_ACCESS", "SIGSEGV"),
}

# Signals seen in report text, used only to refine SIGABRT -> ASSERTION.
_ABORT_SIGNALS = ("SIGABRT", "SIGKILL", "SIGSYS")

_NULL_PAGE_LIMIT = 0x1000  # faulting addresses below this are null-page derefs


def _norm_addr(value: Any) -> str:
    """Normalize an int or hex string to fixed 16-digit form (``""`` on junk)."""
    try:
        if isinstance(value, str):
            iv = int(value, 16) if value.lower().startswith("0x") else int(value)
        else:
            iv = int(value)
    except (ValueError, TypeError):
        return ""
    if iv < 0:
        iv &= (1 << 64) - 1
    return f"0x{iv:016x}"


def _addr_int(value: Any) -> int | None:
    norm = _norm_addr(value)
    if not norm:
        return None
    return int(norm, 16)


def _refine_class(exc_type: str, addr_int: int | None) -> str:
    base = _EXCEPTION_CLASS.get(exc_type.upper(), "UNKNOWN")
    if exc_type.upper() in ("EXC_BAD_ACCESS",):
        if addr_int is not None and addr_int < _NULL_PAGE_LIMIT:
            return "NULL_DEREFERENCE"
        return "UNKNOWN"
    return base


# --------------------------------------------------------------------------
# format detection + splitting
# --------------------------------------------------------------------------

def _split_json_ips(text: str) -> tuple[dict, dict] | None:
    """Split a modern two-part ``.ips`` into (header, body) dicts, or None.

    The file is a single-line JSON header followed by a (possibly multi-line)
    JSON body. Some exporters concatenate them with a blank line; others put the
    body immediately on line 2. We find the first ``{`` that begins the body by
    decoding the header line, then decoding the remainder.
    """
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return None
    # Decode the header object using a raw decoder so we know where it ends.
    decoder = json.JSONDecoder()
    try:
        header, end = decoder.raw_decode(stripped)
    except json.JSONDecodeError:
        return None
    rest = stripped[end:].lstrip()
    if not rest:
        # Single JSON object: treat it as the body with embedded header fields.
        return (header if isinstance(header, dict) else {},
                header if isinstance(header, dict) else {})
    try:
        body, _ = decoder.raw_decode(rest)
    except json.JSONDecodeError:
        body = {}
    return (header if isinstance(header, dict) else {},
            body if isinstance(body, dict) else {})


def is_crash_report(text: str) -> bool:
    """True if ``text`` looks like a parseable iOS crash report."""
    if not text or not text.strip():
        return False
    if _split_json_ips(text) is not None:
        parts = _split_json_ips(text)
        header, body = parts
        if body.get("exception") or header.get("bug_type") or body.get("threads"):
            return True
    return bool(re.search(r"^Exception Type:", text, re.MULTILINE)
                or re.search(r"^Thread \d+ Crashed", text, re.MULTILINE)
                or re.search(r"^Incident Identifier:", text, re.MULTILINE))


# --------------------------------------------------------------------------
# header metadata (used to match a report to the input that triggered it)
# --------------------------------------------------------------------------

_OS_VERSION_RE = re.compile(
    r"(?P<name>[\w ]+?)\s+(?P<ver>\d[\w.]*)\s*\((?P<build>[0-9A-Za-z]+)\)")


def _parse_os_version(value: str) -> dict[str, str]:
    """Extract ``os_name``/``os_version``/``os_build`` from an OS-version string.

    Example: ``"iPhone OS 17.0 (21A329)"`` -> name=iPhone OS, version=17.0,
    build=21A329.
    """
    if not value:
        return {"os_name": "", "os_version": "", "os_build": ""}
    m = _OS_VERSION_RE.search(value)
    if not m:
        return {"os_name": value.strip(), "os_version": "", "os_build": ""}
    return {"os_name": m.group("name").strip(),
            "os_version": m.group("ver").strip(),
            "os_build": m.group("build").strip()}


def parse_metadata(text: str) -> dict[str, str]:
    """Extract report metadata for matching: process name, OS build, timestamp.

    Returns a dict with ``process``, ``os_name``, ``os_version``, ``os_build``,
    and ``timestamp`` (best-effort; missing fields are empty strings).
    """
    parts = _split_json_ips(text)
    if parts is not None:
        header, body = parts
        os_raw = str(header.get("os_version") or body.get("osVersion", "") or "")
        if isinstance(body.get("osVersion"), dict):
            ov = body["osVersion"]
            train = str(ov.get("train", ""))
            build = str(ov.get("build", ""))
            os_raw = f"{train} ({build})" if train or build else os_raw
        meta = _parse_os_version(os_raw)
        proc = str(body.get("procName") or header.get("name")
                   or header.get("app_name") or "")
        ts = str(header.get("timestamp") or body.get("captureTime") or "")
        meta.update({"process": proc.strip(), "timestamp": ts.strip()})
        return meta

    meta = {"process": "", "os_name": "", "os_version": "", "os_build": "",
            "timestamp": ""}
    for line in text.splitlines():
        if line.startswith("Process:"):
            m = re.match(r"Process:\s*(?P<name>[^\[]+)", line)
            if m:
                meta["process"] = m.group("name").strip()
        elif line.startswith("OS Version:"):
            meta.update(_parse_os_version(line.split(":", 1)[1]))
        elif line.startswith("Date/Time:"):
            meta["timestamp"] = line.split(":", 1)[1].strip()
    return meta


# --------------------------------------------------------------------------
# diagnostics parsing
# --------------------------------------------------------------------------

def _parse_json(header: dict, body: dict, module: str) -> Diagnostics:
    exc = body.get("exception", {}) or {}
    exc_type = str(exc.get("type", "") or "").strip()
    signal = str(exc.get("signal", "") or "").strip()
    subtype = str(exc.get("subtype", "") or "").strip()

    faulting = ""
    addr_int: int | None = None
    m = re.search(r"(0x[0-9a-fA-F]+)", subtype)
    if m:
        faulting = _norm_addr(m.group(1))
        addr_int = _addr_int(m.group(1))

    classification = _refine_class(exc_type, addr_int)
    if not classification or classification == "UNKNOWN":
        if signal in _ABORT_SIGNALS:
            classification = "ASSERTION"

    # locate the triggered/faulting thread
    threads = body.get("threads", []) or []
    faulting_idx = body.get("faultingThread")
    tri = None
    for i, th in enumerate(threads):
        if th.get("triggered") or i == faulting_idx:
            tri = th
            break
    if tri is None and threads:
        tri = threads[0]

    images = body.get("usedImages", []) or []

    def _image_name(idx: Any) -> str:
        try:
            return str(images[int(idx)].get("name", "") or "")
        except (IndexError, ValueError, TypeError, AttributeError):
            return ""

    instr = ""
    registers: dict[str, str] = {}
    frames: list[str] = []
    modules: list[str] = []
    seen: set[str] = set()

    if tri:
        state = tri.get("threadState", {}) or {}
        pc = state.get("pc", {})
        if isinstance(pc, dict) and "value" in pc:
            instr = _norm_addr(pc["value"])
            if instr:
                registers["pc"] = instr
        lr = state.get("lr", {})
        if isinstance(lr, dict) and "value" in lr:
            v = _norm_addr(lr["value"])
            if v:
                registers["lr"] = v
        xs = state.get("x", [])
        if isinstance(xs, list):
            for i, reg in enumerate(xs[:8]):
                if isinstance(reg, dict) and "value" in reg:
                    v = _norm_addr(reg["value"])
                    if v:
                        registers[f"x{i}"] = v

        for fr in tri.get("frames", []) or []:
            name = _image_name(fr.get("imageIndex"))
            sym = str(fr.get("symbol", "") or "").strip()
            off = fr.get("imageOffset")
            if name and name not in seen:
                seen.add(name)
                modules.append(name)
            if sym:
                label = f"{name}`{sym}" if name else sym
            elif name and off is not None:
                label = f"{name}+0x{int(off):x}"
            elif name:
                label = name
            else:
                continue
            frames.append(label)

    if module and module not in seen:
        modules.insert(0, module)

    return _finalize(exc_type, signal, classification, faulting, instr,
                     registers, frames, modules, module,
                     proc=str(body.get("procName") or header.get("name") or ""))


_LEGACY_EXC_RE = re.compile(r"^Exception Type:\s*(?P<type>[A-Z_]+)"
                            r"(?:\s*\((?P<sig>[A-Z0-9]+)\))?", re.MULTILINE)
_LEGACY_SUBTYPE_RE = re.compile(r"^Exception Subtype:\s*(?P<sub>.+)$", re.MULTILINE)
_LEGACY_FRAME_RE = re.compile(
    r"^\s*\d+\s+(?P<mod>\S+)\s+(?P<addr>0x[0-9a-fA-F]+)\s+(?P<rest>.*)$")


def _parse_legacy(text: str, module: str) -> Diagnostics:
    exc_type = ""
    signal = ""
    m = _LEGACY_EXC_RE.search(text)
    if m:
        exc_type = m.group("type") or ""
        signal = m.group("sig") or ""

    subtype = ""
    ms = _LEGACY_SUBTYPE_RE.search(text)
    if ms:
        subtype = ms.group("sub").strip()

    faulting = ""
    addr_int: int | None = None
    ma = re.search(r"(0x[0-9a-fA-F]+)", subtype)
    if ma:
        faulting = _norm_addr(ma.group(1))
        addr_int = _addr_int(ma.group(1))

    classification = _refine_class(exc_type, addr_int)
    if classification == "UNKNOWN" and signal in _ABORT_SIGNALS:
        classification = "ASSERTION"

    # frames: parse only the crashed thread's backtrace block
    frames: list[str] = []
    modules: list[str] = []
    seen: set[str] = set()
    instr = ""
    in_crashed = False
    for line in text.splitlines():
        if re.match(r"^Thread \d+ Crashed", line):
            in_crashed = True
            continue
        if in_crashed:
            if not line.strip() or line.startswith("Thread "):
                in_crashed = False
                continue
            fm = _LEGACY_FRAME_RE.match(line)
            if not fm:
                continue
            mod = fm.group("mod")
            addr = _norm_addr(fm.group("addr"))
            if not instr:
                instr = addr
            rest = fm.group("rest").strip()
            sym = re.sub(r"\s*\+\s*\d+$", "", rest).strip() or rest
            if mod and mod not in seen:
                seen.add(mod)
                modules.append(mod)
            frames.append(f"{mod}`{sym}" if mod else sym)

    if module and module not in seen:
        modules.insert(0, module)

    registers: dict[str, str] = {}
    if instr:
        registers["pc"] = instr
    if faulting:
        registers["far"] = faulting

    proc = ""
    mp = re.search(r"^Process:\s*([^\[]+)", text, re.MULTILINE)
    if mp:
        proc = mp.group(1).strip()

    return _finalize(exc_type, signal, classification, faulting, instr,
                     registers, frames, modules, module, proc=proc)


def _finalize(exc_type: str, signal: str, classification: str,
              faulting: str, instr: str, registers: dict[str, str],
              frames: list[str], modules: list[str], module: str,
              *, proc: str) -> Diagnostics:
    if classification not in _CLASS_PROFILE:
        classification = "UNKNOWN"
    prof_exc, prof_sig = _CLASS_PROFILE[classification]
    exc_out = exc_type or prof_exc
    sig_out = signal or prof_sig

    # black-box crash logs do not report read/write discrimination
    access = "read" if classification == "NULL_DEREFERENCE" else "none"

    top = "|".join(frames[:5])
    signature = "ips_" + hashlib.sha256(
        (classification + "|" + (proc or module or "") + "|" + top).encode()
    ).hexdigest()[:16]

    return Diagnostics(
        exception_type=exc_out,
        signal=sig_out,
        faulting_address=faulting,
        instruction_address=instr,
        access_type=access,
        registers=registers,
        stack_trace=frames,
        modules=modules or ([module] if module else []),
        thread={"id": 0, "name": proc or "", "crashed": True},
        signature=signature,
        classification_hint=classification,
    )


def parse(text: str, *, module: str = "") -> Diagnostics:
    """Parse an iOS ``.ips`` crash report into normalized :class:`Diagnostics`.

    ``module`` is the surface/library under test (e.g. ``"ImageIO"``); it is used
    as a fallback module and to tag the signature. Handles both the modern JSON
    two-part format and the legacy text format, and degrades gracefully on an
    unrecognized report.
    """
    text = text or ""
    parts = _split_json_ips(text)
    if parts is not None and (parts[1].get("exception") or parts[1].get("threads")
                              or parts[0].get("bug_type")):
        header, body = parts
        return _parse_json(header, body, module)
    return _parse_legacy(text, module)
