"""Parse the harness's own fatal-signal report into ``Diagnostics``.

The default macOS harness build runs under Guard Malloc (libgmalloc), not a
compiler sanitizer: Apple's frameworks are precompiled, so ASan never checks
their memory accesses, while Guard Malloc faults on a heap overflow or
use-after-free inside them. A detection is therefore a fatal signal, which
``tools/harness/harness_runtime.h`` reports on stderr as::

    IOSR-CRASH signal=SIGSEGV addr=0x... pc=0x... access=read|write|exec|unknown
    IOSR-FRAME 0 0x<pc> <module>+0x<offset> <symbol>
    IOSR-FRAME 1 ...

This module turns that report -- or, if the process died before it could print
one, just the signal from the exit status -- into the same normalized
:class:`~ios_research.targets.base.Diagnostics` the ASan path produces, so
triage, dedup and minimization work unchanged.
"""

from __future__ import annotations

import hashlib
import re
import signal

from .base import Diagnostics

_CRASH_RE = re.compile(
    r"IOSR-CRASH signal=(?P<sig>\S+) addr=(?P<addr>0x[0-9a-fA-F]+) "
    r"pc=(?P<pc>0x[0-9a-fA-F]+) access=(?P<access>\w+)")
_FRAME_RE = re.compile(
    r"IOSR-FRAME (?P<n>\d+) (?P<pc>0x[0-9a-fA-F]+) (?P<mod>\S+)\+(?P<off>0x[0-9a-fA-F]+) (?P<sym>\S+)")

_NULL_PAGE_LIMIT = 0x1000
_SIGNAL_CLASS = {
    "SIGABRT": "ASSERTION",
    "SIGTRAP": "ASSERTION",          # __builtin_trap / brk in framework checks
    "SIGILL": "ASSERTION",
    "SIGFPE": "INTEGER_ERROR",
}
_EXCEPTION_FOR = {
    "SIGSEGV": "EXC_BAD_ACCESS", "SIGBUS": "EXC_BAD_ACCESS",
    "SIGABRT": "EXC_CRASH", "SIGTRAP": "EXC_BREAKPOINT",
    "SIGILL": "EXC_BAD_INSTRUCTION", "SIGFPE": "EXC_ARITHMETIC",
}
_HARNESS_MODULE_PREFIXES = ("dyld", "libsystem_", "libdyld")


def is_signal_report(text: str) -> bool:
    return "IOSR-CRASH signal=" in text


def signal_name(returncode: int) -> str:
    """``-11`` (subprocess) or ``139`` (shell) -> ``SIGSEGV``; '' if not a signal."""
    num = -returncode if returncode < 0 else returncode - 128 if returncode > 128 else 0
    try:
        return signal.Signals(num).name if num else ""
    except ValueError:
        return ""


def _classify(sig: str, access: str, addr: int | None) -> str:
    if sig in _SIGNAL_CLASS:
        return _SIGNAL_CLASS[sig]
    if addr is not None and addr < _NULL_PAGE_LIMIT:
        return "NULL_DEREFERENCE"
    # Under Guard Malloc both an overflow onto the guard page and a touch of
    # freed (unmapped) memory fault here; without allocation metadata the two
    # are indistinguishable, so classify by access direction and let triage
    # (minimize + analyze) separate spatial from temporal.
    return "OUT_OF_BOUNDS_WRITE" if access == "write" else "OUT_OF_BOUNDS_READ"


def parse(text: str, *, module: str = "", returncode: int = 0) -> Diagnostics:
    """Build Diagnostics from an IOSR-CRASH report (or just the exit signal)."""
    m = _CRASH_RE.search(text)
    sig = m.group("sig") if m else signal_name(returncode) or "SIGSEGV"
    access = m.group("access") if m else "unknown"
    addr_hex = f"0x{int(m.group('addr'), 16):016x}" if m else ""
    pc_hex = f"0x{int(m.group('pc'), 16):016x}" if m else ""
    addr_int = int(addr_hex, 16) if addr_hex else None

    frames: list[str] = []
    modules: list[str] = []
    for fm in sorted(_FRAME_RE.finditer(text), key=lambda f: int(f.group("n"))):
        mod, sym, off = fm.group("mod"), fm.group("sym"), fm.group("off")
        frames.append(f"{mod}`{sym if sym != '?' else off}")
        if mod != "?" and mod not in modules:
            modules.append(mod)
    if module and module not in modules:
        modules.insert(0, module)

    classification = _classify(sig, access, addr_int)
    # Dedup on classification + the top frames inside the code under test
    # (module+symbol, never raw addresses, which ASLR moves every run).
    stable = [f for f in frames if not f.startswith(_HARNESS_MODULE_PREFIXES)][:5]
    signature = "sig_" + hashlib.sha256(
        (classification + "|" + sig + "|" + "|".join(stable)).encode()).hexdigest()[:16]
    registers = {"pc": pc_hex} if pc_hex else {}
    return Diagnostics(
        exception_type=_EXCEPTION_FOR.get(sig, "EXC_CRASH"),
        signal=sig,
        faulting_address=addr_hex,
        instruction_address=pc_hex,
        access_type=access if access in ("read", "write", "exec") else "none",
        registers=registers,
        stack_trace=frames,
        modules=modules,
        thread={"id": 0, "name": "harness", "crashed": True},
        signature=signature,
        classification_hint=classification,
    )
