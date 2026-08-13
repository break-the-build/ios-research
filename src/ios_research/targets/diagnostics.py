"""Deterministic synthetic-diagnostics generation for mock targets.

Mock targets do not run native code; instead they emit *synthetic* but fully
deterministic diagnostics derived from the triggering input. This gives the
triage, analysis, and reporting subsystems realistic, reproducible data to work
with in CI without any real device.
"""

from __future__ import annotations

import hashlib

from .base import Diagnostics

# Mapping from a crash classification to the exception/signal/access it implies.
_CLASS_PROFILE = {
    "NULL_DEREFERENCE": ("EXC_BAD_ACCESS", "SIGSEGV", "read"),
    "OUT_OF_BOUNDS_READ": ("EXC_BAD_ACCESS", "SIGSEGV", "read"),
    "OUT_OF_BOUNDS_WRITE": ("EXC_BAD_ACCESS", "SIGSEGV", "write"),
    "USE_AFTER_FREE": ("EXC_BAD_ACCESS", "SIGSEGV", "read"),
    "INTEGER_ERROR": ("EXC_ARITHMETIC", "SIGFPE", "none"),
    "TYPE_CONFUSION": ("EXC_BAD_ACCESS", "SIGSEGV", "read"),
    "ASSERTION": ("EXC_CRASH", "SIGABRT", "none"),
    "TIMEOUT": ("EXC_RESOURCE", "SIGKILL", "none"),
    "UNKNOWN": ("EXC_BAD_ACCESS", "SIGSEGV", "none"),
}


def _digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _addr(seed: bytes, salt: str, *, null: bool = False) -> str:
    if null:
        return "0x0000000000000000"
    h = hashlib.sha256(seed + salt.encode()).digest()
    value = int.from_bytes(h[:6], "big")  # 48-bit userland-ish address
    return f"0x{value:016x}"


def build(data: bytes, classification: str, module: str,
          symbols: list[str]) -> Diagnostics:
    """Build deterministic diagnostics for a crash of ``classification``."""
    exc, sig, access = _CLASS_PROFILE.get(
        classification, _CLASS_PROFILE["UNKNOWN"])
    seed = _digest(data)

    null = classification == "NULL_DEREFERENCE"
    faulting = _addr(seed, "fault", null=null)
    instr = _addr(seed, "instr")

    registers = {}
    for i, name in enumerate(("pc", "lr", "sp", "x0", "x1", "x2", "x3")):
        if name == "pc":
            registers[name] = instr
        elif name == "x0" and null:
            registers[name] = "0x0000000000000000"
        else:
            registers[name] = _addr(seed, f"reg{i}")

    frames = [f"{module}`{sym}+0x{(seed[i] * 4):x}"
              for i, sym in enumerate(symbols)]

    signature = "sig_" + hashlib.sha256(
        (classification + "|" + "|".join(symbols)).encode()).hexdigest()[:16]

    return Diagnostics(
        exception_type=exc,
        signal=sig,
        faulting_address=faulting,
        instruction_address=instr,
        access_type=access,
        registers=registers,
        stack_trace=frames,
        modules=[module, "libsystem_kernel.dylib", "CoreFoundation"],
        thread={"id": 0, "name": "com.ios-research.worker", "crashed": True},
        signature=signature,
        classification_hint=classification,
    )
