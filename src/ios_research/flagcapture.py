"""Detect Apple Target Flag captures inside stored crash evidence (#84).

Apple's Commpage Target Flags let a proof-of-concept demonstrate register
control, arbitrary read/write, or code execution *objectively*: boot-random
values live at fixed offsets in the commpage, and a qualifying crash log shows
a register, fault address, or PC equal to one of them.  The TCC Target Flag is
confirmed with ``tccutil flag check`` ("modified" vs "default").

This module only **classifies evidence that already exists in the workspace**:

* ``detect_commpage`` compares normalized diagnostics (registers, faulting
  address, PC) against researcher-supplied commpage values or against
  structural patterns from Apple's published PoC recipe.  It never fabricates
  register state and never produces exploit material.
* ``parse_tccutil_output`` parses the text output of Apple's own
  ``tccutil flag check`` command into structured evidence.

Results are hypotheses for the researcher to confirm, consistent with the rest
of the framework: detection failure proves nothing, and detection success is
recorded as evidence, not as an eligibility or reward determination.
"""

from __future__ import annotations

import re
from typing import Any

# Published commpage Target Flag layout (security.apple.com/bounty/target-flags).
COMM_PAGE64_BASE_ADDRESS = 0x0000000FFFFFC000
COMM_PAGE_TARGET_OFFSETS: dict[str, int] = {
    "value": 0x320,         # _COMM_PAGE_ASB_TARGET_VALUE      (random uint64)
    "address": 0x328,       # _COMM_PAGE_ASB_TARGET_ADDRESS    (random address)
    "kern_value": 0x330,    # _COMM_PAGE_ASB_TARGET_KERN_VALUE
    "kern_address": 0x338,  # _COMM_PAGE_ASB_TARGET_KERN_ADDRESS
}

# General-purpose ARM64 register names considered for equality matches.
_GP_PREFIXES = tuple(f"x{i}" for i in range(29))  # x0..x28 (x29 is FP)

# Faults below this are null-page dereferences (never flag captures; Apple
# explicitly excludes them), matching targets/ips.py's classification limit.
_NULL_PAGE_LIMIT = 0x1000

_PRIMITIVES = ("code-execution", "arbitrary-read-write", "register-control")


def _to_int(value: Any) -> int | None:
    """Best-effort conversion of an int / decimal / hex string to int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value & ((1 << 64) - 1)
    if isinstance(value, str):
        text = value.strip().lower()
        try:
            if text.startswith("0x"):
                iv = int(text, 16)
            elif re.fullmatch(r"-?\d+", text):
                iv = int(text)
            else:
                return None
        except ValueError:
            return None
        return iv & ((1 << 64) - 1)
    return None


def _reg_value(registers: dict[str, Any], name: str) -> int | None:
    return _to_int(registers.get(name))


def detect_commpage(diagnostics: dict[str, Any],
                    supplied: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Classify a normalized diagnostics dict against Commpage Target Flags.

    ``supplied`` optionally carries the boot-random commpage contents captured
    on the research device during the PoC run::

        {"value": "0x...", "address": "0x...",
         "kern_value": "0x...", "kern_address": "0x..."}

    With supplied values, exact equality matches yield HIGH-confidence
    detections of any primitive level.  Without them, only Apple's canonical
    structural pattern is recognized at LOW confidence: an ``EXC_BAD_ACCESS``
    whose faulting address also appears in a general-purpose register (the
    documented arbitrary read/write PoC shape).  When nothing matches, returns
    ``None`` rather than guessing.
    """
    if not isinstance(diagnostics, dict):
        return None
    registers = diagnostics.get("registers") or {}
    if not isinstance(registers, dict):
        registers = {}
    far = _to_int(diagnostics.get("faulting_address"))
    pc = (_to_int(diagnostics.get("instruction_address"))
          or _reg_value(registers, "pc"))
    exc_type = str(diagnostics.get("exception_type", "") or "").upper()

    sup: dict[str, int] = {}
    for key in COMM_PAGE_TARGET_OFFSETS:
        raw = (supplied or {}).get(key)
        iv = _to_int(raw)
        if iv is not None:
            sup[key] = iv

    def result(primitive: str, space: str, confidence: str, basis: str,
               register: str = "") -> dict[str, Any]:
        out = {"mechanism": "commpage",
               "primitive": primitive,
               "space": space,
               "bit_width": 64,
               "confidence": confidence,
               "basis": basis}
        if register:
            out["register"] = register
        return out

    # --- supplied-value exact matches (highest fidelity) --------------------
    if sup:
        if pc is not None:
            if "address" in sup and pc == sup["address"]:
                return result("code-execution", "userspace", "HIGH",
                              "supplied-values")
            if "kern_address" in sup and pc == sup["kern_address"]:
                return result("code-execution", "kernel", "HIGH",
                              "supplied-values")
        if far is not None:
            if "address" in sup and far == sup["address"]:
                return result("arbitrary-read-write", "userspace", "HIGH",
                              "supplied-values")
            if "kern_address" in sup and far == sup["kern_address"]:
                return result("arbitrary-read-write", "kernel", "HIGH",
                              "supplied-values")
        for key, space in (("value", "userspace"), ("kern_value", "kernel")):
            target = sup.get(key)
            if target is None:
                continue
            for name in sorted(registers):
                if not name.startswith(_GP_PREFIXES):
                    continue
                if _reg_value(registers, name) == target:
                    return result("register-control", space, "HIGH",
                                  "supplied-values", register=name)

    # --- structural fallback (no supplied values needed) --------------------
    # Apple's own arbitrary read/write PoC dereferences a pointer that stays
    # live in a general-purpose register, so the faulting address equals that
    # register's value.
    if (far is not None and far >= _NULL_PAGE_LIMIT
            and exc_type == "EXC_BAD_ACCESS"):
        for name in sorted(registers):
            if not name.startswith(_GP_PREFIXES):
                continue
            if _reg_value(registers, name) == far:
                return result("arbitrary-read-write", "userspace", "LOW",
                              "structural", register=name)

    return None


_TCC_LINE_RE = re.compile(
    r"\b(?P<which>user|system)\s*:\s*(?P<state>modified|default)\b",
    re.IGNORECASE)


def parse_tccutil_output(text: str) -> dict[str, Any]:
    """Parse ``tccutil flag check`` output into structured TCC-flag evidence.

    Example input (macOS)::

        User: modified
        System: default

    Returns ``{"parsed": bool, "user": str, "system": str, "captured": bool}``.
    ``captured`` is true when either database reports ``modified``; it records
    the demonstration — it never modifies TCC state itself.
    """
    found = {m.group("which").lower(): m.group("state").lower()
             for m in _TCC_LINE_RE.finditer(text or "")}
    parsed = bool(found)
    return {"parsed": parsed,
            "user": found.get("user", ""),
            "system": found.get("system", ""),
            "captured": "modified" in found.values()}


def describe(capture: dict[str, Any]) -> str:
    """Human summary used in readiness-check descriptions."""
    bits = f"{capture['space']}/{capture['primitive']} " \
           f"({capture['bit_width']}-bit, {capture['confidence'].lower()} "
    bits += f"confidence via {capture['basis']})"
    return bits


def commpage_info() -> dict[str, Any]:
    """Machine-readable constants for CLI exposure (targetflags list)."""
    return {"base_address": f"0x{COMM_PAGE64_BASE_ADDRESS:016x}",
            "offsets": {k: f"0x{v:x}"
                        for k, v in sorted(COMM_PAGE_TARGET_OFFSETS.items())},
            "reference": "https://security.apple.com/bounty/target-flags/"}
