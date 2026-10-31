"""Detection canary: positive and negative controls for the macOS harness oracle.

From Aug 23 to Oct 29 2026 the mac harnesses ran with an oracle that could not
see heap corruption inside Apple's frameworks, and nothing noticed: a dead
detector looks exactly like "no bugs". The canary makes that failure loud.

* **Positive control.** ``IOSR_CANARY=1`` makes the harness hand the framework a
  buffer whose tail is Guard Malloc's guard page (``canary_open`` in
  ``tools/harness/mac_fuzz_harness.c``) and print that guarded range. The
  framework's own read into it must come back through the normal path (crash
  reporter, :mod:`sigcrash`, ``MacFuzzTarget``) as an out-of-bounds read at an
  address inside the range, with the framework on the stack and the harness not
  at the top. Without Guard Malloc no guard page borders the buffer; the harness
  says ``mode=unguarded`` and the check fails.
* **Negative control.** The same valid seed, run normally, must not crash. If it
  does, the oracle itself is crashing (MALLOC_STRICT_SIZE breaks code that relies
  on 16-byte malloc alignment: it kills the CoreGraphics harness on every input
  in an XPC reply's ``_Block_release``), and every campaign result under it would
  be noise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from .base import ExecResult, Outcome

_LINE_RE = re.compile(r"IOSR-CANARY mode=(?P<mode>\w+) lo=(?P<lo>0x[0-9a-fA-F]+) "
                      r"hi=(?P<hi>0x[0-9a-fA-F]+)")
_SYSTEM_PREFIXES = ("libsystem_", "dyld", "libdyld")
_FAULT_SIGNALS = ("SIGSEGV", "SIGBUS")

# Images where each framework's parsing runs: the fault's stack must include one.
EXPECTED_MODULES = {
    "imageio": ("ImageIO", "AppleJPEG"),
    "coregraphics": ("CoreGraphics",),
    "coretext": ("libFontParser.dylib", "CoreText", "FontServices"),
    "audiotoolbox": ("AudioToolboxCore", "AudioToolbox", "AudioCodecs"),
}
# A seed whose header the framework rejects within the canary's 16 live bytes
# never reads past them; a few seeds make the check independent of that.
MAX_SEEDS = 3


@dataclass(frozen=True)
class CanaryVerdict:
    passed: bool
    reason: str
    mode: str = ""
    fault: str = ""
    frames: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "reason": self.reason, "mode": self.mode,
                "fault": self.fault, "frames": list(self.frames)}


def _top(frames: tuple[str, ...]) -> str:
    return frames[0] if frames else "no frames"


def evaluate(key: str, result: ExecResult, report: str) -> CanaryVerdict:
    """Judge one canary run: ``result`` as classified, ``report`` its stderr."""
    m = _LINE_RE.search(report)
    if not m:
        return CanaryVerdict(False, "the harness printed no IOSR-CANARY line: it predates "
                                    "the canary, rebuild it (tools/harness/build.sh)")
    mode = m.group("mode")
    if mode == "unsupported":
        return CanaryVerdict(False, "this harness target has no canary", mode=mode)
    if mode not in ("after", "before"):
        return CanaryVerdict(False, "Guard Malloc is not active: no guard page borders the "
                                    "canary buffer, so heap bugs inside the framework "
                                    "would go undetected", mode=mode)
    diag = result.diagnostics
    if result.outcome != Outcome.CRASH or diag is None:
        return CanaryVerdict(False, "no detection: the framework read past the canary "
                                    f"buffer and the run was {result.outcome} "
                                    f"({result.detail})", mode=mode)
    frames = tuple(diag.stack_trace)
    lo, hi = int(m.group("lo"), 16), int(m.group("hi"), 16)
    addr = int(diag.faulting_address, 16) if diag.faulting_address else None
    found = {"mode": mode, "fault": diag.faulting_address, "frames": frames}
    if diag.signal not in _FAULT_SIGNALS or addr is None or not lo <= addr < hi:
        return CanaryVerdict(False, f"a different crash ({diag.signal} at "
                                    f"{diag.faulting_address or '?'}, top frame "
                                    f"{_top(frames)}), not the canary read in "
                                    f"[{lo:#x}, {hi:#x})", **found)
    if diag.classification_hint != "OUT_OF_BOUNDS_READ":
        return CanaryVerdict(False, f"the canary read was classified "
                                    f"{diag.classification_hint}, not OUT_OF_BOUNDS_READ",
                             **found)
    modules = [f.split("`", 1)[0] for f in frames]
    code = [mod for mod in modules if not mod.startswith(_SYSTEM_PREFIXES)]
    if not code:
        return CanaryVerdict(False, "the crash report has no usable frames", **found)
    if code[0].endswith("_fuzzer"):
        return CanaryVerdict(False, f"the fault was attributed to the harness "
                                    f"({_top(frames)}), not the framework", **found)
    expected = EXPECTED_MODULES.get(key, ())
    if not any(mod in expected for mod in modules):
        return CanaryVerdict(False, f"no {'/'.join(expected) or key} frame on the stack "
                                    f"(top frame {_top(frames)})", **found)
    return CanaryVerdict(True, f"Guard Malloc ({mode}) caught the framework's read at "
                               f"{diag.faulting_address} in {_top(frames)}", **found)


def check(target, seeds: list[bytes] | None = None) -> CanaryVerdict:
    """Run both controls for a ``MacFuzzTarget`` under the current environment.

    Passes on the first seed whose canary read is properly detected; fails at
    once if a seed crashes when run normally.
    """
    pool = list(target.seeds() if seeds is None else seeds)[:MAX_SEEDS]
    if not pool:
        return CanaryVerdict(False, "no seeds to run the canary with")
    failures: list[CanaryVerdict] = []
    for data in pool:
        plain = target.execute(data)
        if plain.outcome == Outcome.CRASH:
            frames = tuple(plain.diagnostics.stack_trace) if plain.diagnostics else ()
            return CanaryVerdict(False, f"the oracle crashes on a valid seed run normally "
                                        f"({plain.detail}; top frame {_top(frames)}): "
                                        f"every result under it would be noise",
                                 frames=frames)
        result, report = target.run_canary(data)
        verdict = evaluate(target.key, result, report)
        if verdict.passed:
            return verdict
        failures.append(verdict)
    first = failures[0]
    return replace(first, reason=f"{first.reason} ({len(pool)} seed(s) tried)")
