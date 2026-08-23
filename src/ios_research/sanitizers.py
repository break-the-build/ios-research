"""Portable sanitizer profiles and normalized multi-sanitizer triage (#31).

Native campaigns previously built ASan/UBSan only. This module adds named,
platform-aware *profiles* (baseline, asan-ubsan, cfi, tsan, lsan, msan),
validates toolchain/platform support *before* a campaign starts (fail closed
with an actionable reason), and extends triage so equivalent findings from
different profiles can be compared without collapsing unrelated sanitizer
classes.

Profiles carry their compiler flags and runtime options so every experiment
records exactly how its target was built (provenance). Nothing here executes a
toolchain or changes host security settings; it only describes builds and reads
report text.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .errors import ValidationError

SUPPORTED_PLATFORMS = ("darwin", "linux")

SANITIZER_KINDS = (
    "address",
    "undefined-behavior",
    "thread",
    "memory",
    "leak",
    "libfuzzer",
)


@dataclass(frozen=True)
class SanitizerProfile:
    """A named sanitizer build configuration."""

    id: str
    description: str
    compile_flags: tuple[str, ...]
    runtime_env: dict[str, str] = field(default_factory=dict)
    platforms: tuple[str, ...] = ("darwin", "linux")
    requires: tuple[str, ...] = ()   # extra toolchain requirements (notes)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "compile_flags": list(self.compile_flags),
            "runtime_env": dict(self.runtime_env),
            "platforms": list(self.platforms),
            "requires": list(self.requires),
        }


PROFILES: dict[str, SanitizerProfile] = {
    profile.id: profile
    for profile in (
        SanitizerProfile(
            id="baseline",
            description="no sanitizer instrumentation",
            compile_flags=("-fsanitize-coverage=trace-pc-guard",),
        ),
        SanitizerProfile(
            id="asan-ubsan",
            description="AddressSanitizer + UndefinedBehaviorSanitizer",
            compile_flags=(
                "-fsanitize=address,undefined",
                "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            ),
            runtime_env={
                "ASAN_OPTIONS": "abort_on_error=0:exitcode=99:detect_leaks=0",
                "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
            },
        ),
        SanitizerProfile(
            id="cfi",
            description="Control-Flow Integrity (requires lto + visibility)",
            compile_flags=(
                "-fsanitize=cfi",
                "-flto",
                "-fvisibility=hidden",
                "-fsanitize-coverage=trace-pc-guard",
            ),
            requires=("lld linker",),
        ),
        SanitizerProfile(
            id="tsan",
            description="ThreadSanitizer (incompatible with ASan/MSan)",
            compile_flags=("-fsanitize=thread",
                           "-fsanitize-coverage=trace-pc-guard"),
            runtime_env={"TSAN_OPTIONS": "halt_on_error=1"},
        ),
        SanitizerProfile(
            id="lsan",
            description="LeakSanitizer",
            compile_flags=("-fsanitize=leak",),
        ),
        SanitizerProfile(
            id="msan",
            description=("MemorySanitizer (Linux; all linked code must be "
                         "instrumented)"),
            compile_flags=("-fsanitize=memory",
                           "-fsanitize-coverage=trace-pc-guard"),
            platforms=("linux",),
        ),
    )
}

# Profiles that must never be combined in one build.
_INCOMPATIBLE = {
    frozenset({"address", "thread"}),
    frozenset({"memory", "thread"}),
    frozenset({"memory", "address"}),
}


def get_profile(profile_id: str) -> SanitizerProfile:
    try:
        return PROFILES[profile_id]
    except KeyError:
        raise ValidationError(
            f"unknown sanitizer profile '{profile_id}'; "
            f"known: {', '.join(sorted(PROFILES))}") from None


def validate_profile(profile_id: str, *, platform: str = "darwin") -> dict:
    """Validate a profile for ``platform``; fail closed with actionable detail.

    Returns a stable dict: ``{"supported": bool, "profile": ..., "reason": ...}``.
    Raises :class:`ValidationError` only for unknown profile IDs.
    """
    profile = get_profile(profile_id)
    if platform not in SUPPORTED_PLATFORMS:
        return {"supported": False, "profile": profile.to_dict(),
                "reason": f"unsupported platform '{platform}'"}
    if platform not in profile.platforms:
        return {
            "supported": False,
            "profile": profile.to_dict(),
            "reason": (f"profile '{profile_id}' is not supported on "
                       f"'{platform}' (supported: "
                       f"{', '.join(profile.platforms)})"),
        }
    return {"supported": True, "profile": profile.to_dict(), "reason": ""}


def check_combination(profile_ids: list[str]) -> dict:
    """Validate a campaign matrix of profiles for mutual compatibility."""
    seen: set[str] = set()
    for pid in profile_ids:
        flags = get_profile(pid).compile_flags[0]
        if flags.startswith("-fsanitize="):
            seen |= set(flags.replace("-fsanitize=", "").split(","))
    conflicts = sorted(
        "|".join(sorted(pair)) for pair in _INCOMPATIBLE if pair <= seen)
    if conflicts:
        raise ValidationError(
            "incompatible sanitizer combination requested: "
            f"{', '.join(conflicts)}")
    return {"compatible": True, "profiles": list(profile_ids)}


# --- report triage -----------------------------------------------------------

_KIND_RE = re.compile(
    r"(AddressSanitizer|UndefinedBehaviorSanitizer|ThreadSanitizer|"
    r"MemorySanitizer|LeakSanitizer|libFuzzer)")
_KIND_MAP = {
    "addresssanitizer": "address",
    "undefinedbehaviorsanitizer": "undefined-behavior",
    "threadsanitizer": "thread",
    "memorysanitizer": "memory",
    "leaksanitizer": "leak",
    "libfuzzer": "libfuzzer",
}
_RACE_RE = re.compile(r"ThreadSanitizer:\s*(?P<what>[a-z][a-z \-]+)", re.I)
_UNINIT_RE = re.compile(r"use-of-uninitialized-value")
_LEAK_RE = re.compile(r"(detected memory leaks|\d+ byte\(s\) leaked)")
_FRAME_RE = re.compile(
    r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<rest>.+?)\s*$")


def detect_sanitizers(text: str) -> list[str]:
    """Return the sanitizer kinds named in a report (deterministic order)."""
    found = {_KIND_MAP.get(k.lower(), k.lower())
             for k in _KIND_RE.findall(text or "")}
    return [kind for kind in SANITIZER_KINDS if kind in found]


def violation_class(text: str) -> str:
    """Normalized violation class, comparable across sanitizer profiles."""
    blob = (text or "").lower()
    if "heap-buffer-overflow" in blob or "stack-buffer-overflow" in blob \
            or "global-buffer-overflow" in blob:
        return "BUFFER_OVERFLOW"
    if "use-after-free" in blob:
        return "USE_AFTER_FREE"
    if "double-free" in blob:
        return "DOUBLE_FREE"
    if "data race" in blob:
        return "DATA_RACE"
    if "deadlock" in blob:
        return "DEADLOCK"
    if _UNINIT_RE.search(blob):
        return "UNINITIALIZED_READ"
    if _LEAK_RE.search(blob):
        return "MEMORY_LEAK"
    if "runtime error:" in blob:
        return "UNDEFINED_BEHAVIOR"
    if "segv" in blob or "null-deref" in blob:
        return "SEGV_OR_NULL_DEREF"
    return "UNKNOWN"


def _top_frames(text: str, limit: int = 3) -> tuple[str, ...]:
    import ios_research.targets.asan as asan
    frames: list[str] = []
    for line in (text or "").splitlines():
        m = _FRAME_RE.match(line)
        if m:
            frames.append(asan._extract_symbol(m.group("rest")))
    return tuple(frames[:limit])


def dedup_signature(text: str, *, module: str = "") -> str:
    """Dedup-safe signature namespaced by sanitizer kind + violation class.

    Equivalent findings from different profiles stay distinct unless both the
    sanitizer class and top frames agree, so unrelated sanitizer violations are
    never collapsed together.
    """
    kinds = detect_sanitizers(text)
    kind = ",".join(kinds) if kinds else "none"
    vclass = violation_class(text)
    top = "|".join(_top_frames(text))
    digest = hashlib.sha256(
        f"{vclass}|{module}|{top}".encode()).hexdigest()[:16]
    return f"{kind}_{vclass}_{digest}"


def triage_report(text: str, *, module: str = "") -> dict:
    """Normalize one report into multi-sanitizer triage fields."""
    import ios_research.targets.asan as asan
    diag = asan.parse(text, module=module)
    return {
        "sanitizers": detect_sanitizers(text),
        "violation_class": violation_class(text),
        "classification": diag.classification_hint,
        "dedup_signature": dedup_signature(text, module=module),
        "top_frames": list(_top_frames(text)),
    }


def compare_findings(findings: list[dict]) -> dict:
    """Compare findings from multiple profiles without collapsing classes.

    Each finding is a ``triage_report()`` dict optionally carrying a
    ``profile`` key. Returns grouped equivalents plus per-class counts.
    """
    groups: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    for finding in findings:
        sig = finding.get("dedup_signature", "")
        label = f"{finding.get('profile', 'unknown')}:{sig}"
        groups.setdefault(sig, []).append(label)
        vclass = finding.get("violation_class", "UNKNOWN")
        counts[vclass] = counts.get(vclass, 0) + 1
    return {
        "equivalence_groups": {sig: sorted(labels)
                               for sig, labels in sorted(groups.items())},
        "by_violation_class": dict(sorted(counts.items())),
        "total": len(findings),
    }
