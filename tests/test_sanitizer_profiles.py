"""Sanitizer profiles and normalized multi-sanitizer triage (#31)."""

from __future__ import annotations

import pytest

from ios_research import sanitizers
from ios_research.errors import StateError, ValidationError
from ios_research.fuzz import FuzzEngine
from ios_research.experiment import ExperimentStore
from ios_research.corpus import CorpusStore


# --- profile registry --------------------------------------------------------

def test_registry_contains_expected_profiles():
    assert set(sanitizers.PROFILES) >= {
        "baseline", "asan-ubsan", "cfi", "tsan", "lsan", "msan"}


def test_get_profile_unknown_fails_with_known_list():
    with pytest.raises(ValidationError) as exc:
        sanitizers.get_profile("bogus")
    assert "baseline" in str(exc.value)


def test_validate_profile_msan_fails_closed_on_darwin():
    result = sanitizers.validate_profile("msan", platform="darwin")
    assert result["supported"] is False
    assert "linux" in result["reason"]


def test_validate_profile_supported_paths():
    assert sanitizers.validate_profile("asan-ubsan", platform="darwin")["supported"]
    assert sanitizers.validate_profile("msan", platform="linux")["supported"]
    assert sanitizers.validate_profile("tsan", platform="linux")["supported"]


def test_validate_profile_unknown_platform_unsupported():
    result = sanitizers.validate_profile("asan-ubsan", platform="plan9")
    assert result["supported"] is False


def test_check_combination_rejects_conflicting_sanitizers():
    with pytest.raises(ValidationError):
        # asan-ubsan + tsan both inject address/thread instrumentation.
        sanitizers.check_combination(["asan-ubsan", "msan", "tsan"])
    ok = sanitizers.check_combination(["asan-ubsan", "cfi"])
    assert ok["compatible"] is True


def test_profiles_record_flags_and_runtime_provenance():
    p = sanitizers.get_profile("asan-ubsan")
    assert "-fsanitize=address,undefined" in p.compile_flags
    assert "ASAN_OPTIONS" in p.runtime_env


# --- multi-sanitizer report triage -------------------------------------------

ASAN_OOB = """\
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000d15 at pc 0x00010a2b3c4d bp 0x7ffee1234560 sp 0x7ffee1234558
READ of size 1 at 0x602000000d15 thread T0
    #0 0x10a2b3c4c in decode_scanline decode.c:112:9
SUMMARY: AddressSanitizer: heap-buffer-overflow decode.c:112:9 in decode_scanline
"""

TSAN_RACE = """\
==================
WARNING: ThreadSanitizer: data race (pid=4242)
  Read of size 4 at 0x7f0000000001 by thread T1:
    #0 0x000010a4 in worker_tick tasks.c:88
SUMMARY: ThreadSanitizer: data race
==================
"""

MSAN_UNINIT = """\
==7==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x420 in parse_header header.c:31
SUMMARY: MemorySanitizer: use-of-uninitialized-value
"""

LSAN_LEAK = """\
==9==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0x11 in allocate pool.c:12
SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).
"""

UBSAN_SHIFT = """\
p.c:10:5: runtime error: shift exponent 64 is too large for 32-bit type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior p.c:10:5
"""


def test_detect_sanitizers_identifies_kinds():
    assert sanitizers.detect_sanitizers(ASAN_OOB) == ["address"]
    assert sanitizers.detect_sanitizers(TSAN_RACE) == ["thread"]
    assert sanitizers.detect_sanitizers(MSAN_UNINIT) == ["memory"]
    assert sanitizers.detect_sanitizers(UBSAN_SHIFT) == ["undefined-behavior"]


def test_violation_class_is_comparable_across_profiles():
    assert sanitizers.violation_class(ASAN_OOB) == "BUFFER_OVERFLOW"
    assert sanitizers.violation_class(TSAN_RACE) == "DATA_RACE"
    assert sanitizers.violation_class(MSAN_UNINIT) == "UNINITIALIZED_READ"
    assert sanitizers.violation_class(LSAN_LEAK) == "MEMORY_LEAK"
    assert sanitizers.violation_class(UBSAN_SHIFT) == "UNDEFINED_BEHAVIOR"


def test_dedup_signature_namespaces_by_sanitizer_class():
    a = sanitizers.dedup_signature(ASAN_OOB, module="ImageIO")
    t = sanitizers.dedup_signature(TSAN_RACE, module="ImageIO")
    m = sanitizers.dedup_signature(MSAN_UNINIT, module="ImageIO")
    # Different sanitizer classes never collapse together...
    assert len({a, t, m}) == 3
    # ...and the same finding yields the same signature (stable dedup).
    assert a == sanitizers.dedup_signature(
        ASAN_OOB.replace("0x602000000d15", "0x999900000001"), module="ImageIO")


def test_triage_report_normalizes_fields():
    triage = sanitizers.triage_report(TSAN_RACE, module="libX")
    assert triage["sanitizers"] == ["thread"]
    assert triage["violation_class"] == "DATA_RACE"
    assert triage["classification"]  # never empty
    assert triage["top_frames"]


def test_compare_findings_groups_equivalents_keeps_classes_apart():
    findings = [
        {**sanitizers.triage_report(ASAN_OOB), "profile": "asan-ubsan"},
        {**sanitizers.triage_report(ASAN_OOB), "profile": "cfi"},
        {**sanitizers.triage_report(TSAN_RACE), "profile": "tsan"},
    ]
    out = sanitizers.compare_findings(findings)
    assert out["total"] == 3
    assert out["by_violation_class"] == {"BUFFER_OVERFLOW": 2,
                                         "DATA_RACE": 1}
    groups = out["equivalence_groups"]
    overflow_sig = [sig for sig in groups if "BUFFER_OVERFLOW" in sig][0]
    assert len(groups[overflow_sig]) == 2
    assert any(label.startswith("asan-ubsan:")
               for label in groups[overflow_sig])
    assert any(label.startswith("cfi:") for label in groups[overflow_sig])
    race_sig = [sig for sig in groups if "DATA_RACE" in sig][0]
    assert groups[race_sig] == ["tsan:" + race_sig]


# --- campaign provenance / fail-closed validation -----------------------------

def _corpus(workspace, target_id):
    store = CorpusStore(workspace)
    corpus = store.create(f"profile-{target_id}", target=target_id)
    store.add_bytes(corpus, b"\x00", origin="seed")
    return corpus.id


def test_session_records_sanitizer_profile_provenance(workspace):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="prof", seed=1)
    engine = FuzzEngine(workspace)
    session = engine.create(
        experiment_id=exp.id, target="mock:parser",
        corpus_id=_corpus(workspace, "mock:parser"), seed=1, workers=1,
        max_cases=4, duration_s=None, sanitizer_profile="asan-ubsan")
    assert session.sanitizer_profile == "asan-ubsan"
    assert session.stats()["sanitizer_profile"] == "asan-ubsan"


def test_session_rejects_unusable_profile_before_campaign(workspace):
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="prof-bad", seed=1)
    engine = FuzzEngine(workspace)
    import sys
    unsupported = "msan" if sys.platform == "darwin" else "nonexistent-x"
    with pytest.raises(StateError):
        engine.create(
            experiment_id=exp.id, target="mock:parser",
            corpus_id=_corpus(workspace, "mock:parser"), seed=1, workers=1,
            max_cases=4, duration_s=None, sanitizer_profile=unsupported)


# --- build.sh mirrors profiles and fails closed -------------------------------

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]


def test_build_sh_rejects_unknown_profile():
    import subprocess
    r = subprocess.run(
        ["bash", str(REPO / "tools" / "harness" / "build.sh"),
         "--sanitizer", "bogus", "selftest"], capture_output=True, timeout=30)
    assert r.returncode == 2
    assert b"unknown sanitizer profile" in r.stderr


def test_build_sh_fails_closed_for_unsupported_platform_combo():
    import subprocess
    import sys
    if sys.platform == "linux":
        pytest.skip("msan is supported on linux")
    r = subprocess.run(
        ["bash", str(REPO / "tools" / "harness" / "build.sh"),
         "--sanitizer", "msan", "selftest"], capture_output=True, timeout=30)
    assert r.returncode == 4
    assert b"not supported on" in r.stderr
