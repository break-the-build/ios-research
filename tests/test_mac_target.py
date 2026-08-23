"""Tests for the macOS in-process fuzzing target and ASan report parsing.

The parser (:mod:`ios_research.targets.asan`) is exercised against real-shaped
sanitizer output and requires no toolchain, so it runs everywhere. The native
end-to-end build/run test is opt-in and skipped unless a macOS clang with the
fuzzer runtime is available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ios_research.targets import asan, create, is_registered, list_targets
import ios_research.targets as target_registry
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.targets import _mac_seeds
from ios_research.targets.base import Outcome
from ios_research.targets.mac import (
    MacFuzzTarget, MAC_FRAMEWORKS, _decode_status, _decode_statuses)


def _write_stub(path, *, stdout="", stderr="", code=0):
    """Write an executable stub harness that emits fixed output and exit code."""
    lines = ["#!/usr/bin/env bash"]
    if stdout:
        lines.append(f'printf "%b" {shlex_quote(stdout)}')
    if stderr:
        lines.append(f'printf "%b" {shlex_quote(stderr)} >&2')
    lines.append(f"exit {code}")
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)


def shlex_quote(s):
    import shlex
    return shlex.quote(s)


def _asan_clang() -> str | None:
    """Return a clang whose ASan runtime works for the standalone driver.

    The Command Line Tools clang ships an ASan runtime that CHECK-fails when the
    harness dlopens a system framework, so prefer a full-Xcode / Homebrew clang.
    Returns None when no suitable toolchain is available (skip the test).
    """
    if sys.platform != "darwin" or shutil.which("clang") is None:
        return None
    candidates = []
    xcode = Path("/Applications/Xcode.app/Contents/Developer/Toolchains/"
                 "XcodeDefault.xctoolchain/usr/bin/clang")
    if xcode.is_file():
        candidates.append(str(xcode))
    if shutil.which("brew"):
        try:
            prefix = subprocess.run(["brew", "--prefix", "llvm"],
                                    capture_output=True, timeout=15)
            p = Path(prefix.stdout.decode().strip()) / "bin" / "clang"
            if p.is_file():
                candidates.append(str(p))
        except (OSError, subprocess.TimeoutExpired):
            pass
    return candidates[0] if candidates else None


REPO = Path(__file__).resolve().parents[1]

# --- real-shaped sanitizer reports -----------------------------------------

HEAP_OOB_READ = """\
==54321==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000d15 at pc 0x00010a2b3c4d bp 0x7ffee1234560 sp 0x7ffee1234558
READ of size 1 at 0x602000000d15 thread T0
    #0 0x10a2b3c4c in decode_scanline decode.c:112:9
    #1 0x7fff2038a4b1 in CGImageSourceCreateImageAtIndex (ImageIO:x86_64+0x2a4b1)
    #2 0x10a2b1000 in LLVMFuzzerTestOneInput mac_fuzz_harness.c:200:5
SUMMARY: AddressSanitizer: heap-buffer-overflow decode.c:112:9 in decode_scanline
"""

HEAP_OOB_WRITE = """\
==11==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x611000000100 at pc 0x000104ffaa10 bp 0x7ffee0 sp 0x7ffed8
WRITE of size 8 at 0x611000000100 thread T0
    #0 0x104ffaa0f in store_pixels render.c:44
    #1 0x7fff20111222 in CGImageSourceCreateWithData (ImageIO:x86_64+0x11222)
SUMMARY: AddressSanitizer: heap-buffer-overflow in store_pixels
"""

SEGV_NULL = """\
==99==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0001020304 bp 0x7f sp 0x7e T0)
==99==The signal is caused by a READ memory access.
==99==Hint: address points to the zero page.
    #0 0x1020304 in handle_dispatch dispatch.c:9
    #1 0x7fff5000 in AudioFileOpen (AudioToolbox:x86_64+0x5000)
SUMMARY: AddressSanitizer: SEGV dispatch.c:9 in handle_dispatch
"""

USE_AFTER_FREE = """\
==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x00010aa0 bp 0x7f sp 0x7e
READ of size 4 at 0x602000000010 thread T0
    #0 0x10aa0 in use_node node.c:88
    #1 0x7fff33 in CFRelease (CoreFoundation:x86_64+0x33)
SUMMARY: AddressSanitizer: heap-use-after-free in use_node
"""

UBSAN_OVERFLOW = """\
render.c:51:19: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x104abc in compute_stride render.c:51:19
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow render.c:51:19
"""

# UBSan fires before ASan on an out-of-bounds store (undefined-behavior summary).
UBSAN_WRITE = """\
harness.c:229:9: runtime error: store to address 0x602000000130 with insufficient space for an object of type 'uint8_t'
0x602000000130: note: pointer points here
    #0 0x1028a8b24 in LLVMFuzzerTestOneInput harness.c:229:9
    #1 0x1028a8d1c in main harness.c:308
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior harness.c:229:9
"""

UBSAN_LOAD = """\
p.c:10:5: runtime error: load of address 0x602000000200 with insufficient space for an object of type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior p.c:10:5
"""


# --- parser tests ----------------------------------------------------------

def test_is_crash_report_detects_asan():
    assert asan.is_crash_report(HEAP_OOB_READ)
    assert asan.is_crash_report(UBSAN_OVERFLOW)
    assert not asan.is_crash_report("")
    assert not asan.is_crash_report("just some normal stdout\n")


def test_parse_heap_oob_read():
    d = asan.parse(HEAP_OOB_READ, module="ImageIO")
    assert d.classification_hint == "OUT_OF_BOUNDS_READ"
    assert d.access_type == "read"
    assert d.faulting_address == "0x0000602000000d15"
    assert d.instruction_address == "0x000000010a2b3c4d"
    assert d.exception_type == "EXC_BAD_ACCESS"
    assert d.signal == "SIGSEGV"
    assert any("decode_scanline" in f for f in d.stack_trace)
    assert "ImageIO" in d.modules
    assert d.signature.startswith("asan_")


def test_parse_heap_oob_write_access_type():
    d = asan.parse(HEAP_OOB_WRITE, module="ImageIO")
    assert d.classification_hint == "OUT_OF_BOUNDS_WRITE"
    assert d.access_type == "write"
    assert d.faulting_address == "0x0000611000000100"


def test_parse_segv_null_is_null_deref():
    d = asan.parse(SEGV_NULL, module="AudioToolbox")
    assert d.classification_hint == "NULL_DEREFERENCE"
    assert d.faulting_address == "0x0000000000000000"
    assert d.access_type == "read"
    assert "AudioToolbox" in d.modules


def test_parse_use_after_free():
    d = asan.parse(USE_AFTER_FREE, module="CoreFoundation")
    assert d.classification_hint == "USE_AFTER_FREE"
    assert any("use_node" in f for f in d.stack_trace)


def test_parse_ubsan_integer_error():
    d = asan.parse(UBSAN_OVERFLOW, module="ImageIO")
    assert d.classification_hint == "INTEGER_ERROR"
    assert d.exception_type == "EXC_ARITHMETIC"


def test_parse_ubsan_write_recovers_oob_write():
    # UBSan-only report (no ASan kind) must still classify + get the address.
    d = asan.parse(UBSAN_WRITE, module="SelfTest")
    assert d.classification_hint == "OUT_OF_BOUNDS_WRITE"
    assert d.access_type == "write"
    assert d.faulting_address == "0x0000602000000130"


def test_parse_ubsan_load_recovers_oob_read():
    d = asan.parse(UBSAN_LOAD, module="SelfTest")
    assert d.classification_hint == "OUT_OF_BOUNDS_READ"
    assert d.access_type == "read"
    assert d.faulting_address == "0x0000602000000200"


@pytest.mark.parametrize("msg,expected", [
    ("load of null pointer of type 'int'", "NULL_DEREFERENCE"),
    ("member access within null pointer of type 'S'", "NULL_DEREFERENCE"),
    ("division by zero", "INTEGER_ERROR"),
    ("shift exponent 64 is too large", "INTEGER_ERROR"),
    ("misaligned address 0x1 for type 'int'", "OUT_OF_BOUNDS_READ"),
    ("applying non-zero offset to non-null pointer", "UNKNOWN"),
])
def test_ubsan_message_classification(msg, expected):
    report = f"x.c:1:1: runtime error: {msg}\nSUMMARY: UndefinedBehaviorSanitizer: undefined-behavior x.c:1:1\n"
    assert asan.parse(report).classification_hint == expected


def test_parse_is_deterministic_and_signature_stable():
    a = asan.parse(HEAP_OOB_READ, module="ImageIO")
    b = asan.parse(HEAP_OOB_READ, module="ImageIO")
    assert a.to_dict() == b.to_dict()
    # different crash -> different signature
    c = asan.parse(USE_AFTER_FREE, module="ImageIO")
    assert a.signature != c.signature


def test_parse_unknown_report_is_defensive():
    d = asan.parse("AddressSanitizer: some-future-check went wrong")
    assert d.classification_hint  # never empty
    assert d.signature.startswith("asan_")


def test_parse_to_dict_shape_matches_contract():
    d = asan.parse(HEAP_OOB_READ, module="ImageIO")
    keys = set(d.to_dict())
    assert {"exception_type", "signal", "faulting_address", "stack_trace",
            "modules", "signature", "classification_hint"} <= keys


# --- target registration / metadata ----------------------------------------

def test_mac_targets_registered():
    ids = {t["id"] for t in list_targets()}
    for key in MAC_FRAMEWORKS:
        assert f"mac:{key}" in ids
        assert is_registered(f"mac:{key}")


def test_mac_target_is_not_mock():
    t = create("mac:imageio")
    assert t.mock is False
    d = t.describe()
    assert d["framework"] == "ImageIO"
    assert d["entry_point"] == "CGImageSourceCreateWithData"
    assert "available" in d


def test_coregraphics_entry_point_drives_a_real_parser():
    """#27: the entry point must open the full PDF parser (and render), not
    merely wrap bytes — CGDataProviderCreateWithCFData accepted 100% of inputs
    because it never decodes anything."""
    d = create("mac:coregraphics").describe()
    assert d["entry_point"] == "CGPDFDocumentCreateWithProvider"
    assert "PDF" in d["description"]


def test_mac_target_missing_harness_is_abnormal(monkeypatch):
    monkeypatch.delenv("IOS_RESEARCH_MAC_HARNESS", raising=False)
    t = MacFuzzTarget("imageio", harness="/nonexistent/harness/binary")
    assert t.available() is False
    res = t.execute(b"\x89PNG\r\n\x1a\n")
    assert res.outcome == Outcome.ABNORMAL
    assert "not built" in res.detail


def test_mac_target_runs_stub_harness(tmp_path):
    """A fake harness that emits a real ASan report -> CRASH with diagnostics."""
    stub = tmp_path / "imageio_fuzzer"
    report = HEAP_OOB_READ.replace("\n", "\\n")
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%b" "{report}" >&2\n'
        "exit 99\n")
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub))
    assert t.available() is True
    res = t.execute(b"any-bytes")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics is not None
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_READ"
    assert "ImageIO" in res.diagnostics.modules


def test_mac_target_clean_exit_is_accepted(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text("#!/usr/bin/env bash\nexit 0\n")
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub))
    res = t.execute(b"valid-input")
    assert res.outcome == Outcome.ACCEPTED


# --- decode-status protocol (#16) ------------------------------------------

def test_decode_status_parsers():
    out = "RUN 0\nDONE 0 decoded\nRUN 1\nDONE 1 rejected\n"
    assert _decode_statuses(out) == ["decoded", "rejected"]
    assert _decode_status(out, 0) == "decoded"
    assert _decode_status(out, 1) == "rejected"
    assert _decode_status(out, 5) is None
    assert _decode_statuses("no markers here") == []


def test_mac_target_decoded_marker_is_accepted(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    _write_stub(stub, stdout="RUN 0\nDONE 0 decoded\n", code=0)
    res = MacFuzzTarget("imageio", harness=str(stub)).execute(b"img")
    assert res.outcome == Outcome.ACCEPTED


def test_mac_target_rejected_marker_is_rejected(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    _write_stub(stub, stdout="RUN 0\nDONE 0 rejected\n", code=0)
    res = MacFuzzTarget("imageio", harness=str(stub)).execute(b"junk")
    assert res.outcome == Outcome.REJECTED


# --- batched execution (#15) -----------------------------------------------

def test_execute_batch_maps_per_input_status(tmp_path):
    # Stub emits a DONE line for each of the 3 inputs it receives ($#).
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'i=0\nfor f in "$@"; do echo "RUN $i"; '
        'if [ $((i % 2)) -eq 0 ]; then echo "DONE $i decoded"; '
        'else echo "DONE $i rejected"; fi; i=$((i+1)); done\nexit 0\n')
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub))
    results = t.execute_batch([b"a", b"b", b"c"])
    assert [r.outcome for r in results] == [
        Outcome.ACCEPTED, Outcome.REJECTED, Outcome.ACCEPTED]


def test_execute_batch_single_input_uses_execute(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    _write_stub(stub, stdout="RUN 0\nDONE 0 rejected\n", code=0)
    t = MacFuzzTarget("imageio", harness=str(stub))
    results = t.execute_batch([b"only"])
    assert len(results) == 1 and results[0].outcome == Outcome.REJECTED


def test_execute_batch_falls_back_on_crash(tmp_path):
    # A crash aborts the batch; per-input fallback re-runs each input, and the
    # stub (which always reports a crash) yields CRASH for every input.
    stub = tmp_path / "imageio_fuzzer"
    report = HEAP_OOB_READ.replace("\n", "\\n")
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f'printf "%b" "{report}" >&2\nexit 99\n')
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub))
    results = t.execute_batch([b"a", b"b"])
    assert len(results) == 2
    assert all(r.outcome == Outcome.CRASH for r in results)


def test_execute_batch_no_markers_falls_back(tmp_path):
    # libFuzzer-style build: exit 0, no per-input markers -> safe per-input path.
    stub = tmp_path / "imageio_fuzzer"
    _write_stub(stub, stdout="", code=0)
    t = MacFuzzTarget("imageio", harness=str(stub))
    results = t.execute_batch([b"a", b"b"])
    assert [r.outcome for r in results] == [Outcome.ACCEPTED, Outcome.ACCEPTED]


def test_execute_batch_missing_harness(tmp_path):
    t = MacFuzzTarget("imageio", harness="/nonexistent")
    results = t.execute_batch([b"a", b"b"])
    assert all(r.outcome == Outcome.ABNORMAL for r in results)


# --- format-aware seeds & structure mutation (#17) -------------------------

@pytest.mark.parametrize("key", sorted(MAC_FRAMEWORKS))
def test_mac_seeds_present(key):
    t = create(f"mac:{key}")
    seeds = t.seeds()
    assert seeds and all(isinstance(s, bytes) and s for s in seeds)


def test_png_structure_mutation_changes_png():
    import random
    png = _mac_seeds.seeds("imageio")[0]
    assert png.startswith(b"\x89PNG")
    rng = random.Random(0)
    changed = False
    for _ in range(20):
        m = _mac_seeds.structure_mutate("imageio", png, rng)
        assert m is not None and isinstance(m, bytes)
        if m != png:
            changed = True
    assert changed


def test_structure_mutation_non_png_returns_none():
    import random
    assert _mac_seeds.structure_mutate("imageio", b"not-a-png", random.Random(0)) is None


def test_target_structure_mutate_hook_delegates():
    import random
    t = create("mac:imageio")
    png = t.seeds()[0]
    out = t.structure_mutate(png, random.Random(1))
    assert out is not None and out.startswith(b"\x89PNG")


# --- campaign runner (#17) -------------------------------------------------

def _load_campaign():
    sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
    import importlib
    return importlib.import_module("run")


def test_campaign_runner_against_stub(tmp_path, monkeypatch):
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'i=0\nfor f in "$@"; do echo "DONE $i decoded"; i=$((i+1)); done\nexit 0\n')
    stub.chmod(0o755)
    monkeypatch.setenv("IOS_RESEARCH_MAC_HARNESS", str(stub))
    run = _load_campaign()
    out = run.run_campaign("mac:imageio", cases=10, seed=1, batch=4)
    assert out is not None
    summary, crash_inputs = out
    assert summary["cases"] == 10
    assert summary["counts"]["accepted"] == 10
    assert summary["total_crashes"] == 0


def test_instrumented_driver_exports_sancov_evidence(workspace, tmp_path):
    """The native driver adapter retains measured guard evidence in a corpus."""
    stub = tmp_path / "instrumented_driver"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'printf "IOSR_SANCOV_V1\\n17\\n3\\n" > "$IOS_RESEARCH_SANCOV_FILE"\n'
        'printf "RUN 0\\nDONE 0 decoded\\n"\n')
    stub.chmod(0o755)
    target_id = "test:instrumented-mac"
    target_registry.register(target_id,
                             lambda: MacFuzzTarget("imageio", harness=str(stub)))
    try:
        exp = ExperimentStore(workspace).create(
            target=target_id, device="mock:device", os_version="17.0",
            config_hash="sancov", seed=4)
        store = CorpusStore(workspace)
        corpus = store.create("sancov", target=target_id)
        store.add_bytes(corpus, b"seed", origin="seed")
        session = FuzzEngine(workspace).create(
            experiment_id=exp.id, target=target_id, corpus_id=corpus.id,
            seed=4, workers=1, max_cases=3, duration_s=None)
        engine = FuzzEngine(workspace)
        session = engine.advance(session)
        assert session.stats()["coverage"]["available"] is True
        assert session.coverage_features == [
            "sancov:mac:imageio:guard:17", "sancov:mac:imageio:guard:3"]
        retained = [tc for tc in store.get(corpus.id).testcases
                    if tc.get("coverage_new_features")]
        assert retained and retained[0]["coverage_features"] == session.coverage_features
    finally:
        target_registry._REGISTRY.pop(target_id, None)


def test_campaign_runner_parallel_workers(tmp_path, monkeypatch):
    # Same deterministic result with >1 worker; exercises the thread-pool path.
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'i=0\nfor f in "$@"; do echo "DONE $i decoded"; i=$((i+1)); done\nexit 0\n')
    stub.chmod(0o755)
    monkeypatch.setenv("IOS_RESEARCH_MAC_HARNESS", str(stub))
    run = _load_campaign()
    serial = run.run_campaign("mac:imageio", cases=40, seed=1, batch=4, workers=1)
    parallel = run.run_campaign("mac:imageio", cases=40, seed=1, batch=4, workers=4)
    assert serial[0]["counts"] == parallel[0]["counts"]
    assert parallel[0]["cases"] == 40


# --- in-process libFuzzer engine (#20) -------------------------------------

def _write_libfuzzer_stub(path):
    """A stub that emulates a libFuzzer binary across its three invocations:
    -help, a corpus/fork run (writes crash artifacts), and single-input re-run.
    """
    path.write_text(r'''#!/usr/bin/env bash
case "$1" in
  -help=1) echo "libFuzzer flags: -runs= -max_total_time= -fork="; exit 0 ;;
esac
prefix=""; corpus=""; is_run=0
for a in "$@"; do
  case "$a" in
    -artifact_prefix=*) prefix="${a#-artifact_prefix=}"; is_run=1 ;;
    -*) ;;
    *) corpus="$a" ;;
  esac
done
if [ "$is_run" = "1" ]; then
  printf 'OOBcrashinput' > "${prefix}crash-aaaa"
  printf 'UAFcrashinput' > "${prefix}crash-bbbb"
  echo "stat::number_of_executed_units: 54321"
  exit 0
fi
data=$(cat "$corpus" 2>/dev/null)
case "$data" in
  *OOB*) printf '%b' "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010 at pc 0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602000000010 thread T0\n    #0 0x1 in decode a.c:1\n" >&2; exit 99 ;;
  *UAF*) printf '%b' "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000020 at pc 0x1 bp 0x2 sp 0x3\nREAD of size 4 at 0x602000000020 thread T0\n    #0 0x1 in use b.c:2\n" >&2; exit 99 ;;
  *) exit 0 ;;
esac
''')
    path.chmod(0o755)


def test_is_libfuzzer_detection(tmp_path):
    lf = tmp_path / "imageio_fuzzer"
    _write_libfuzzer_stub(lf)
    assert MacFuzzTarget("imageio", harness=str(lf)).is_libfuzzer() is True

    drv = tmp_path / "driver_fuzzer"
    _write_stub(drv, stdout="RUN 0\nDONE 0 rejected\n", code=0)
    t = MacFuzzTarget("imageio", harness=str(drv))
    t.prepare()
    assert t.is_libfuzzer() is False


def test_fuzz_corpus_collects_and_dedups(tmp_path):
    lf = tmp_path / "imageio_fuzzer"
    _write_libfuzzer_stub(lf)
    t = MacFuzzTarget("imageio", harness=str(lf))
    unique, stats = t.fuzz_corpus([b"seed"], runs=1000, workers=2)
    classes = sorted(res.diagnostics.classification_hint for _d, res in unique)
    assert classes == ["OUT_OF_BOUNDS_READ", "USE_AFTER_FREE"]
    assert stats["runs"] == 54321
    assert stats["unique_crashes"] == 2
    assert all(res.outcome == Outcome.CRASH for _d, res in unique)


def test_fuzz_corpus_rejects_non_libfuzzer(tmp_path):
    drv = tmp_path / "imageio_fuzzer"
    _write_stub(drv, stdout="RUN 0\nDONE 0 rejected\n", code=0)
    t = MacFuzzTarget("imageio", harness=str(drv))
    unique, stats = t.fuzz_corpus([b"seed"], runs=10)
    assert unique == []
    assert "not a libFuzzer build" in stats["error"]


def test_campaign_auto_selects_libfuzzer(tmp_path, monkeypatch):
    lf = tmp_path / "imageio_fuzzer"
    _write_libfuzzer_stub(lf)
    monkeypatch.setenv("IOS_RESEARCH_MAC_HARNESS", str(lf))
    run = _load_campaign()
    summary, crash_inputs = run.run_campaign(
        "mac:imageio", cases=0, seed=1, batch=8, workers=2, engine="auto")
    assert summary["engine"] == "libfuzzer"
    assert summary["unique_crashes"] == 2
    assert len(crash_inputs) == 2


# --- self-test target (real-crash pipeline validation) ---------------------

def test_selftest_target_registered_and_seeds():
    assert is_registered("mac:selftest")
    t = create("mac:selftest")
    assert t.mock is False
    markers = b"".join(t.seeds())
    assert b"OOB" in markers and b"WRT" in markers and b"UAF" in markers


def _selftest_clang() -> str | None:
    # The self-test does not dlopen a framework, so any macOS clang with an ASan
    # runtime works (including Command Line Tools).
    if sys.platform != "darwin" or shutil.which("clang") is None:
        return None
    return _asan_clang() or "clang"


@pytest.mark.skipif(_selftest_clang() is None,
                    reason="requires a macOS clang with an ASan runtime")
def test_selftest_real_crash_pipeline(tmp_path):
    """Build the self-test harness and drive real ASan crashes through the target.

    Validates the real-crash path (issue #10) on genuine data: three distinct
    classifications from real ASan/UBSan reports, and a clean input accepted.
    """
    build = REPO / "tools" / "harness" / "build.sh"
    env = dict(os.environ)
    env["CC"] = _selftest_clang()
    r = subprocess.run(["bash", str(build), "selftest"],
                       capture_output=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    binary = REPO / "tools" / "harness" / "build" / "selftest_fuzzer"
    assert binary.is_file()

    t = MacFuzzTarget("selftest", harness=str(binary), timeout_s=30)
    assert t.available()

    expect = {
        b"OOB" + b"." * 20: "OUT_OF_BOUNDS_READ",
        b"WRT" + b"." * 20: "OUT_OF_BOUNDS_WRITE",
        b"UAF" + b"." * 20: "USE_AFTER_FREE",
    }
    sigs = set()
    for payload, cls in expect.items():
        res = t.execute(payload)
        if res.outcome == Outcome.ABNORMAL and "CHECK failed" in res.detail:
            pytest.skip("toolchain ASan runtime unusable")
        assert res.outcome == Outcome.CRASH, res.detail
        assert res.diagnostics.classification_hint == cls
        assert res.diagnostics.faulting_address
        sigs.add(res.diagnostics.signature)
    assert len(sigs) == 3  # distinct signatures -> dedup works

    clean = t.execute(b"clean-input-no-marker")
    assert clean.outcome in (Outcome.ACCEPTED, Outcome.REJECTED)

    # Batched: the crash-in-batch fallback still attributes each crash.
    results = t.execute_batch(list(expect.keys()) + [b"clean"])
    crash_results = [r for r in results if r.outcome == Outcome.CRASH]
    assert len(crash_results) == 3


def test_mac_target_nonzero_without_report_is_abnormal(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text("#!/usr/bin/env bash\necho 'boom' >&2\nexit 3\n")
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub))
    res = t.execute(b"x")
    assert res.outcome == Outcome.ABNORMAL


def test_mac_target_timeout(tmp_path):
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text("#!/usr/bin/env bash\nsleep 5\n")
    stub.chmod(0o755)
    t = MacFuzzTarget("imageio", harness=str(stub), timeout_s=0.3)
    res = t.execute(b"x")
    assert res.outcome == Outcome.TIMEOUT


# --- opt-in native end-to-end (requires macOS with a working ASan clang) ----


def _fuzzer_clang() -> str | None:
    """A clang that links -fsanitize=fuzzer (Apple ships no fuzzer runtime)."""
    cc = _asan_clang()
    if cc is None:
        return None
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "p.c"
        src.write_text("#include <stdint.h>\n#include <stddef.h>\n"
                       "int LLVMFuzzerTestOneInput(const uint8_t*x,size_t n){"
                       "return 0;}\n")
        try:
            r = subprocess.run([cc, "-fsanitize=fuzzer,address",
                                str(src), "-o", str(Path(d) / "p")],
                               capture_output=True, timeout=90)
            return cc if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None


@pytest.mark.skipif(_fuzzer_clang() is None,
                    reason="requires a clang with the libFuzzer runtime "
                           "(e.g. Homebrew LLVM; Apple ships none)")
def test_native_libfuzzer_finds_real_crashes(tmp_path):
    """End-to-end libFuzzer engine (#20): build --libfuzzer selftest and let the
    in-process persistent loop discover real ASan crashes, normalized via asan."""
    build = REPO / "tools" / "harness" / "build.sh"
    env = dict(os.environ)
    env["CC"] = _fuzzer_clang()
    r = subprocess.run(["bash", str(build), "--libfuzzer", "selftest"],
                       capture_output=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    binary = REPO / "tools" / "harness" / "build" / "selftest_fuzzer"
    t = MacFuzzTarget("selftest", harness=str(binary), timeout_s=30)
    assert t.is_libfuzzer()
    unique, stats = t.fuzz_corpus(t.seeds(), runs=200_000,
                                  max_total_time=20, workers=2)
    assert unique, "libFuzzer found no crashes on the self-test target"
    for _data, res in unique:
        assert res.outcome == Outcome.CRASH
        assert res.diagnostics.signature.startswith("asan_")


@pytest.mark.skipif(_asan_clang() is None,
                    reason="requires macOS with a full-Xcode/Homebrew ASan clang")
def test_native_coregraphics_rejects_junk(tmp_path):
    """#27 end-to-end: the rebuilt CoreGraphics driver must *reject* non-PDF
    bytes (real parser signal) instead of accepting every input."""
    build = REPO / "tools" / "harness" / "build.sh"
    env = dict(os.environ)
    env["CC"] = _asan_clang()
    env["DEVELOPER_DIR"] = "/Applications/Xcode.app/Contents/Developer"
    r = subprocess.run(["bash", str(build), "coregraphics"],
                       capture_output=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    binary = REPO / "tools" / "harness" / "build" / "coregraphics_fuzzer"
    assert binary.is_file()

    t = MacFuzzTarget("coregraphics", harness=str(binary), timeout_s=30)
    junk = t.execute(b"definitely-not-a-pdf")
    if junk.outcome == Outcome.ABNORMAL and "CHECK failed" in junk.detail:
        pytest.skip("toolchain ASan runtime aborts on dlopen (init CHECK)")
    assert junk.outcome == Outcome.REJECTED

    # A well-formed minimal PDF still parses (accepted) or is rejected cleanly;
    # either way it must not be reported as a sanitizer finding.
    pdf = t.execute(t.seeds()[1])
    assert pdf.outcome in (Outcome.ACCEPTED, Outcome.REJECTED)


@pytest.mark.skipif(_asan_clang() is None,
                    reason="requires macOS with a full-Xcode/Homebrew ASan clang")
def test_native_harness_builds_and_runs(tmp_path):
    """End-to-end: build the real ImageIO driver and run inputs through it.

    Success-criteria smoke test using the default standalone-driver mode (no
    libFuzzer runtime needed). Asserts the harness builds, runs, distinguishes
    decoded from rejected on real ImageIO, and produces normalized results.
    """
    build = REPO / "tools" / "harness" / "build.sh"
    env = dict(os.environ)
    env["CC"] = _asan_clang()
    env["DEVELOPER_DIR"] = "/Applications/Xcode.app/Contents/Developer"
    r = subprocess.run(["bash", str(build), "imageio"],
                       capture_output=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    binary = REPO / "tools" / "harness" / "build" / "imageio_fuzzer"
    assert binary.is_file()

    t = MacFuzzTarget("imageio", harness=str(binary), timeout_s=30)
    assert t.available()

    # A valid seed must decode; guard against a broken ASan runtime by skipping
    # if the harness aborts during sanitizer init rather than actually running.
    valid = t.execute(t.seeds()[0])
    if valid.outcome == Outcome.ABNORMAL and "CHECK failed" in valid.detail:
        pytest.skip("toolchain ASan runtime aborts on dlopen (init CHECK)")
    assert valid.outcome == Outcome.ACCEPTED

    junk = t.execute(b"definitely-not-an-image")
    assert junk.outcome in (Outcome.REJECTED, Outcome.ACCEPTED)

    # Batch a handful of structure-mutated PNGs; assert normalized results.
    import random
    rng = random.Random(0)
    batch = [t.structure_mutate(t.seeds()[0], rng) or t.seeds()[0]
             for _ in range(8)]
    results = t.execute_batch(batch)
    assert len(results) == 8
    assert all(res.outcome in Outcome.ALL for res in results)
