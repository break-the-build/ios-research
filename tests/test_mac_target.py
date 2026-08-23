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
from ios_research.targets.base import Outcome
from ios_research.targets.mac import MacFuzzTarget, MAC_FRAMEWORKS


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


# --- opt-in native end-to-end (requires macOS clang + fuzzer runtime) -------

def _has_fuzzer_toolchain() -> bool:
    if sys.platform != "darwin" or shutil.which("clang") is None:
        return False
    # Probe whether -fsanitize=fuzzer links on this toolchain.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "p.c"
        src.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*x,size_t n){return 0;}\n")
        out = Path(d) / "p"
        try:
            r = subprocess.run(
                ["clang", "-fsanitize=fuzzer,address", str(src), "-o", str(out)],
                capture_output=True, timeout=60)
            return r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


@pytest.mark.skipif(not _has_fuzzer_toolchain(),
                    reason="requires macOS clang with libFuzzer/ASan runtime")
def test_native_harness_builds_and_runs(tmp_path):
    """End-to-end: build the real ImageIO harness and run one input through it.

    Success-criteria smoke test. We do not assert a crash occurs (that depends
    on the OS build), only that the harness builds, runs, and produces a
    normalized ExecResult through the real target path.
    """
    build = REPO / "tools" / "harness" / "build.sh"
    env = dict(os.environ)
    env["CC"] = "clang"
    r = subprocess.run(["bash", str(build), "imageio"],
                       capture_output=True, env=env, timeout=180)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    binary = REPO / "tools" / "harness" / "build" / "imageio_fuzzer"
    assert binary.is_file()

    t = MacFuzzTarget("imageio", harness=str(binary), timeout_s=30)
    assert t.available()
    res = t.execute(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert res.outcome in Outcome.ALL
    if res.outcome == Outcome.CRASH:
        assert res.diagnostics is not None
        assert res.diagnostics.signature.startswith("asan_")
