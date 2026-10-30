"""The Guard Malloc oracle for mac:<framework> targets.

Compiler sanitizers in the harness never check memory accesses inside Apple's
precompiled frameworks, so the default build runs under Guard Malloc and
reports detections as fatal signals (tools/harness/harness_runtime.h). These
tests cover the parser for those reports (sigcrash), their classification as
CRASH (previously ABNORMAL, i.e. lost), the depth metric on DONE lines, the
real-file seed corpus, and the gmalloc build profile. Native tests (opt-in)
build real harnesses and prove detection and depth end to end.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ios_research import sanitizers
from ios_research.errors import ValidationError
from ios_research.targets import _mac_real_seeds, sigcrash
from ios_research.targets.base import Outcome
from ios_research.targets.mac import MacFuzzTarget, _decode_lines

REPO = Path(__file__).resolve().parents[1]
BUILD_SH = REPO / "tools" / "harness" / "build.sh"

REPORT = """RUN 0
IOSR-CRASH signal=SIGSEGV addr=0x0000000150a8c010 pc=0x000000019a14547c access=write
IOSR-FRAME 0 0x000000019a14547c ImageIO+0x1947c _ZN12IIOReadPlugin10copyPixelsEv
IOSR-FRAME 1 0x000000018a7db324 ImageIO+0x164324 CGImageSourceCreateImageAtIndex
IOSR-FRAME 2 0x0000000102044df0 imageio_fuzzer+0xdf0 LLVMFuzzerTestOneInput
IOSR-FRAME 3 0x00000001877484e4 dyld+0x204e4 start
"""


# ---------------- sigcrash: report parsing ----------------

def test_parses_a_guard_malloc_report():
    d = sigcrash.parse(REPORT, module="ImageIO", returncode=-11)
    assert d.signal == "SIGSEGV" and d.exception_type == "EXC_BAD_ACCESS"
    assert d.classification_hint == "OUT_OF_BOUNDS_WRITE" and d.access_type == "write"
    assert d.faulting_address == "0x0000000150a8c010"
    assert d.stack_trace[0] == "ImageIO`_ZN12IIOReadPlugin10copyPixelsEv"
    assert d.modules[0] == "ImageIO" and "dyld" in d.modules
    assert d.signature.startswith("sig_")


def test_signature_ignores_aslr_and_tracks_code_location():
    moved = REPORT.replace("0x0000000150a8c010", "0x0000000160000010").replace("0x00000001", "0x00000002")
    assert sigcrash.parse(moved).signature == sigcrash.parse(REPORT).signature
    other_site = REPORT.replace("copyPixelsEv", "decodeTileEv")
    assert sigcrash.parse(other_site).signature != sigcrash.parse(REPORT).signature


@pytest.mark.parametrize("sig,addr,access,expected", [
    ("SIGSEGV", "0x0000000000000008", "read", "NULL_DEREFERENCE"),
    ("SIGBUS", "0x0000000150a8c010", "read", "OUT_OF_BOUNDS_READ"),
    ("SIGSEGV", "0x0000000150a8c010", "write", "OUT_OF_BOUNDS_WRITE"),
    ("SIGABRT", "0x0000000000000000", "unknown", "ASSERTION"),
    ("SIGTRAP", "0x0000000000000000", "unknown", "ASSERTION"),
    ("SIGFPE", "0x0000000000000000", "unknown", "INTEGER_ERROR"),
])
def test_classification(sig, addr, access, expected):
    text = f"IOSR-CRASH signal={sig} addr={addr} pc=0x1 access={access}\n"
    assert sigcrash.parse(text).classification_hint == expected


def test_signal_without_a_report_still_yields_diagnostics():
    d = sigcrash.parse("", module="AudioToolbox", returncode=-10)
    assert d.signal == "SIGBUS" and d.modules == ["AudioToolbox"] and d.signature


# Darwin numbering on every host: 10 is SIGBUS on macOS but SIGUSR1 on Linux
# (CI caught the host-numbering version on Ubuntu).
@pytest.mark.parametrize("code,name", [(-11, "SIGSEGV"), (139, "SIGSEGV"), (-6, "SIGABRT"),
                                       (-10, "SIGBUS"), (138, "SIGBUS"), (-30, "SIGUSR1"),
                                       (0, ""), (1, ""), (-999, "")])
def test_signal_name(code, name):
    assert sigcrash.signal_name(code) == name


# ---------------- mac target: signal deaths are CRASHes ----------------

def _stub(tmp_path, body: str) -> str:
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text("#!/usr/bin/env bash\n" + body)
    stub.chmod(0o755)
    return str(stub)


def test_signal_death_with_report_is_a_crash(tmp_path):
    body = "".join(f"echo '{line}' >&2\n" for line in REPORT.splitlines()[1:]) + "kill -SEGV $$\n"
    res = MacFuzzTarget("imageio", harness=_stub(tmp_path, body)).execute(b"x")
    assert res.outcome == Outcome.CRASH
    assert res.detail.startswith("IOSR-CRASH signal=SIGSEGV")
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_WRITE"


def test_bare_signal_death_is_a_crash_not_abnormal(tmp_path):
    # The stub dies on the CI host, so use a signal numbered alike on Linux and
    # Darwin (SIGSEGV = 11); SIGBUS is 10 on Darwin but 7 on Linux.
    res = MacFuzzTarget("imageio", harness=_stub(tmp_path, "kill -SEGV $$\n")).execute(b"x")
    assert res.outcome == Outcome.CRASH and res.diagnostics.signal == "SIGSEGV"


def test_ordinary_error_exit_stays_abnormal(tmp_path):
    res = MacFuzzTarget("imageio", harness=_stub(tmp_path, "echo boom >&2\nexit 3\n")).execute(b"x")
    assert res.outcome == Outcome.ABNORMAL


def test_depth_metric_is_parsed_and_reported(tmp_path):
    assert _decode_lines("RUN 0\nDONE 0 decoded pixels=10105\nDONE 1 rejected\n") == [
        ("decoded", "pixels=10105"), ("rejected", "")]
    res = MacFuzzTarget("imageio", harness=_stub(
        tmp_path, "echo 'RUN 0'\necho 'DONE 0 decoded pixels=42'\n")).execute(b"x")
    assert res.outcome == Outcome.ACCEPTED and "pixels=42" in res.detail


def test_batch_reruns_individually_after_a_signal_death(tmp_path):
    # Batch call (several args) dies mid-way; single-input calls succeed.
    body = ('if [ "$#" -gt 1 ]; then echo "RUN 0"; kill -SEGV $$; fi\n'
            'echo "RUN 0"; echo "DONE 0 decoded frames=7"\n')
    results = MacFuzzTarget("imageio", harness=_stub(tmp_path, body)).execute_batch([b"a", b"b", b"c"])
    assert [r.outcome for r in results] == [Outcome.ACCEPTED] * 3
    assert all("frames=7" in r.detail for r in results)


# ---------------- real-file seeds ----------------

def _tree(tmp_path, files: dict[str, bytes]) -> Path:
    root = tmp_path / "root"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def test_real_seeds_round_robin_across_formats_dedup_and_cap(tmp_path):
    root = _tree(tmp_path, {
        "a/1.png": b"png-1", "a/2.png": b"png-2", "a/3.png": b"png-3",
        "b/1.jpg": b"jpg-1", "b/dup.jpg": b"png-1",          # duplicate content
        "c/big.png": b"x" * 100, "c/empty.png": b"", "c/note.txt": b"ignored",
    })
    sources = {"imageio": ((str(root),), (".png", ".jpg"))}
    got = _mac_real_seeds.real_file_seeds("imageio", sources=sources, limit=4, max_bytes=50)
    assert got == [b"jpg-1", b"png-1", b"png-2", b"png-3"]   # jpg first (sorted), dup + big skipped
    again = _mac_real_seeds.real_file_seeds("imageio", sources=sources, limit=4, max_bytes=50)
    assert again == got                                         # deterministic


def test_real_seeds_limit_zero_and_unknown_key(tmp_path):
    root = _tree(tmp_path, {"f.ttf": b"font"})
    sources = {"coretext": ((str(root),), (".ttf",))}
    assert _mac_real_seeds.real_file_seeds("coretext", sources=sources, limit=0) == []
    assert _mac_real_seeds.real_file_seeds("videotoolbox", sources=sources) == []
    assert _mac_real_seeds.real_file_seeds("coretext", sources=sources) == [b"font"]


def test_campaign_seed_corpus_appends_real_files_for_mac_targets(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
    import run as campaign
    monkeypatch.setattr(campaign, "real_file_seeds", lambda key, limit: [f"{key}:{limit}".encode()])

    class T:
        def seeds(self):
            return [b"builtin"]

    assert campaign._seed_corpus(T(), "mac:coretext", 5) == [b"builtin", b"coretext:5"]
    assert campaign._seed_corpus(T(), "mac:coretext", 0) == [b"builtin"]
    assert campaign._seed_corpus(T(), "mock:parser", 5) == [b"builtin"]


def test_campaign_streams_batches_in_order_with_bounded_memory():
    """Regression: run.py materialized every case up front (11.8 GB for 300k
    real-file cases). Batches must be generated lazily, at most 2*workers
    ahead of consumption, and consumed in submission order (determinism)."""
    import threading
    import time as _time

    sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
    import run as campaign

    generated, consumed, lock = [], [], threading.Lock()
    max_ahead = 0

    def batches():
        nonlocal max_ahead
        for i in range(40):
            with lock:
                generated.append(i)
                max_ahead = max(max_ahead, len(generated) - len(consumed))
            yield [bytes([i])]

    class SlowEarly:
        def execute_batch(self, chunk):
            _time.sleep(0.02 if chunk[0][0] % 3 == 0 else 0.0)   # complete out of order
            return [chunk[0][0]]

    def consume(chunk, results):
        with lock:
            consumed.append(results[0])

    campaign._stream_batches(SlowEarly(), batches(), 4, consume)
    assert consumed == list(range(40))
    assert max_ahead <= 2 * 4 + 1
    serial = []
    campaign._stream_batches(SlowEarly(), iter([[b"\x05"], [b"\x06"]]), 1,
                             lambda c, r: serial.append(r[0]))
    assert serial == [5, 6]


# ---------------- gmalloc profile ----------------

def test_gmalloc_profile_registered_and_exclusive_with_allocator_sanitizers():
    p = sanitizers.get_profile("gmalloc")
    assert p.platforms == ("darwin",)
    assert p.runtime_env["DYLD_INSERT_LIBRARIES"] == "/usr/lib/libgmalloc.dylib"
    assert sanitizers.notes_for("gmalloc")
    assert sanitizers.check_combination(["gmalloc", "baseline"])["compatible"]
    for other in ("asan-ubsan", "tsan", "mte"):
        with pytest.raises(ValidationError):
            sanitizers.check_combination(["gmalloc", other])


def _driver_flags(profile: str | None) -> str:
    prof = f"SANITIZER_PROFILE={profile};" if profile else ""
    script = (f"MODE=driver; TRACE_CMP=0; {prof}\n"
              f"eval \"$(sed -n '/^SANITIZER_PROFILE=/p; /^sanitize_flags()/,/^}}/p; "
              f"/^profile_flags()/,/^}}/p' '{BUILD_SH}')\";\n"
              f"{'SANITIZER_PROFILE=' + profile + ';' if profile else ''} sanitize_flags\n")
    r = subprocess.run(["bash", "-c", script], capture_output=True, timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    return r.stdout.decode()


def test_build_sh_default_profile_is_gmalloc():
    flags = _driver_flags(None)
    assert "-DHARNESS_GMALLOC" in flags and "-fsanitize=address" not in flags
    assert "-DHARNESS_STANDALONE" in flags


@pytest.mark.skipif(sys.platform == "darwin", reason="gmalloc is supported on darwin")
def test_build_sh_rejects_gmalloc_off_darwin():
    r = subprocess.run(["bash", str(BUILD_SH), "--sanitizer", "gmalloc", "selftest"],
                       capture_output=True, timeout=30, check=False)
    assert r.returncode == 4 and b"not supported on" in r.stderr


# ---------------- Jackalope wrapper (argument handling; no Jackalope needed) ----------------

JACKALOPE_SH = REPO / "tools" / "harness" / "jackalope.sh"


@pytest.mark.parametrize("args,env,code,msg", [
    (["bogus", "10"], {}, 2, b"unknown framework"),
    (["imageio", "ten"], {}, 2, b"positive integer"),
    (["imageio", "10"], {"JACKALOPE": "/nonexistent/fuzzer"}, 3, b"not found"),
    ([], {}, 2, b"Usage"),
])
def test_jackalope_wrapper_validates_before_building(args, env, code, msg):
    r = subprocess.run(["bash", str(JACKALOPE_SH), *args], capture_output=True, timeout=30,
                       check=False, env={**os.environ, **env})
    assert r.returncode == code and msg in (r.stdout + r.stderr)


def test_harness_exports_persistent_entry_for_binary_instrumentation():
    src = (REPO / "tools" / "harness" / "mac_fuzz_harness.c").read_text()
    assert '__attribute__((noinline, visibility("default")))\nint iosr_fuzz_file(const char *path)' in src
    assert "-target_method _iosr_fuzz_file" in JACKALOPE_SH.read_text()
    assert "-generate_unwind" in JACKALOPE_SH.read_text()


# ---------------- native, opt-in: real builds, real frameworks ----------------

def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


def _build(tmp_path, key: str) -> Path:
    r = subprocess.run(["bash", str(BUILD_SH), key], capture_output=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return REPO / "tools" / "harness" / "build" / f"{key}_fuzzer"


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_guard_malloc_catches_heap_bugs_without_instrumentation(tmp_path):
    """The gmalloc self-test build has NO sanitizer: only Guard Malloc can see these."""
    t = MacFuzzTarget("selftest", harness=str(_build(tmp_path, "selftest")), timeout_s=30)
    expect = {b"OOB" + b"." * 20: "OUT_OF_BOUNDS_READ",
              b"WRT" + b"." * 20: "OUT_OF_BOUNDS_WRITE",
              b"UAF" + b"." * 20: "OUT_OF_BOUNDS_READ"}   # freed page: same fault as OOB
    for payload, cls in expect.items():
        res = t.execute(payload)
        assert res.outcome == Outcome.CRASH, (payload, res.outcome, res.detail)
        assert res.diagnostics.classification_hint == cls
        # run_target is static and inlined at -O1: the fault is attributed to
        # the exported entry point that contains it.
        assert res.diagnostics.stack_trace[0].endswith("LLVMFuzzerTestOneInput")
    assert t.execute(b"clean input").outcome == Outcome.ACCEPTED


NATIVE_DEPTH = [
    ("imageio", "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericDocumentIcon.icns", "pixels"),
    ("coretext", "/System/Library/Fonts/Supplemental/Arial.ttf", "lines"),
    ("audiotoolbox", "/System/Library/Sounds/Glass.aiff", "frames"),
]


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
@pytest.mark.parametrize("key,path,metric", NATIVE_DEPTH)
def test_native_deep_stage_runs_on_real_files(tmp_path, key, path, metric):
    """Regression for the ABI bugs: each deep stage must produce real output."""
    if not os.path.exists(path):
        pytest.skip(f"{path} not on this macOS")
    out = subprocess.run([str(_build(tmp_path, key)), path], capture_output=True, timeout=60, check=False)
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")
    assert b"WARNING" not in out.stderr                      # Guard Malloc really loaded
    done = next(ln for ln in out.stdout.decode().splitlines() if ln.startswith("DONE"))
    status, measured = done.split()[2], done.split()[3]
    assert status == "decoded" and measured.startswith(metric + "=")
    assert int(measured.split("=")[1]) > 0, done
