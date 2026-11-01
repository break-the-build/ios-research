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
import time
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


# Verbatim from libgmalloc on macOS 26.5 (1-byte heap underflow, default mode).
GMALLOC_BANNER = """GuardMalloc[imageio_fuzzer-92005]: Allocations will be placed on 16 byte boundaries.
GuardMalloc[imageio_fuzzer-92005]:  - Some buffer overruns may not be noticed.
GuardMalloc[imageio_fuzzer-92005]:  - Applications using vector instructions (e.g., SSE) should work.
GuardMalloc[imageio_fuzzer-92005]: version 064575.39.1
"""
GMALLOC_UNDERRUN = ("GuardMalloc[host_plain-92984]: free: header for block 0x13e063000-0x13e064000 "
                    "has been trashed by a buffer underrun. Header magic value at 0x13e062ff8 is "
                    "0x42adbeefdeadbeef, not 0xdeadbeefdeadbeef.  Try running with "
                    "MALLOC_PROTECT_BEFORE to catch this error immediately as it happens.\n")
ABORT = "IOSR-CRASH signal=SIGABRT addr=0x0000000000000000 pc=0x1 access=unknown\n"


def test_guard_malloc_abort_is_heap_corruption_not_an_assertion():
    """Guard Malloc reports some corruption only at free(), via SIGABRT."""
    d = sigcrash.parse(GMALLOC_BANNER + GMALLOC_UNDERRUN + ABORT)
    assert d.classification_hint == "OUT_OF_BOUNDS_WRITE" and d.signal == "SIGABRT"
    cls, msg = sigcrash.gmalloc_diagnosis(GMALLOC_UNDERRUN)
    assert cls == "OUT_OF_BOUNDS_WRITE" and "buffer underrun" in msg


# Verbatim from libgmalloc on macOS 26.x with MALLOC_STRICT_SIZE=1.
GMALLOC_STRICT_BANNER = """GuardMalloc[imageio_fuzzer-7001]: Allocations will be placed on byte boundaries.
GuardMalloc[imageio_fuzzer-7001]:  - Overrunning a buffer will cause an immediate crash. (Good.)
GuardMalloc[imageio_fuzzer-7001]:  - Applications using vector instructions (e.g., SSE) may fail.
GuardMalloc[imageio_fuzzer-7001]:  - Applications expecting word-aligned pointers may fail (such as Carbon applications)
GuardMalloc[imageio_fuzzer-7001]: version 064575.39.1
"""


@pytest.mark.parametrize("banner", [GMALLOC_BANNER, GMALLOC_STRICT_BANNER])
def test_guard_malloc_banner_alone_is_not_a_diagnosis(banner):
    """Banners say 'buffer overruns may not be noticed' / 'Overrunning a buffer
    will cause an immediate crash' -- neither is a diagnosis. The strict one
    once labeled every strict-mode crash OUT_OF_BOUNDS_WRITE."""
    assert sigcrash.gmalloc_diagnosis(banner) is None
    assert sigcrash.parse(banner + ABORT).classification_hint == "ASSERTION"
    read = "IOSR-CRASH signal=SIGSEGV addr=0x0000000150a8c010 pc=0x1 access=read\n"
    assert sigcrash.parse(banner + read).classification_hint == "OUT_OF_BOUNDS_READ"


def test_guard_malloc_double_free_diagnosis():
    text = "GuardMalloc[x-1]: attempted free of pointer 0x1234 that was not allocated\n"
    assert sigcrash.gmalloc_diagnosis(text)[0] == "DOUBLE_FREE"


def test_guard_malloc_abort_through_the_target_is_a_crash(tmp_path):
    body = "".join(f"echo '{ln}' >&2\n" for ln in (GMALLOC_UNDERRUN + ABORT).splitlines())
    res = MacFuzzTarget("imageio", harness=_stub(tmp_path, body + "kill -ABRT $$\n")).execute(b"x")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint == "OUT_OF_BOUNDS_WRITE"
    assert res.detail.startswith("GuardMalloc: free: header for block")


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
    (["bogus", "10"], {"JACKALOPE_MODULES": "ImageIO"}, 2, b"unknown framework"),
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


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_until(cond, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while not cond():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)
    return True


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_hung_input_costs_one_deadline_not_the_batch(tmp_path):
    t = MacFuzzTarget("selftest", harness=str(_build(tmp_path, "selftest")), timeout_s=1)
    start = time.monotonic()
    results = t.execute_batch([b"ok", b"IOSR-SELFTEST-HANG", b"ok", b"ok"])
    assert [r.outcome for r in results] == [
        Outcome.ACCEPTED, Outcome.TIMEOUT, Outcome.ACCEPTED, Outcome.ACCEPTED]
    assert time.monotonic() - start < 10   # was timeout_s * 4, then 4 re-runs


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_harness_exits_when_its_parent_dies(tmp_path):
    harness = _build(tmp_path, "selftest")
    hang, pidfile = tmp_path / "hang.bin", tmp_path / "child.pid"
    hang.write_bytes(b"IOSR-SELFTEST-HANG")
    parent = subprocess.Popen(
        ["sh", "-c", (f'"{harness}" "{hang}" >/dev/null 2>&1 & echo $! > "{pidfile}"; '
                      "exec sleep 60")])
    child = 0
    try:
        assert _wait_until(lambda: pidfile.exists() and pidfile.read_text().strip(), 10)
        child = int(pidfile.read_text())
        time.sleep(1)                    # past the Guard Malloc re-exec, into the hang
        assert _alive(child)
        parent.kill()
        parent.wait()
        assert _wait_until(lambda: not _alive(child), 10)
    finally:
        parent.kill()
        if child and _alive(child):
            os.kill(child, 9)


def _rect_pdf() -> bytes:
    """A one-page PDF with a filled rectangle, with a correct xref table."""
    content = b"0 0 1 rg 10 10 100 100 re f"
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content)]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref)
    return bytes(out)


def _done_line(harness: Path, path: Path, **env: str) -> tuple[str, str]:
    r = subprocess.run([str(harness), str(path)], capture_output=True, timeout=60,
                       check=False, env={**os.environ, **env})
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-2000:]
    lines = _decode_lines(r.stdout.decode())
    assert len(lines) == 1
    return lines[0]


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_imageio_thumbnail_pass_decodes_pdf(tmp_path):
    """ImageIO hands a PDF to CoreGraphics only on the thumbnail path."""
    harness = _build(tmp_path, "imageio")
    pdf = tmp_path / "rect.pdf"
    pdf.write_bytes(_rect_pdf())
    assert _done_line(harness, pdf, IOSR_IMGIO_THUMBNAIL="0")[0] == "rejected"
    status, metric = _done_line(harness, pdf)
    assert status == "decoded" and int(metric.split("=")[1]) > 0


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_coretext_large_pass_rasterizes_more(tmp_path):
    harness = _build(tmp_path, "coretext")
    arial = Path("/System/Library/Fonts/Supplemental/Arial.ttf")
    off = _done_line(harness, arial, IOSR_CT_LARGE_SIZE="0")
    on = _done_line(harness, arial)
    assert off[0] == on[0] == "decoded"
    assert int(on[1].split("=")[1]) > int(off[1].split("=")[1])


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_coretext_strike_pass_draws_embedded_bitmaps(tmp_path):
    """Monaco's bitmap strikes are used only at their own pixel sizes."""
    harness = _build(tmp_path, "coretext")
    monaco = Path("/System/Library/Fonts/Monaco.ttf")
    if not monaco.exists():
        pytest.skip("Monaco.ttf not installed")
    off = _done_line(harness, monaco, IOSR_CT_STRIKES="0")
    on = _done_line(harness, monaco)
    assert int(on[1].split("=")[1]) > int(off[1].split("=")[1])


NATIVE_DEPTH = [
    ("imageio", "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/GenericDocumentIcon.icns", "pixels"),
    ("coretext", "/System/Library/Fonts/Supplemental/Arial.ttf", "pixels"),
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
