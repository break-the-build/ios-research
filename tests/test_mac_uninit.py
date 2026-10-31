"""Uninitialized-memory differential (tools/mac_campaign/uninit.py).

A file is a HIT when two plain runs agree, two MALLOC_FILL_SPACE runs agree,
and the two differ: its output contains heap bytes the framework never wrote.
Controls (a canary that must be a hit, a valid seed that must be clean) run
before any scan. A stub harness exercises the logic in CI; native tests run
the real ImageIO and CoreText harnesses.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
import uninit  # noqa: E402

# A batch 'harness': file content picks the behavior. With MALLOC_FILL_SPACE a
# leaking file's digest changes; the canary does the same for every file
# unless STUB_DEAD (no Guard Malloc) makes fill-space a no-op.
STUB = r"""#!/usr/bin/env bash
i=0
for f in "$@"; do
  c=$(cat "$f")
  fill=${MALLOC_FILL_SPACE:-0}
  [ "${STUB_DEAD:-}" = 1 ] && fill=0
  case "$c" in
    crash) kill -SEGV $$ ;;
    reject) echo "DONE $i rejected" ;;
    *)
      echo "DONE $i decoded pixels=1"
      d=00000000000000aa
      [ "$c" = leak ] && [ "$fill" = 1 ] && d=5555555555555555
      [ "$c" = flaky ] && d=$(printf '%016x' "$RANDOM$RANDOM$RANDOM")
      [ "${IOSR_UNINIT_CANARY:-}" = 1 ] && [ "$fill" = 1 ] && d=5555555555555556
      [ "${IOSR_DIGEST:-}" = 1 ] && echo "DIGEST $i $d"
      ;;
  esac
  i=$((i+1))
done
"""


@pytest.fixture()
def stub(tmp_path) -> str:
    path = tmp_path / "imageio_fuzzer"
    path.write_text(STUB)
    path.chmod(0o755)
    return str(path)


def _files(tmp_path, *contents: str) -> list[str]:
    out = []
    for i, c in enumerate(contents):
        p = tmp_path / f"in_{i}"
        p.write_text(c)
        out.append(str(p))
    return out


@pytest.mark.parametrize("plain, fill, verdict", [
    (("a", "a"), ("b", "b"), "hit"),
    (("a", "a"), ("a", "a"), "clean"),
    (("a", "x"), ("b", "b"), "unstable"),
    (("a", "a"), ("b", "y"), "unstable"),
    ((None, "a"), ("b", "b"), "no-output"),
])
def test_classify(plain, fill, verdict):
    assert uninit.classify(plain, fill) == verdict


def test_scan_separates_leaks_from_noise(stub, tmp_path):
    files = _files(tmp_path, "clean", "leak", "flaky", "reject", "crash", "leak")
    assert uninit.scan(stub, files) == ["clean", "hit", "unstable", "no-output",
                                        "no-output", "hit"]


def test_controls_pass_on_the_first_seed_with_output(stub, tmp_path):
    ok, reason = uninit.controls(stub, [b"reject", b"clean"], tmp_path / "w")
    assert ok and "seed 1" in reason


def test_controls_fail_without_an_effective_fill(stub, tmp_path, monkeypatch):
    monkeypatch.setenv("STUB_DEAD", "1")
    ok, reason = uninit.controls(stub, [b"clean"], tmp_path / "w")
    assert not ok and reason.startswith("positive control")


def test_controls_fail_when_a_valid_seed_already_leaks(stub, tmp_path):
    ok, reason = uninit.controls(stub, [b"leak"], tmp_path / "w")
    assert not ok and reason.startswith("negative control")


def test_main_scans_reports_and_copies_hits(stub, tmp_path):
    src = tmp_path / "corpus"
    src.mkdir()
    for name, body in (("a.png", "clean"), ("b.png", "leak")):
        (src / name).write_text(body)
    report, hits = tmp_path / "r.json", tmp_path / "hits"
    code = uninit.main(["--target", "mac:imageio", str(src), "--report", str(report),
                        "--out", str(hits)], harness=stub)
    summary = json.loads(report.read_text())
    assert code == 0 and summary["counts"]["hit"] == 1 and summary["counts"]["clean"] == 1
    assert [p.name for p in hits.iterdir()] == ["b.png"]


def test_main_refuses_with_failed_controls(stub, monkeypatch):
    monkeypatch.setenv("STUB_DEAD", "1")
    assert uninit.main(["--target", "mac:imageio", "--controls-only"],
                       harness=stub) == uninit.EXIT_CONTROLS_FAILED


def test_main_rejects_targets_without_a_digest():
    assert uninit.main(["--target", "mac:audiotoolbox"]) == uninit.EXIT_USAGE


# ---------------- native ----------------

def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


def _build(key: str) -> str:
    r = subprocess.run(["bash", str(REPO / "tools" / "harness" / "build.sh"), key],
                       capture_output=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")
    return str(REPO / "tools" / "harness" / "build" / f"{key}_fuzzer")


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
@pytest.mark.parametrize("key", ["imageio", "coretext"])
def test_native_controls_pass_under_guard_malloc(key, monkeypatch, tmp_path):
    monkeypatch.delenv("IOSR_GMALLOC_REEXEC", raising=False)
    from ios_research.targets import create
    ok, reason = uninit.controls(_build(key), create(f"mac:{key}").seeds(), tmp_path)
    assert ok, reason


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_controls_fail_without_guard_malloc(monkeypatch, tmp_path):
    monkeypatch.setenv("IOSR_GMALLOC_REEXEC", "0")
    monkeypatch.delenv("DYLD_INSERT_LIBRARIES", raising=False)
    from ios_research.targets import create
    ok, reason = uninit.controls(_build("imageio"), create("mac:imageio").seeds(), tmp_path)
    assert not ok and reason.startswith("positive control")


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
def test_native_valid_system_image_is_clean(monkeypatch):
    monkeypatch.delenv("IOSR_GMALLOC_REEXEC", raising=False)
    icon = ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/"
            "GenericDocumentIcon.icns")
    assert uninit.scan(_build("imageio"), [icon]) == ["clean"]
