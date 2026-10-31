"""Detection canary: positive and negative controls for the mac harness oracle.

The canary (ios_research.targets.canary, IOSR_CANARY=1 in the harness) proves,
before any campaign, that a heap read inside the framework is detected,
reported and classified -- and that a valid input does not crash on its own.

Stub harnesses (bash scripts speaking the harness's stderr protocol) exercise
the whole Python path in CI; native tests (opt-in, -m native) run the real
harnesses under each Guard Malloc mode.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ios_research.targets import canary
from ios_research.targets.base import Diagnostics, ExecResult, Outcome
from ios_research.targets.mac import MacFuzzTarget

REPO = Path(__file__).resolve().parents[1]
LO, HI = 0x150A8C000, 0x150A8D000
CANARY_LINE = f"IOSR-CANARY mode=after lo={LO:#018x} hi={HI:#018x}"
FRAMEWORK_FRAMES = (("IOSR-FRAME 0 0x0000000194c62aa8 ImageIO+0xfaa8 "
                     "ERROR_ImageIO_SourceBufferRangeIsNotBigEnough"),
                    "IOSR-FRAME 1 0x00000001021f9a84 imageio_fuzzer+0x1a84 decode_all_frames")
HARNESS_FRAMES = ("IOSR-FRAME 0 0x00000001021f9a84 imageio_fuzzer+0x1a84 decode_all_frames",
                  "IOSR-FRAME 1 0x0000000194c62aa8 ImageIO+0xfaa8 CGImageSourceGetCount")


def _crash_lines(addr: int, frames=FRAMEWORK_FRAMES, sig: str = "SIGSEGV") -> list[str]:
    return [f"IOSR-CRASH signal={sig} addr={addr:#018x} pc=0x0000000194c62aa8 access=read",
            *frames]


def _stub(tmp_path, canary_lines=None, *, plain_crash: bool = False,
          kill: bool = True) -> MacFuzzTarget:
    """An imageio 'harness' that answers IOSR_CANARY=1 with `canary_lines`
    (then dies by SIGSEGV if `kill`), and decodes plain runs cleanly unless
    `plain_crash`."""
    def echo(lines):
        return "".join(f"echo '{ln}' >&2\n" for ln in lines)

    plain = (echo(_crash_lines(0x10)) + "kill -SEGV $$\n" if plain_crash
             else "echo 'DONE 0 decoded pixels=5'\n")
    on_canary = ("echo 'DONE 0 decoded pixels=5'\nexit 0\n" if canary_lines is None
                 else echo(canary_lines) + ("kill -SEGV $$\n" if kill
                                            else "echo 'DONE 0 rejected'\nexit 0\n"))
    stub = tmp_path / "imageio_fuzzer"
    stub.write_text("#!/usr/bin/env bash\n"
                    f'if [ "${{IOSR_CANARY:-}}" = 1 ]; then\n{on_canary}fi\n{plain}')
    stub.chmod(0o755)
    return MacFuzzTarget("imageio", harness=str(stub))


# ---------------- verdicts through the real MacFuzzTarget path ----------------

def test_framework_read_inside_the_guarded_range_passes(tmp_path):
    v = canary.check(_stub(tmp_path, [CANARY_LINE, *_crash_lines(LO + 7)]), seeds=[b"x"])
    assert v.passed, v.reason
    assert v.mode == "after" and v.fault == f"{LO + 7:#018x}"
    assert v.frames[0].startswith("ImageIO`")


def test_no_guard_malloc_fails_loudly(tmp_path):
    line = "IOSR-CANARY mode=unguarded lo=0x0000000000000000 hi=0x0000000000000000"
    v = canary.check(_stub(tmp_path, [line], kill=False), seeds=[b"x"])
    assert not v.passed and "Guard Malloc is not active" in v.reason


def test_harness_that_predates_the_canary_says_rebuild(tmp_path):
    v = canary.check(_stub(tmp_path, None), seeds=[b"x"])
    assert not v.passed and "rebuild" in v.reason


def test_unsupported_target(tmp_path):
    v = canary.check(_stub(tmp_path, ["IOSR-CANARY mode=unsupported lo=0x0 hi=0x0"],
                           kill=False), seeds=[b"x"])
    assert not v.passed and "no canary" in v.reason


def test_read_that_is_not_detected_fails(tmp_path):
    v = canary.check(_stub(tmp_path, [CANARY_LINE], kill=False), seeds=[b"x"])
    assert not v.passed and v.reason.startswith("no detection")


def test_fault_outside_the_range_is_a_different_crash(tmp_path):
    v = canary.check(_stub(tmp_path, [CANARY_LINE, *_crash_lines(HI)]), seeds=[b"x"])
    assert not v.passed and "a different crash" in v.reason


def test_fault_attributed_to_the_harness_fails(tmp_path):
    lines = [CANARY_LINE, *_crash_lines(LO, frames=HARNESS_FRAMES)]
    v = canary.check(_stub(tmp_path, lines), seeds=[b"x"])
    assert not v.passed and "attributed to the harness" in v.reason


def test_stack_without_the_framework_fails(tmp_path):
    frames = ("IOSR-FRAME 0 0x1 libsystem_platform.dylib+0x3504 _platform_memmove",
              "IOSR-FRAME 1 0x2 CoreFoundation+0x10 CFDataGetBytes")
    v = canary.check(_stub(tmp_path, [CANARY_LINE, *_crash_lines(LO, frames=frames)]),
                     seeds=[b"x"])
    assert not v.passed and "ImageIO/AppleJPEG" in v.reason


def test_oracle_that_crashes_on_a_valid_seed_is_noise(tmp_path):
    """MALLOC_STRICT_SIZE crashes several harnesses on any input."""
    target = _stub(tmp_path, [CANARY_LINE, *_crash_lines(LO)], plain_crash=True)
    v = canary.check(target, seeds=[b"x"])
    assert not v.passed and "would be noise" in v.reason


def test_a_later_seed_can_prove_detection(tmp_path):
    calls = []

    class Scripted:
        key = "imageio"

        def seeds(self):
            return [b"a", b"b"]

        def execute(self, data):
            return ExecResult(outcome=Outcome.ACCEPTED)

        def run_canary(self, data):
            calls.append(data)
            if data == b"a":                       # rejected within the live bytes
                return ExecResult(outcome=Outcome.REJECTED), CANARY_LINE
            diag = Diagnostics(signal="SIGBUS", faulting_address=f"{LO:#018x}",
                               access_type="read", stack_trace=["ImageIO`x"],
                               classification_hint="OUT_OF_BOUNDS_READ")
            return ExecResult(outcome=Outcome.CRASH, diagnostics=diag), CANARY_LINE

    v = canary.check(Scripted())
    assert v.passed and calls == [b"a", b"b"]


def test_all_seeds_failing_reports_the_count(tmp_path):
    v = canary.check(_stub(tmp_path, [CANARY_LINE], kill=False), seeds=[b"a", b"b", b"c", b"d"])
    assert not v.passed and v.reason.endswith(f"({canary.MAX_SEEDS} seed(s) tried)")


def test_canary_read_classified_as_a_write_fails():
    diag = Diagnostics(signal="SIGSEGV", faulting_address=f"{LO:#018x}", access_type="read",
                       stack_trace=["ImageIO`x"], classification_hint="OUT_OF_BOUNDS_WRITE")
    v = canary.evaluate("imageio", ExecResult(outcome=Outcome.CRASH, diagnostics=diag),
                        CANARY_LINE)
    assert not v.passed and "OUT_OF_BOUNDS_WRITE" in v.reason


def test_canary_env_reaches_the_harness_and_plain_runs_stay_clean(tmp_path):
    target = _stub(tmp_path, [CANARY_LINE, *_crash_lines(LO)])
    assert target.execute(b"x").outcome == Outcome.ACCEPTED
    result, report = target.run_canary(b"x")
    assert result.outcome == Outcome.CRASH and CANARY_LINE in report


# ---------------- run.py gate ----------------

def _campaign(monkeypatch):
    sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
    import run as campaign

    def no_campaign(*a, **k):
        raise AssertionError("campaign started despite the canary")

    monkeypatch.setattr(campaign, "run_campaign", no_campaign)
    return campaign


@pytest.mark.parametrize("verdict, code", [
    (canary.CanaryVerdict(True, "ok"), 0),
    (canary.CanaryVerdict(False, "Guard Malloc is not active"), 4),
    (None, 3),
])
def test_canary_only_exit_codes(monkeypatch, verdict, code):
    campaign = _campaign(monkeypatch)
    monkeypatch.setattr(campaign, "check_canary", lambda target_id: verdict)
    assert campaign.main(["--target", "mac:imageio", "--canary-only"]) == code


def test_failed_canary_blocks_the_campaign(monkeypatch, capsys):
    campaign = _campaign(monkeypatch)
    monkeypatch.setattr(campaign, "check_canary",
                        lambda target_id: canary.CanaryVerdict(False, "dead oracle"))
    assert campaign.main(["--target", "mac:imageio", "--cases", "10"]) == 4
    assert "canary: FAIL: dead oracle" in capsys.readouterr().err


def test_no_canary_skips_the_check(monkeypatch):
    campaign = _campaign(monkeypatch)
    monkeypatch.setattr(campaign, "check_canary",
                        lambda target_id: pytest.fail("canary ran despite --no-canary"))
    with pytest.raises(AssertionError, match="campaign started"):
        campaign.main(["--target", "mac:imageio", "--cases", "10", "--no-canary"])


def test_check_canary_skips_targets_without_a_canary():
    sys.path.insert(0, str(REPO / "tools" / "mac_campaign"))
    import run as campaign
    assert campaign.check_canary("mock:parser") is None


# ---------------- native ----------------

FRAMEWORKS = ["imageio", "coretext", "audiotoolbox", "coregraphics"]


def _can_build_native() -> bool:
    return sys.platform == "darwin" and os.path.exists("/usr/lib/libgmalloc.dylib")


@pytest.fixture(scope="module")
def built():
    for key in FRAMEWORKS:
        r = subprocess.run(["bash", str(REPO / "tools" / "harness" / "build.sh"), key],
                           capture_output=True, timeout=300, check=False)
        assert r.returncode == 0, r.stderr.decode("utf-8", "replace")


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
@pytest.mark.parametrize("key", FRAMEWORKS)
@pytest.mark.parametrize("oracle", [{}, {"MALLOC_PROTECT_BEFORE": "1"}],
                         ids=["default", "before"])
def test_native_canary_passes_under_guard_malloc(built, monkeypatch, key, oracle):
    monkeypatch.delenv("IOSR_GMALLOC_REEXEC", raising=False)
    for name, value in oracle.items():
        monkeypatch.setenv(name, value)
    v = canary.check(MacFuzzTarget(key))
    assert v.passed, v.reason
    assert v.mode == ("before" if oracle else "after")


@pytest.mark.native
@pytest.mark.skipif(not _can_build_native(), reason="requires macOS with libgmalloc")
@pytest.mark.parametrize("key", FRAMEWORKS)
def test_native_canary_fails_without_guard_malloc(built, monkeypatch, key):
    """The point of the canary: a blind oracle must not look like 'no bugs'."""
    monkeypatch.setenv("IOSR_GMALLOC_REEXEC", "0")
    monkeypatch.delenv("DYLD_INSERT_LIBRARIES", raising=False)
    v = canary.check(MacFuzzTarget(key))
    assert not v.passed and "Guard Malloc is not active" in v.reason
