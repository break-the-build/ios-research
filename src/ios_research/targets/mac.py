"""macOS in-process fuzzing target (real crashes, no device required).

Many iOS parsing libraries ship the *same* binaries on macOS (ImageIO,
CoreGraphics, AudioToolbox, CoreAudio, …). This target drives one input through
a native ``-fsanitize=fuzzer,address,undefined`` harness that ``dlopen``\\s such a
framework and calls a real decode entry point. When the sanitizer catches a
defect it prints a report that :mod:`ios_research.targets.asan` normalizes into
the same :class:`~ios_research.targets.base.Diagnostics` every other subsystem
consumes — so this is the first path that produces **real** faulting addresses,
registers, stack traces, and modules rather than synthetic ones.

Unlike every other shipped target this one is **not a mock** (``mock = False``):
it executes native code. It is therefore *opt-in* — it requires a macOS toolchain
and a built harness binary, and is skipped in CI (which stays mock-only).

Safety: authorized / own-machine research only. The harness only feeds bytes to
a parsing entry point in a library already present on the machine; it does not
bypass permissions or touch device sensors (see ``SECURITY.md``). Real findings
route to Apple Security Bounty via responsible disclosure.

Build the harness with ``tools/harness/build.sh`` (see ``docs/MAC-FUZZING.md``).
Point the target at the resulting binary via the ``IOS_RESEARCH_MAC_HARNESS``
environment variable, or place it at ``tools/harness/build/<framework>_fuzzer``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .base import ExecResult, Outcome, Target
from . import asan

# Frameworks exposed as ``mac:<framework>`` targets and the parse entry point the
# harness wraps. The value is informational (surfaced via ``describe``); the
# actual entry point is selected at harness build time.
_FRAMEWORKS = {
    "imageio": {
        "framework": "ImageIO",
        "entry": "CGImageSourceCreateWithData",
        "formats": ("png", "jpeg", "gif", "tiff", "heic", "webp"),
        "description": "ImageIO image-decode fuzzing (CGImageSourceCreateWithData)",
    },
    "audiotoolbox": {
        "framework": "AudioToolbox",
        "entry": "AudioFileOpenWithCallbacks",
        "formats": ("wav", "mp3", "aac", "caf", "m4a"),
        "description": "AudioToolbox audio-decode fuzzing (AudioFileOpenWithCallbacks)",
    },
    "coregraphics": {
        "framework": "CoreGraphics",
        "entry": "CGDataProviderCreateWithData",
        "formats": ("pdf", "raw"),
        "description": "CoreGraphics data-decode fuzzing (CGDataProvider)",
    },
}

# Sanitizer exit codes: libFuzzer/ASan abort with a non-zero code on a finding.
# A clean run returns 0; a timeout is handled separately.
_DEFAULT_TIMEOUT_S = 10.0
_HARNESS_ENV = "IOS_RESEARCH_MAC_HARNESS"


def _decode_statuses(stdout: str) -> list[str]:
    """Parse the standalone driver's ``DONE <i> <status>`` lines, in order."""
    out: list[str] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "DONE":
            out.append(parts[2])
    return out


def _decode_status(stdout: str, index: int) -> str | None:
    """Return the decode status for input ``index`` (or None if not reported)."""
    statuses = _decode_statuses(stdout)
    if 0 <= index < len(statuses):
        return statuses[index]
    return None


class MacFuzzTarget(Target):
    """Drive one input through a native libFuzzer/ASan harness on macOS."""

    kind = "mac-native"
    mock = False

    def __init__(self, key: str, *, harness: str | None = None,
                 timeout_s: float = _DEFAULT_TIMEOUT_S) -> None:
        meta = _FRAMEWORKS[key]
        self.key = key
        self.framework = meta["framework"]
        self.entry = meta["entry"]
        self.target_id = f"mac:{key}"
        self.formats = meta["formats"]
        self.description = meta["description"]
        self._harness_override = harness
        self.timeout_s = timeout_s
        self._harness_path: Path | None = None

    # --- discovery -------------------------------------------------------
    def _candidate_paths(self) -> list[Path]:
        # An explicit constructor override is authoritative — no fallback, so a
        # caller can pin (or negatively assert) exactly one binary.
        if self._harness_override:
            return [Path(self._harness_override)]
        cands: list[Path] = []
        env = os.environ.get(_HARNESS_ENV)
        if env:
            cands.append(Path(env))
        repo = Path(__file__).resolve().parents[3]
        cands.append(repo / "tools" / "harness" / "build" / f"{self.key}_fuzzer")
        cands.append(repo / "tools" / "harness" / "build" / f"{self.framework}_fuzzer")
        return cands

    def resolve_harness(self) -> Path | None:
        for cand in self._candidate_paths():
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        return None

    def available(self) -> bool:
        """True when a built harness binary is present and executable."""
        return self.resolve_harness() is not None

    def describe(self):
        d = super().describe()
        d["framework"] = self.framework
        d["entry_point"] = self.entry
        d["available"] = self.available()
        d["note"] = ("real native harness; authorized/own-machine research only; "
                     "requires a built libFuzzer/ASan binary")
        return d

    # --- format hooks ----------------------------------------------------
    def seeds(self) -> list[bytes]:
        from . import _mac_seeds
        return _mac_seeds.seeds(self.key)

    def structure_mutate(self, data: bytes, rng):
        from . import _mac_seeds
        return _mac_seeds.structure_mutate(self.key, data, rng)

    # --- lifecycle -------------------------------------------------------
    def prepare(self) -> None:
        self._harness_path = self.resolve_harness()

    def cleanup(self) -> None:
        self._harness_path = None

    def _run(self, data: bytes) -> ExecResult:
        harness = self._harness_path
        if harness is None:
            return ExecResult(
                outcome=Outcome.ABNORMAL,
                detail=(f"harness for {self.target_id} not built; set "
                        f"${_HARNESS_ENV} or run tools/harness/build.sh "
                        f"(see docs/MAC-FUZZING.md)"),
                duration_ms=0)

        import tempfile
        import time

        start = time.monotonic()
        tmp = tempfile.NamedTemporaryFile(
            prefix="ios-research-mac-", suffix=".input", delete=False)
        try:
            tmp.write(data)
            tmp.flush()
            tmp.close()
            return self._run_harness(harness, tmp.name, start)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def _run_harness(self, harness: Path, input_path: str,
                     start: float) -> ExecResult:
        import time

        # libFuzzer binaries run a single input to completion when given a file
        # argument, then exit. ASAN_OPTIONS keeps the report on stderr and exits
        # (rather than re-raising) so we capture a full, parseable report.
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS",
                       "abort_on_error=0:exitcode=99:detect_leaks=0")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
        try:
            proc = subprocess.run(
                [str(harness), input_path],
                capture_output=True, env=env, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            dur = int((time.monotonic() - start) * 1000)
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail=f"harness exceeded {self.timeout_s}s budget",
                              duration_ms=dur)
        except OSError as exc:  # pragma: no cover - defensive
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=f"failed to execute harness: {exc}",
                              duration_ms=0)

        dur = int((time.monotonic() - start) * 1000)
        report = (proc.stderr or b"").decode("utf-8", "replace")
        stdout = (proc.stdout or b"").decode("utf-8", "replace")

        if proc.returncode == 0:
            # The standalone driver reports per-input decode status on stdout;
            # distinguish "the decoder produced an object" (ACCEPTED) from "the
            # decoder rejected the input" (REJECTED). libFuzzer builds emit no
            # such marker, so fall back to ACCEPTED.
            status = _decode_status(stdout, 0)
            if status == "rejected":
                return ExecResult(outcome=Outcome.REJECTED,
                                  detail="entry point rejected the input",
                                  duration_ms=max(dur, 1))
            return ExecResult(outcome=Outcome.ACCEPTED,
                              detail="input decoded without a sanitizer finding",
                              duration_ms=max(dur, 1))

        if asan.is_crash_report(report):
            diag = asan.parse(report, module=self.framework)
            first = report.splitlines()[0].strip() if report else ""
            return ExecResult(outcome=Outcome.CRASH,
                              detail=first[:500] or "sanitizer reported a crash",
                              duration_ms=max(dur, 1), diagnostics=diag)

        # Non-zero exit without a recognizable report: abnormal, not a crash.
        detail = (report.strip().splitlines()[-1][:500]
                  if report.strip() else
                  f"harness exited with code {proc.returncode}")
        return ExecResult(outcome=Outcome.ABNORMAL, detail=detail,
                          duration_ms=max(dur, 1))

    # --- batched execution (throughput) ----------------------------------
    def execute_batch(self, inputs: list[bytes]) -> list[ExecResult]:
        """Run many inputs, amortizing process-spawn cost over one harness call.

        Only the standalone-driver harness supports batching (it accepts multiple
        file arguments and reports per-input status). For a single input, a
        libFuzzer harness, or any crash within the batch, this falls back to the
        per-input :meth:`execute` path so results stay precise and attributable.
        """
        if len(inputs) <= 1:
            return [self.execute(d) for d in inputs]

        self.prepare()
        try:
            harness = self._harness_path
            if harness is None:
                return [self._run(d) for d in inputs]  # uniform ABNORMAL results
            return self._run_batch(harness, inputs)
        finally:
            self.cleanup()

    def _run_batch(self, harness: Path, inputs: list[bytes]) -> list[ExecResult]:
        import tempfile
        import time

        start = time.monotonic()
        tmpdir = tempfile.mkdtemp(prefix="ios-research-mac-batch-")
        paths: list[str] = []
        try:
            for i, data in enumerate(inputs):
                p = os.path.join(tmpdir, f"case_{i:06d}.input")
                with open(p, "wb") as fh:
                    fh.write(data)
                paths.append(p)

            env = dict(os.environ)
            env.setdefault("ASAN_OPTIONS",
                           "abort_on_error=0:exitcode=99:detect_leaks=0")
            env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
            try:
                proc = subprocess.run(
                    [str(harness), *paths], capture_output=True, env=env,
                    timeout=self.timeout_s * len(inputs))
            except subprocess.TimeoutExpired:
                return [self.execute(d) for d in inputs]

            report = (proc.stderr or b"").decode("utf-8", "replace")
            stdout = (proc.stdout or b"").decode("utf-8", "replace")

            # A crash aborts the batch process; re-run individually so the
            # crashing input (and any after it) get precise, attributable results.
            if proc.returncode != 0 and asan.is_crash_report(report):
                return [self.execute(d) for d in inputs]

            statuses = _decode_statuses(stdout)
            if len(statuses) != len(inputs):
                # No/partial per-input markers (e.g. libFuzzer build): be safe.
                return [self.execute(d) for d in inputs]

            per_ms = max(int((time.monotonic() - start) * 1000) // len(inputs), 1)
            results: list[ExecResult] = []
            for status in statuses:
                if status == "rejected":
                    results.append(ExecResult(outcome=Outcome.REJECTED,
                                              detail="entry point rejected the input",
                                              duration_ms=per_ms))
                else:
                    results.append(ExecResult(outcome=Outcome.ACCEPTED,
                                              detail="input decoded without a finding",
                                              duration_ms=per_ms))
            return results
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


def build_targets() -> dict[str, type]:
    """Return the ``{target_id: factory}`` mapping for registration."""
    return _FRAMEWORKS


MAC_FRAMEWORKS = _FRAMEWORKS
