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
import threading
from pathlib import Path

from .base import ExecResult, Outcome, Target
from . import asan
from ..coverage import SanitizerCoverageFileAdapter

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
        "entry": "CGPDFDocumentCreateWithProvider",
        "formats": ("pdf", "raw"),
        "description": ("CoreGraphics PDF-decode fuzzing "
                        "(CGPDFDocumentCreateWithProvider + page render)"),
    },
    "coretext": {
        "framework": "CoreText",
        "entry": "CTFontManagerCreateFontDescriptorsFromData",
        "formats": ("ttf", "otf", "ttc"),
        "description": ("CoreText font-parsing fuzzing "
                        "(font descriptors from data + glyph outline decode)"),
    },
    "selftest": {
        "framework": "SelfTest",
        "entry": "selftest_parser",
        "formats": ("raw",),
        "description": ("controlled buggy parser to validate the real-crash "
                        "pipeline (no framework; deliberate ASan bugs)"),
    },
}

# Sanitizer exit codes: libFuzzer/ASan abort with a non-zero code on a finding.
# A clean run returns 0; a timeout is handled separately.
_DEFAULT_TIMEOUT_S = 10.0
_HARNESS_ENV = "IOS_RESEARCH_MAC_HARNESS"
_SANCOV_ENV = "IOS_RESEARCH_SANCOV_FILE"


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
        # Serializes prepare()/cleanup() mutations of `_harness_path` so that
        # concurrent `execute()` calls on this shared instance (parallel ddmin
        # rounds, threaded execute_batch in tools/mac_campaign/run.py) cannot
        # interleave the cached-path updates.
        self._lifecycle_lock = threading.Lock()
        self._coverage_by_input: dict[bytes, tuple[str, ...]] = {}

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
        d["coverage_adapter"] = "sanitizer-coverage file map (driver builds)"
        return d

    # --- format hooks ----------------------------------------------------
    def seeds(self) -> list[bytes]:
        from . import _mac_seeds
        return _mac_seeds.seeds(self.key)

    def structure_mutate(self, data: bytes, rng):
        from . import _mac_seeds
        return _mac_seeds.structure_mutate(self.key, data, rng)

    def coverage_features(self, data: bytes, result: ExecResult):
        """Return guard features captured by an instrumented driver run.

        A non-instrumented or libFuzzer harness emits no map, so ``None`` keeps
        the generic engine on its deterministic fallback schedule.
        """
        return self._coverage_by_input.get(data)

    # --- lifecycle -------------------------------------------------------
    def prepare(self) -> None:
        with self._lifecycle_lock:
            self._harness_path = self.resolve_harness()

    def cleanup(self) -> None:
        with self._lifecycle_lock:
            self._harness_path = None

    def _run(self, data: bytes) -> ExecResult:
        harness = self._harness_path
        if harness is None:
            # Concurrent executes on a shared instance: another thread's
            # cleanup() may have nulled the cached path between our prepare()
            # and this read. Re-resolve (idempotent, cheap) instead of
            # reporting a spurious "not built" abnormal result.
            harness = self.resolve_harness()
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
        coverage = tempfile.NamedTemporaryFile(
            prefix="ios-research-sancov-", suffix=".map", delete=False)
        coverage.close()
        try:
            tmp.write(data)
            tmp.flush()
            tmp.close()
            result = self._run_harness(harness, tmp.name, start, coverage.name)
            features = SanitizerCoverageFileAdapter.read(
                coverage.name, f"mac:{self.key}")
            if features is not None:
                self._coverage_by_input[data] = features
            return result
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
            try:
                os.unlink(coverage.name)
            except OSError:
                pass

    def _run_harness(self, harness: Path, input_path: str,
                     start: float, coverage_path: str | None = None) -> ExecResult:
        import time

        # libFuzzer binaries run a single input to completion when given a file
        # argument, then exit. ASAN_OPTIONS keeps the report on stderr and exits
        # (rather than re-raising) so we capture a full, parseable report.
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS",
                       "abort_on_error=0:exitcode=99:detect_leaks=0")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
        if coverage_path is not None:
            env[_SANCOV_ENV] = coverage_path
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

    @staticmethod
    def build_libfuzzer_command(harness: Path, corpus_dir: str,
                                artifact_dir: str, *, runs: int,
                                workers: int,
                                max_total_time: float | None = None,
                                value_profile: bool = False,
                                dictionary: str | None = None,
                                max_len: int | None = None) -> list[str]:
        """Build the libFuzzer argv. Exposed for tests and campaign provenance.

        #30: ``value_profile`` opts into comparison/value-profile guidance
        (requires a harness built with ``-fsanitize-coverage=trace-cmp``).
        """
        cmd = [str(harness), corpus_dir,
               f"-artifact_prefix={artifact_dir}/",
               f"-runs={runs}",
               # -fork enables -ignore_crashes so the run collects MANY
               # crash artifacts instead of stopping at the first.
               f"-fork={max(1, workers)}", "-ignore_crashes=1",
               "-print_final_stats=1"]
        if value_profile:
            cmd.append("-use_value_profile=1")
        if dictionary:
            cmd.append(f"-dict={dictionary}")
        if max_len:
            cmd.append(f"-max_len={max_len}")
        if max_total_time is not None:
            cmd.append(f"-max_total_time={int(max_total_time)}")
        return cmd

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

    # --- in-process persistent-mode libFuzzer (#20) ----------------------
    def is_libfuzzer(self) -> bool:
        """True if the resolved harness is a libFuzzer build (vs. the driver).

        Probed by asking the binary for its help: libFuzzer prints its flag list
        (``-runs``/``-max_total_time``); the standalone driver treats ``-help=1``
        as a filename and prints its ``RUN``/``DONE`` protocol instead.
        """
        harness = self._harness_path or self.resolve_harness()
        if harness is None:
            return False
        try:
            proc = subprocess.run([str(harness), "-help=1"],
                                  capture_output=True, timeout=self.timeout_s)
        except (OSError, subprocess.TimeoutExpired):
            return False
        blob = (proc.stdout + proc.stderr).decode("utf-8", "replace")
        return ("libFuzzer" in blob or "-runs=" in blob
                or "-max_total_time" in blob)

    def fuzz_corpus(self, seeds: list[bytes], *, runs: int = 100_000,
                    max_total_time: float | None = None, workers: int = 1,
                    artifact_dir: str | None = None,
                    value_profile: bool = False,
                    dictionary: str | None = None,
                    max_len: int | None = None,
                    corpus_dir: str | None = None
                    ) -> tuple[list[tuple[bytes, ExecResult]], dict]:
        """Run libFuzzer's in-process persistent loop over a seeded corpus.

        This is the high-throughput path (#20): libFuzzer mutates and executes
        in-process (no per-input process/dlopen cost), forks workers to run in
        parallel, and writes each crashing input to ``artifact_prefix``. We then
        re-run each unique crash artifact once through the same binary to capture
        a clean ASan report and normalize it via :mod:`asan`.

        ``value_profile=True`` passes ``-use_value_profile=1`` (#30), enabling
        comparison/value-profile-guided mutation for builds compiled with
        ``-fsanitize-coverage=trace-cmp``.

        ``dictionary`` is an optional libFuzzer token-dictionary path;
        ``max_len`` bounds generated input size; ``corpus_dir`` persists the
        fuzzing corpus across calls when given (otherwise a temp dir is used).

        Returns ``(unique_crashes, stats)`` where ``unique_crashes`` is a list of
        ``(crashing_input, ExecResult)`` deduped by signature. Requires a
        libFuzzer build (see :meth:`is_libfuzzer`).
        """
        import glob
        import shutil
        import tempfile
        import time

        self.prepare()
        try:
            harness = self._harness_path
            if harness is None:
                return [], {"error": "harness not built", "runs": 0}
            if not self.is_libfuzzer():
                return [], {"error": "harness is not a libFuzzer build "
                            "(rebuild with: build.sh --libfuzzer)", "runs": 0}

            owns_art = artifact_dir is None
            artifact_dir = artifact_dir or tempfile.mkdtemp(
                prefix="ios-research-lf-art-")
            owns_corpus = corpus_dir is None
            corpus_dir = corpus_dir or tempfile.mkdtemp(
                prefix="ios-research-lf-corpus-")
            os.makedirs(corpus_dir, exist_ok=True)
            try:
                for i, s in enumerate(seeds or [b"\x00"]):
                    with open(os.path.join(corpus_dir, f"seed_{i:06d}"), "wb") as fh:
                        fh.write(s)

                cmd = self.build_libfuzzer_command(
                    harness, corpus_dir, artifact_dir, runs=runs,
                    workers=workers, max_total_time=max_total_time,
                    value_profile=value_profile, dictionary=dictionary,
                    max_len=max_len)

                env = dict(os.environ)
                env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
                start = time.monotonic()
                budget = (max_total_time or self.timeout_s) + self.timeout_s
                try:
                    proc = subprocess.run(cmd, capture_output=True, env=env,
                                          timeout=budget)
                    blob = (proc.stdout + proc.stderr).decode("utf-8", "replace")
                except subprocess.TimeoutExpired:
                    blob = ""
                elapsed = time.monotonic() - start

                # Collect crash artifacts and normalize each unique one.
                unique: list[tuple[bytes, ExecResult]] = []
                seen: set[str] = set()
                timeouts: list[bytes] = []
                seen_timeouts: set[str] = set()
                arts = sorted(glob.glob(os.path.join(artifact_dir, "crash-*"))
                              + glob.glob(os.path.join(artifact_dir, "oom-*"))
                              + glob.glob(os.path.join(artifact_dir, "timeout-*")))
                for art in arts:
                    try:
                        with open(art, "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    res = self._run(data)  # single-input re-run -> ASan report
                    if res.outcome == Outcome.CRASH and res.diagnostics:
                        sig = res.diagnostics.signature
                        if sig not in seen:
                            seen.add(sig)
                            unique.append((data, res))
                    elif res.outcome == Outcome.TIMEOUT:
                        # Confirmed hang: keep it visible in stats instead of
                        # silently dropping the finding (#190). The raw input
                        # stays on disk as libFuzzer's timeout-* artifact.
                        import hashlib
                        digest = hashlib.sha256(data).hexdigest()
                        if digest not in seen_timeouts:
                            seen_timeouts.add(digest)
                            timeouts.append(data)

                executed = _parse_lf_runs(blob)
                stats = {
                    "runs": executed if executed is not None else runs,
                    "elapsed_s": round(elapsed, 2),
                    "exec_per_s": (round(executed / elapsed, 1)
                                   if executed and elapsed else None),
                    "artifacts": len(arts),
                    "unique_crashes": len(unique),
                    "unique_timeouts": len(timeouts),
                    "value_profile": bool(value_profile),
                    "corpus_dir": corpus_dir,
                }
                return unique, stats
            finally:
                if owns_corpus:
                    shutil.rmtree(corpus_dir, ignore_errors=True)
                if owns_art:
                    shutil.rmtree(artifact_dir, ignore_errors=True)
        finally:
            self.cleanup()


def _parse_lf_runs(blob: str) -> "int | None":
    """Extract the executed-run count from libFuzzer's final stats, if present."""
    import re
    m = re.search(r"stat::number_of_executed_units:\s*(\d+)", blob)
    if m:
        return int(m.group(1))
    m = re.search(r"\bDone\s+(\d+)\s+runs\b", blob)
    return int(m.group(1)) if m else None


def build_targets() -> dict[str, type]:
    """Return the ``{target_id: factory}`` mapping for registration."""
    return _FRAMEWORKS


MAC_FRAMEWORKS = _FRAMEWORKS
