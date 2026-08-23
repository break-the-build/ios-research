"""JavaScriptCore/WebKit semantic fuzzing target profile (#46).

Closes the semantic-engine gap on Apple platforms: instead of byte mutation,
this profile consumes **semantically valid JavaScript programs** and executes
them through an authorized, *user-built* JavaScriptCore shell.

Two executor modes:

* ``mock`` (default, CI-safe): a deterministic in-process interpreter stub
  that derives outcomes and stable coverage features from the program's
  structure. It exists so the whole pipeline — generation, execution,
  coverage feedback, minimization, reporting — can be exercised anywhere
  without a JavaScript engine.
* ``shell`` (opt-in, ``mock = False``): runs a user-supplied binary
  (``IOS_RESEARCH_JSC_SHELL``) implementing the tiny stdin/stdout contract of
  ``tools/harness/jsc_shell``-style runners: print ``COVER <id>`` lines while
  executing, exit non-zero with an ASan/UBSan report on defect. Reports are
  normalized through :mod:`ios_research.targets.asan` exactly like the macOS
  framework targets.

Integration is designed around an external semantic generator such as
Fuzzilli through a local adapter (``generator_path`` pointing at a module
exposing ``GENERATOR.next_program(rng)``); nothing here ships browser
exploitation or sandbox-escape payloads — it feeds authorized shells with
generated programs and records what happens.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
from pathlib import Path

from .base import ExecResult, Outcome, Target
from . import asan

SHELL_ENV = "IOS_RESEARCH_JSC_SHELL"
DEFAULT_TIMEOUT_S = 10.0

_COVER_RE = re.compile(r"^COVER\s+(?P<id>[A-Za-z0-9_.:\-]+)\s*$",
                       re.MULTILINE)


class ProgramGenerator:
    """Deterministic built-in generator over a small JS template grammar."""

    FUNCTIONS = (
        ("parseHeader", b"function parseHeader(s){ return s.length | 0; }"),
        ("sumTyped", b"function sumTyped(a){ var t=0;"
                     b" for (var i=0;i<a.length;i++) t+=a[i]|0; return t|0; }"),
        ("buildMap", b"function buildMap(n){ var m=new Map();"
                     b" for(var i=0;i<n;i++) m.set(i,i*2); return m.size|0; }"),
        ("deepProp", b"function deepProp(o){ try { return o.a.b.c|0; }"
                     b" catch(e){ return -1; } }"),
        ("regexScan", b"function regexScan(s){ return (s.match(/ab+c/g)||[])"
                     b".length|0; }"),
    )
    CALLS = (
        b'parseHeader("abc");',
        b'sumTyped(new Int32Array([1,2,3]));',
        b'buildMap(8);',
        b'deepProp({a:{b:{c:7}}});',
        b'regexScan("abbbc");',
    )

    def __init__(self):
        self.functions_used: list[str] = []

    def next_program(self, rng) -> bytes:
        """Compose a valid program: definitions plus a call sequence."""
        picks = [rng.randrange(len(self.FUNCTIONS))
                 for _ in range(rng.randint(2, len(self.FUNCTIONS)))]
        picks = sorted(set(picks))
        body = [self.FUNCTIONS[i][1] for i in picks]
        calls = [self.CALLS[rng.randrange(len(self.CALLS))]
                 for _ in range(rng.randint(1, 4))]
        self.functions_used = [self.FUNCTIONS[i][0] for i in picks]
        return b"\n".join(body + calls) + b"\n"


def load_external_generator(path: str | Path):
    """Load a Fuzzilli-compatible local adapter exposing GENERATOR."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"generator not found: {path}")
    spec = importlib.util.spec_from_file_location(
        f"iosr_jscgen_{abs(hash(str(path)))}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)   # user-declared, trusted code
    generator = getattr(module, "GENERATOR", None)
    if generator is None or not callable(
            getattr(generator, "next_program", None)):
        raise ValueError("module exposes no GENERATOR with next_program()")
    return generator


def minimize_program(program: bytes, crashes_with, max_rounds: int = 24
                     ) -> bytes:
    """Token-aware delta-debugging preserving the crashing behavior.

    Splits on statement/token boundaries so shrunk programs stay syntactically
    plausible, unlike byte-level ddmin.
    """
    tokens = _split_tokens(program)

    def still_crashes(blob: bytes) -> bool:
        return blob and crashes_with(blob)

    current = tokens
    changed = True
    rounds = 0
    while changed and len(current) > 1 and rounds < max_rounds:
        changed = False
        rounds += 1
        half = len(current) // 2
        for candidate in (current[:half], current[half:],
                          current[:half] + current[half + 1:]):
            joined = b"".join(candidate)
            if still_crashes(joined):
                current = candidate
                changed = True
                break
    return b"".join(current)


def _split_tokens(program: bytes) -> list[bytes]:
    parts: list[bytes] = []
    for line in program.splitlines(keepends=True):
        pieces = re.split(rb"(?<=[;{}])\s*", line)
        parts.extend(p for p in pieces if p)
    return parts or [program]


class JSCSemanticTarget(Target):
    """Semantic JavaScript program target with pluggable executors."""

    kind = "jsc-semantic"
    description = ("authorized JavaScriptCore semantic fuzzing "
                   "(mock executor by default)")

    def __init__(self, *, executor: str = "mock",
                 timeout_s: float = DEFAULT_TIMEOUT_S):
        if executor not in ("mock", "shell"):
            raise ValueError("executor must be 'mock' or 'shell'")
        self.executor = executor
        self.mock = executor == "mock"
        self.target_id = "jsc:semantic"
        self.formats = ("js",)
        self.timeout_s = timeout_s
        self._features_by_input: dict[bytes, tuple[str, ...]] = {}

    # --- registry metadata ---------------------------------------------------
    def describe(self):
        d = super().describe()
        d["executor"] = self.executor
        d["entry_point"] = ("LLVMFuzzerTestOneInput (user-built JSC shell)"
                            if not self.mock else
                            "deterministic mock interpreter")
        d["external_generator"] = "Fuzzilli-compatible local adapter optional"
        d["available"] = True if self.mock else \
            bool(os.environ.get(SHELL_ENV))
        return d

    def blocker(self) -> str:
        if self.mock:
            return ""
        return (f"set ${SHELL_ENV} to your authorized, locally built "
                f"JavaScriptCore shell binary")

    # --- seeds / coverage ----------------------------------------------------
    def seeds(self) -> list[bytes]:
        gen = ProgramGenerator()
        import random
        rng = random.Random(0)
        return [gen.next_program(rng) for _ in range(3)]

    def coverage_features(self, data: bytes, result: ExecResult):
        return self._features_by_input.get(data)

    # --- execution -----------------------------------------------------------
    def prepare(self) -> None:  # pragma: no cover - trivial
        pass

    def cleanup(self) -> None:  # pragma: no cover - trivial
        pass

    def _run(self, data: bytes) -> ExecResult:
        if self.executor == "mock":
            return self._run_mock(data)
        return self._run_shell(data)

    # mock executor -------------------------------------------------------------
    def _run_mock(self, data: bytes) -> ExecResult:
        features: list[str] = ["jsc:entry"]
        for name, _src in ProgramGenerator.FUNCTIONS:
            fname = name.encode()
            if b"function " + fname in data:
                features.append(f"jsc:def:{name}")
                if fname + b"(" in data.split(b"function " + fname)[0]:
                    continue
                if b"\n" + fname + b"(" in b"\n" + data or \
                        data.rstrip().endswith(b");"):
                    features.append(f"jsc:call:{name}")
        if b"CRASHMARKER" in data:
            diag = asan.parse(
                "==1==ERROR: AddressSanitizer: SEGV on unknown address "
                "0x000000000000\nSUMMARY: AddressSanitizer: SEGV jsc_mock.c:3 "
                "in mock_dispatch\n", module="JSC-Mock")
            return ExecResult(outcome=Outcome.CRASH,
                              detail="mock interpreter dispatched crash "
                                     "marker",
                              duration_ms=1, diagnostics=diag)
        if b"SYNTAX!" in data and data.count(b"{") != data.count(b"}"):
            return ExecResult(outcome=Outcome.REJECTED,
                              detail="program rejected: unbalanced braces",
                              duration_ms=1)
        self._features_by_input[data] = tuple(sorted(set(features)))
        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail="program executed cleanly",
                          duration_ms=1)

    # shell executor --------------------------------------------------------------
    def _run_shell(self, data: bytes) -> ExecResult:
        import tempfile
        import time
        shell = os.environ.get(SHELL_ENV)
        if not shell or not Path(shell).is_file():
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=self.blocker(), duration_ms=0)
        start = time.monotonic()
        tmp = tempfile.NamedTemporaryFile(prefix="iosr-jsc-", suffix=".js",
                                          delete=False)
        try:
            tmp.write(data)
            tmp.close()
            env = dict(os.environ)
            env.setdefault(
                "ASAN_OPTIONS", "abort_on_error=0:exitcode=99:detect_leaks=0")
            proc = subprocess.run([shell, tmp.name], capture_output=True,
                                  env=env, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail=f"shell exceeded {self.timeout_s}s",
                              duration_ms=int((time.monotonic() - start)
                                              * 1000))
        except OSError as exc:
            return ExecResult(outcome=Outcome.ABNORMAL,
                              detail=f"failed to execute shell: {exc}",
                              duration_ms=0)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        dur = int((time.monotonic() - start) * 1000)
        report = (proc.stderr or b"").decode("utf-8", "replace")
        stdout = (proc.stdout or b"").decode("utf-8", "replace")

        covers = _COVER_RE.findall(stdout)
        if covers:
            self._features_by_input[data] = tuple(sorted(
                {f"jsc:cover:{c}" for c in covers}))

        if proc.returncode == 0:
            if asan.is_crash_report(report):
                return ExecResult(outcome=Outcome.CRASH,
                                  detail=report.splitlines()[0][:500],
                                  duration_ms=max(dur, 1),
                                  diagnostics=asan.parse(report,
                                                         module="JavaScriptCore"))
            return ExecResult(outcome=Outcome.ACCEPTED,
                              detail="program executed without finding",
                              duration_ms=max(dur, 1))
        if asan.is_crash_report(report):
            return ExecResult(outcome=Outcome.CRASH,
                              detail=report.splitlines()[0][:500],
                              duration_ms=max(dur, 1),
                              diagnostics=asan.parse(report,
                                                     module="JavaScriptCore"))
        return ExecResult(outcome=Outcome.ABNORMAL,
                          detail=(report.strip().splitlines()[-1][:500]
                                  if report.strip()
                                  else f"shell exited {proc.returncode}"),
                          duration_ms=max(dur, 1))


def register(registry_register) -> None:
    registry_register("jsc:semantic", lambda: JSCSemanticTarget())
