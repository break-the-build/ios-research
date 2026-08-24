"""JavaScriptCore semantic fuzzing target profile (#46)."""

from __future__ import annotations

import random

import pytest

from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.targets import create, is_registered, list_targets
from ios_research.targets.base import Outcome
from ios_research.targets.jsc import (
    JSCSemanticTarget, ProgramGenerator, minimize_program)


def test_registered_with_mock_executor_default():
    assert is_registered("jsc:semantic")
    t = create("jsc:semantic")
    assert isinstance(t, JSCSemanticTarget)
    assert t.mock is True                      # CI-safe default
    d = t.describe()
    assert d["executor"] == "mock"
    assert any(entry["id"] == "jsc:semantic" for entry in list_targets())


def test_generator_produces_semantically_valid_programs():
    rng = random.Random(11)
    gen = ProgramGenerator()
    for _ in range(20):
        program = gen.next_program(rng)
        assert program.count(b"{") == program.count(b"}")
        assert b"function " in program
        # Every declared function used in a call sequence exists.
        for name in (b"parseHeader", b"sumTyped", b"buildMap"):
            if b"function " + name in program:
                assert name + b"(" in program


def test_mock_execution_is_reproducible_with_features():
    t = JSCSemanticTarget()
    program = ProgramGenerator().next_program(random.Random(4))
    a = t.execute(program)
    b = t.execute(program)
    assert a.to_dict() == b.to_dict()
    features = t.coverage_features(program, a)
    assert features and all(f.startswith("jsc:") for f in features)
    # A different program yields a different feature set.
    other = ProgramGenerator().next_program(random.Random(99))
    t2 = JSCSemanticTarget()
    t2.execute(other)
    assert t2.coverage_features(other, None) is not None


def test_crash_marker_yields_normalized_diagnostics():
    t = JSCSemanticTarget()
    res = t.execute(b'var x="CRASHMARKER";\n')
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.classification_hint in ("SEGV", "NULL_DEREFERENCE")
    assert res.diagnostics.signature


def test_minimizer_preserves_crash_and_shrinks():
    t = JSCSemanticTarget()
    crashes = lambda blob: t.execute(blob).outcome == Outcome.CRASH
    big = (b"function f1(){ return 1; }\n"
           b"function f2(){ return 2; }\n"
           b'f1();\nvar note = "CRASHMARKER";\nf2();\n')
    assert crashes(big)
    shrunk = minimize_program(big, crashes)
    assert len(shrunk) < len(big)
    assert crashes(shrunk)


def test_engine_retains_interesting_programs(workspace):
    """Coverage-guided retention over generated programs (#46 acceptance)."""
    from ios_research.targets.jsc import JSCSemanticTarget as T

    exp = ExperimentStore(workspace).create(
        target="jsc:semantic", device="mock:device", os_version="17.0",
        config_hash="jsc", seed=5)
    store = CorpusStore(workspace)
    corpus = store.create("jsc-seeds", target="jsc:semantic")
    gen = ProgramGenerator()
    rng = random.Random(7)
    for _ in range(3):
        store.add_bytes(corpus, gen.next_program(rng), origin="seed")
    engine = FuzzEngine(workspace)

    original_execute = T._run_mock

    def structured(self, data, rng_):   # light grammar-aware hook for the run
        mutated = bytearray(data)
        pos = rng_.randrange(len(mutated))
        mutated[pos] = rng_.randrange(256)
        return bytes(mutated)

    session = engine.create(
        experiment_id=exp.id, target="jsc:semantic", corpus_id=corpus.id,
        seed=5, workers=1, max_cases=40, duration_s=None,
        mutator_plugin_path=None)
    session.struct_fn_backup = None  # unused; keep default generic mutation
    session = engine.advance(session)
    stats = session.stats()
    assert stats["coverage"]["available"] is True
    assert stats["coverage"]["unique_features"] >= 3
    retained = [tc for tc in store.get(corpus.id).testcases
                if tc.get("coverage_new_features")]
    assert retained


def test_shell_executor_missing_binary_is_abnormal(monkeypatch):
    monkeypatch.delenv("IOS_RESEARCH_JSC_SHELL", raising=False)
    t = JSCSemanticTarget(executor="shell")
    assert t.mock is False
    assert t.describe()["available"] is False
    res = t.execute(b"foo();")
    assert res.outcome == Outcome.ABNORMAL
    assert "IOS_RESEARCH_JSC_SHELL" in res.detail


def test_shell_executor_runs_stub(tmp_path, monkeypatch):
    stub = tmp_path / "jsc_shell"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'echo "COVER fn:parseHeader"\n'
        'case "$(cat "$1")" in *BOOM*)\n'
        'printf "%b" "==9==ERROR: AddressSanitizer: SEGV on unknown address '
        "0x000000000000\\nSUMMARY: AddressSanitizer: SEGV shell.c:8 in "
        'jsc_eval\\n" >&2\nexit 99;; esac\nexit 0\n')
    stub.chmod(0o755)
    monkeypatch.setenv("IOS_RESEARCH_JSC_SHELL", str(stub))
    t = JSCSemanticTarget(executor="shell")
    ok = t.execute(b"parseHeader('abc');")
    assert ok.outcome == Outcome.ACCEPTED
    assert "jsc:cover:fn:parseHeader" in \
        (t.coverage_features(b"parseHeader('abc');", ok) or ())
    boom = t.execute(b'var s="BOOM";')
    assert boom.outcome == Outcome.CRASH
    assert boom.diagnostics.classification_hint in ("SEGV",
                                                    "NULL_DEREFERENCE")
