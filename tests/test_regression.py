"""Phase 10 regression tests: replay the regression corpus.

Minimization seeds a 'regression' corpus with minimized crashing inputs. This
test guards against future changes silently altering known crash behavior: every
regression testcase must still crash its target with the recorded signature.
"""

from __future__ import annotations

from ios_research.agent import Agent
from ios_research.context import Context
from ios_research.corpus import CorpusStore
from ios_research.crashes import CrashStore
from ios_research.targets import create
from ios_research.targets.base import Outcome


def test_regression_corpus_inputs_still_crash(workspace):
    ctx = Context(workspace_path=str(workspace.root), assume_yes=True)
    # Discover + minimize crashes -> populates the 'regression' corpus.
    Agent(ctx).run(target="mock:parser", seed=1, max_cases=200, minimize=True)

    store = CorpusStore(workspace)
    regression = next((c for c in store.list() if c.name == "regression"), None)
    assert regression is not None and regression.testcases

    # Known crash signatures for this target.
    known = {c.signature for c in CrashStore(workspace).list()}
    target = create("mock:parser")
    for tc in regression.testcases:
        data = store.read_bytes(regression, tc["sha256"])
        res = target.execute(data)
        assert res.outcome in (Outcome.CRASH, Outcome.ABNORMAL)
        assert res.diagnostics.signature in known


def test_regression_minimized_inputs_are_small(workspace):
    ctx = Context(workspace_path=str(workspace.root), assume_yes=True)
    Agent(ctx).run(target="audio:wav", seed=2, max_cases=200, minimize=True)
    store = CorpusStore(workspace)
    regression = next((c for c in store.list() if c.name == "regression"), None)
    assert regression is not None
    # Minimized crash inputs should be compact.
    assert all(tc["size"] <= 64 for tc in regression.testcases)
