"""Tests for directed greybox fuzzing (#73)."""

from __future__ import annotations

import json

import pytest

from ios_research import targets as tgt
from ios_research.cli import main
from ios_research.corpus import CorpusStore
from ios_research.directed import (
    focus_summary, load_callgraph, objective_symbols_from_findings,
    selection_weight, target_distances, weighted_selection,
)
from ios_research.errors import ValidationError
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine


@pytest.fixture(autouse=True)
def _unregister_stub_target():
    """Keep the in-test stub out of the global registry (suite pollution)."""
    yield
    tgt._REGISTRY.pop("stub:directed", None)

DIAMOND = {
    "nodes": ["a", "b", "c", "d", "e", "sink"],
    "edges": [["a", "b"], ["a", "c"], ["b", "d"], ["c", "d"],
              ["d", "sink"], ["e", "a"]],
}


def test_load_callgraph_validates_and_builds():
    graph = load_callgraph(DIAMOND)
    assert graph["nodes"] == {"a", "b", "c", "d", "e", "sink"}
    assert graph["reverse"]["sink"] == ["d"]
    assert graph["adjacency"]["a"] == ["b", "c"]


@pytest.mark.parametrize("bad", [
    "not a dict",
    {"nodes": "nope", "edges": []},
    {"nodes": ["a"], "edges": [["a"]]},
    {"edges": [["a", "b"]]},
])
def test_load_callgraph_rejects_malformed(bad):
    with pytest.raises(ValidationError):
        load_callgraph(bad if isinstance(bad, dict) else {"x": bad})


def test_target_distances_diamond_and_unreachable():
    graph = load_callgraph(DIAMOND)
    distances = target_distances(graph, {"sink"})
    assert distances["sink"] == 0
    assert distances["d"] == 1
    assert distances["b"] == 2 and distances["c"] == 2
    assert distances["a"] == 3
    assert distances["e"] == 4  # e -> a -> b/c -> d -> sink


def test_target_distances_multi_target_min():
    graph = load_callgraph({"nodes": ["x", "y", "z"],
                            "edges": [["x", "y"], ["x", "z"]]})
    distances = target_distances(graph, {"y", "z"})
    assert distances == {"y": 0, "z": 0, "x": 1}


def test_selection_weight_table():
    assert selection_weight(None) == 1
    assert [selection_weight(d) for d in range(6)] == [16, 8, 4, 2, 1, 1]


def test_weighted_selection_fractional_fair():
    entries = [("near", 0), ("far", None)]
    counts: dict[str, int] = {}
    picks = []
    for _ in range(24):
        chosen = weighted_selection(entries, counts)
        counts[chosen] = counts.get(chosen, 0) + 1  # caller-side, as engine
        picks.append(chosen)
    assert picks[0] == "far"          # 0/1 ties break on sha
    assert picks[1:17] == ["near"] * 16   # then weight-16 dominates
    assert counts["near"] == 22 and counts["far"] == 2
    # Deterministic: identical accounting reproduces the identical sequence.
    counts2: dict[str, int] = {}
    picks2 = []
    for _ in range(24):
        chosen = weighted_selection(entries, counts2)
        counts2[chosen] = counts2.get(chosen, 0) + 1
        picks2.append(chosen)
    assert picks == picks2


def test_weighted_selection_requires_entries():
    with pytest.raises(ValidationError):
        weighted_selection([], {})


def test_objective_symbols_from_findings():
    objectives = [
        {"finding_id": "f1", "file": "src/app/db.py", "line": 1},
        {"finding_id": "f2", "file": "app/parser.c", "line": 9},
        {"finding_id": "f3", "file": "", "line": 3},
    ]
    assert objective_symbols_from_findings(objectives) == {"db", "parser"}
    assert objective_symbols_from_findings([]) == set()


def test_machsim_callgraph_distances():
    graph = load_callgraph(tgt.create("mach:sim").callgraph())
    distances = target_distances(graph, {"copyin_ool_region"})
    assert distances["copyin_ool_region"] == 0
    assert distances["descriptor_walk"] == 1
    assert distances["ipc_kmsg_copyin"] == 2
    assert distances["mach_msg"] == 3
    assert "map_reuse_page" not in distances


def test_base_callgraph_hook_default_none():
    assert tgt.create("mock:parser").callgraph() is None


# --- engine integration ------------------------------------------------------------
class _DirectedStubTarget(tgt.base.Target):
    target_id = "stub:directed"
    kind = "parser"
    description = "stub with callgraph"
    formats = ("bin",)

    def seeds(self):
        return [b"A", b"B"]

    def callgraph(self):
        return {"nodes": ["entry", "sink"],
                "edges": [["entry", "sink"]]}

    def focus_symbol_for(self, data):
        return "sink" if data[:1] == b"A" else "entry"

    def _run(self, data):
        from ios_research.targets.base import ExecResult, Outcome
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok",
                          duration_ms=1)


def _campaign(ctx, *, focus=None, cases=12):
    tgt.register("stub:directed", lambda: _DirectedStubTarget())
    store = CorpusStore(ctx.workspace())
    existing = [c for c in store.list() if c.name == "dir-corpus"]
    corpus = existing[0] if existing else \
        store.create("dir-corpus", target="stub:directed")
    if not corpus.testcases:
        for seed in (b"A" * 4, b"B" * 4):
            store.add_bytes(corpus, seed, origin="seed")
    experiment = ExperimentStore(ctx.workspace()).create(
        target="stub:directed", device="dev", os_version="1",
        config_hash="h", seed=3, params={})
    engine = FuzzEngine(ctx.workspace())
    session = engine.create(experiment_id=experiment.id,
                            target="stub:directed", corpus_id=corpus.id,
                            seed=3, workers=1, max_cases=cases,
                            duration_s=None,
                            focus_symbol=focus or "")
    session = engine.advance(session, max_new=cases)
    return session


def test_engine_focus_computes_distances_and_biases(ctx):
    session = _campaign(ctx, focus="sink", cases=16)
    assert session.focus_distances == {"entry": 1, "sink": 0}
    # Per-entry distances resolved through focus_symbol_for: the "A" seed
    # exercises sink (0), the "B" seed exercises entry (1).
    assert sorted(session.focus_entry_distances.values(),
                  key=lambda d: (d is None, d)) == [0, 1]
    assert sum(session.focus_counts.values()) >= 8   # corpus path engaged
    # Both entries carry weight > 1 (16 and 8): every selection is biased.
    assert session.focus_biased == sum(session.focus_counts.values())
    # Weight-16 entry dominates weight-8 entry under fractional fairness.
    counts = session.focus_counts
    near_sha = [sha for sha, d in session.focus_entry_distances.items()
                if d == 0][0]
    far_sha = [sha for sha, d in session.focus_entry_distances.items()
               if d == 1][0]
    assert counts.get(near_sha, 0) >= counts.get(far_sha, 0)


def test_engine_focus_resume_deterministic(ctx):
    import tempfile
    from ios_research.context import Context
    from ios_research.workspace import Workspace
    from ios_research import __version__
    from ios_research.clock import now_iso

    def fresh():
        ws = Workspace(tempfile.mkdtemp() / ".ios-research") \
            if False else None
    # Split run: advance(8) then resume(8) must match one advance(16).
    s_full = _campaign(ctx, focus="sink", cases=16)

    ws2 = Workspace(ctx.workspace().root.parent / "ws2")
    ws2.init(framework_version=__version__, created_at=now_iso())
    ctx2 = Context(workspace_path=str(ws2.root), assume_yes=True)
    tgt.register("stub:directed", lambda: _DirectedStubTarget())
    store = CorpusStore(ws2)
    corpus = store.create("dir-corpus", target="stub:directed")
    for seed in (b"A" * 4, b"B" * 4):
        store.add_bytes(corpus, seed, origin="seed")
    experiment = ExperimentStore(ws2).create(
        target="stub:directed", device="dev", os_version="1",
        config_hash="h", seed=3, params={})
    engine = FuzzEngine(ws2)
    half = engine.create(experiment_id=experiment.id,
                         target="stub:directed", corpus_id=corpus.id,
                         seed=3, workers=1, max_cases=16, duration_s=None,
                         focus_symbol="sink")
    half = engine.advance(half, max_new=8)
    half = engine.resume(half, max_new=8)
    assert half.focus_counts == s_full.focus_counts
    assert half.focus_biased == s_full.focus_biased


def test_engine_without_focus_unchanged(ctx):
    session = _campaign(ctx, focus=None, cases=10)
    assert session.focus_distances == {}
    assert session.focus_counts == {} and session.focus_biased == 0
    # Legacy coverage schedule untouched.
    assert isinstance(session.coverage_selection_counts, dict)


def test_engine_focus_without_callgraph_hook_is_inert(ctx):
    session = _campaign(ctx, focus="nonexistent_symbol", cases=4)
    # Stub has a graph but the symbol is unknown -> empty distances.
    assert session.focus_distances == {}
    assert session.focus_counts == {}


def test_stats_includes_focus_block(ctx):
    session = _campaign(ctx, focus="sink", cases=4)
    stats = session.stats()
    assert stats["focus"]["symbol"] == "sink"
    assert "biased_selections" in stats["focus"]
    plain = _campaign(ctx, focus=None, cases=2).stats()
    assert plain["focus"] == {}


# --- CLI surface -----------------------------------------------------------------------
def test_cli_fuzz_start_focus_symbol(ctx, capsys):
    rc = main(["fuzz", "start", "--target", "mach:sim",
               "--focus-symbol", "copyin_ool_region",
               "--max-cases", "6", "--json",
               "--workspace", str(ctx.workspace().root)])
    envelope = json.loads(capsys.readouterr().out.strip())
    assert rc == 0, envelope
    focus = envelope["data"]["stats"]["focus"]
    assert focus["symbol"] == "copyin_ool_region"
    assert focus["targets_reachable"] >= 1
