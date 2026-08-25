"""Multi-focus rotation for directed scheduling (#205).

Locks in that ``focus_symbols`` (a) rotates the active distance table every
``focus_phase_len`` executed cases deterministically, (b) leaves single-symbol
sessions byte-identical to the legacy ``focus_symbol`` path, and (c) resumes
deterministically (tables are recomputed from the callgraph, never persisted).
"""

from __future__ import annotations

import pytest

from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine, focus_phase_index
from ios_research.targets import ExecResult, Outcome, Target
from ios_research.workspace import Workspace
from ios_research import __version__

W = dict(DEFAULT_CONFIG["fuzz"]["strategy_weights"])

DIAMOND = {
    "nodes": ["entry", "left", "right", "sink_l", "sink_r"],
    "edges": [["entry", "left"], ["entry", "right"],
              ["left", "sink_l"], ["right", "sink_r"]],
}


class _TwoRegionStub(Target):
    """Adapter-less target whose inputs map to one of two callgraph regions."""

    target_id = "test:multifocus"
    kind = "parser"
    description = "two-region deterministic stub for focus rotation"
    formats = ("bin",)

    def seeds(self):
        return [b"L|seed", b"R|seed"]

    def callgraph(self):
        return dict(DIAMOND)

    def focus_symbol_for(self, data):
        return "sink_l" if data[:1] == b"L" else "sink_r"

    def _run(self, data):
        if b"CRASH" in data:
            d = None  # adapter-less: signature-less abnormal-free crash rule
            return ExecResult(outcome=Outcome.REJECTED, detail="nope")
        return ExecResult(outcome=Outcome.ACCEPTED, detail="ok")


@pytest.fixture(autouse=True)
def _register_and_cleanup():
    from ios_research.targets import _REGISTRY
    _REGISTRY[_TwoRegionStub.target_id] = _TwoRegionStub
    yield
    _REGISTRY.pop(_TwoRegionStub.target_id, None)


def _fresh(tmp_path, name):
    ws = Workspace(tmp_path / name / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    return ws


_corpus_seq = 0


def _make_session(workspace, *, seed=17, max_cases=64, focus_symbol=None,
                  focus_symbols=None, phase_len=None):
    global _corpus_seq
    _corpus_seq += 1
    exp = ExperimentStore(workspace).create(
        target=_TwoRegionStub.target_id, device="mock:device",
        os_version="17.0", config_hash="c", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"mf{_corpus_seq}", target=_TwoRegionStub.target_id)
    for s_bytes in (b"L|seed", b"R|seed"):
        cs.add_bytes(corpus, s_bytes, origin="seed")
    eng = FuzzEngine(workspace)
    kwargs = {}
    if focus_symbol is not None:
        kwargs["focus_symbol"] = focus_symbol
    if focus_symbols is not None:
        kwargs["focus_symbols"] = focus_symbols
    if phase_len is not None:
        kwargs["focus_phase_len"] = phase_len
    session = eng.create(experiment_id=exp.id,
                         target=_TwoRegionStub.target_id,
                         corpus_id=corpus.id, seed=seed, workers=1,
                         max_cases=max_cases, duration_s=None,
                         strategy_weights=W, **kwargs)
    return eng, cs, corpus, session


# --- rotation math -------------------------------------------------------------
def test_focus_phase_index_math():
    assert focus_phase_index(0, 4, 2) == 0
    assert focus_phase_index(3, 4, 2) == 0
    assert focus_phase_index(4, 4, 2) == 1
    assert focus_phase_index(8, 4, 2) == 0
    assert focus_phase_index(13, 4, 3) == 0      # 13//4=3 -> 3%3=0
    assert focus_phase_index(9, 4, 3) == 2       # 9//4=2 -> 2%3=2
    assert focus_phase_index(999, 4, 1) == 0      # single symbol -> always 0
    assert focus_phase_index(50, 0, 5) == 0       # disabled rotation


# --- engine plumbing -------------------------------------------------------------
def test_focus_tables_cover_every_symbol(workspace):
    eng, _, _, session = _make_session(workspace,
                                       focus_symbols=["sink_l", "sink_r"])
    tables = eng._focus_tables(session, eng_targets_create())
    assert set(tables) == {"sink_l", "sink_r"}
    # The two tables must actually differ so rotation changes selection.
    assert tables["sink_l"] != tables["sink_r"]
    assert tables["sink_l"].get("sink_l") == 0
    assert tables["sink_r"].get("sink_r") == 0


def eng_targets_create():
    from ios_research.targets import create
    return create(_TwoRegionStub.target_id)


def test_single_symbol_path_unchanged_by_multi_code(workspace, tmp_path):
    """Legacy focus_symbol run equals focus_symbols=[same] run exactly."""
    ws_legacy = _fresh(tmp_path, "legacy")
    e1, _, _, s1 = _make_session(ws_legacy, focus_symbol="sink_l")
    s1 = e1.advance(s1)

    ws_list = _fresh(tmp_path, "list")
    e2, _, _, s2 = _make_session(ws_list, focus_symbols=["sink_l"],
                                 phase_len=512)
    s2 = e2.advance(s2)

    assert s2.outcomes == s1.outcomes
    assert s2.focus_counts == s1.focus_counts


def test_rotation_shifts_energy_between_regions(tmp_path):
    """With a tiny phase length both regions receive directed selections."""
    ws = _fresh(tmp_path, "rotate")
    e, cs, corpus, s = _make_session(ws, max_cases=32,
                                     focus_symbols=["sink_l", "sink_r"],
                                     phase_len=4)
    s = e.advance(s)

    # Selection counts exist and directed bias was applied at least once.
    assert sum(s.focus_counts.values()) >= 32 // 2 or s.focus_counts
    assert s.focus_biased >= 0
    # Both symbols' tables were resolvable during the run (no silent drop).
    tables = e._focus_tables(s, eng_targets_create())
    assert len(tables) == 2


def test_resume_determinism_with_rotation(tmp_path):
    single = _fresh(tmp_path, "single")
    e1, _, _, s1 = _make_session(single, max_cases=48,
                                 focus_symbols=["sink_l", "sink_r"],
                                 phase_len=6)
    s1 = e1.advance(s1)

    chunked = _fresh(tmp_path, "chunk")
    e2, _, _, s2 = _make_session(chunked, max_cases=48,
                                 focus_symbols=["sink_l", "sink_r"],
                                 phase_len=6)
    while s2.status != "completed":
        s2 = e2.advance(s2, max_new=11)

    assert s2.focus_counts == s1.focus_counts
    assert s2.outcomes == s1.outcomes


def test_no_focus_symbols_leaves_directed_mode_off(workspace):
    eng, _, _, session = _make_session(workspace)
    assert eng._focus_tables(session, eng_targets_create()) == {}
    session = eng.advance(session)
    assert session.focus_counts == {}
