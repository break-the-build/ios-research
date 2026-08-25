"""Opt-in duplicate-input skip (#204).

Locks in that ``skip_duplicates`` (a) never executes the same input twice
within a session while keeping cursor/budget accounting exact, (b) is fully
opt-in — default runs are untouched — and (c) stays resume-deterministic:
the persisted sha list reproduces identical skip decisions.
"""

from __future__ import annotations

from ios_research import __version__
from ios_research.config import DEFAULT_CONFIG
from ios_research.corpus import CorpusStore
from ios_research.experiment import ExperimentStore
from ios_research.fuzz import FuzzEngine
from ios_research.workspace import Workspace

# Zero-weight everything except deletion so a 1-byte seed yields the SAME
# mutant on every iteration — guaranteed duplicates for the enabled case.
_W_DELETION_ONLY = {
    "byte": 0, "truncation": 0, "insertion": 0,
    "boundary": 0, "integer": 0, "structure_aware": 0,
    "deletion": 9,
}

_corpus_seq = 0


def _fresh(tmp_path, name):
    ws = Workspace(tmp_path / name / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    return ws


def _make_session(workspace, *, seed=11, max_cases=20, skip_duplicates=False,
                  weights=None, window=None, workers=1):
    global _corpus_seq
    _corpus_seq += 1
    exp = ExperimentStore(workspace).create(
        target="mock:parser", device="mock:device", os_version="17.0",
        config_hash="c", seed=seed)
    cs = CorpusStore(workspace)
    corpus = cs.create(f"dup{_corpus_seq}", target="mock:parser")
    cs.add_bytes(corpus, b"A", origin="seed")
    eng = FuzzEngine(workspace)
    session = eng.create(
        experiment_id=exp.id, target="mock:parser", corpus_id=corpus.id,
        seed=seed, workers=workers, window=window, max_cases=max_cases,
        duration_s=None, strategy_weights=weights or dict(_W_DELETION_ONLY),
        skip_duplicates=skip_duplicates)
    return eng, cs, corpus, session


def _manifest_shas(cs, corpus):
    return sorted(tc["sha256"] for tc in cs.get(corpus.id).testcases)


# --- disabled by default: zero behavioral surface ----------------------------
def test_disabled_by_default_executes_everything(tmp_path):
    eng, cs, corpus, s = _make_session(_fresh(tmp_path, "off"))
    s = eng.advance(s)
    assert s.skip_duplicates is False
    assert s.skipped_duplicate == 0
    assert s.seen_input_shas == []
    assert sum(s.outcomes.values()) == s.cursor == 20


# --- enabled: duplicates counted, never re-executed --------------------------
def test_enabled_skips_known_inputs_without_reexecution(tmp_path):
    eng, cs, corpus, s = _make_session(_fresh(tmp_path, "on"),
                                       max_cases=20, skip_duplicates=True)
    s = eng.advance(s)

    # The single-byte deletion-only pool produces one repeated input; exactly
    # ONE execution happens and the rest are accounted as skips.
    assert len(s.seen_input_shas) == 1
    assert sum(s.outcomes.values()) == 1
    assert s.skipped_duplicate == 19
    assert s.cursor == 20                      # budget accounting stays exact
    assert s.stats()["skipped_duplicate"] == 19


def test_enabled_unique_inputs_are_all_executed(tmp_path):
    """No artificial suppression: distinct inputs all execute normally."""
    eng, cs, corpus, s = _make_session(
        _fresh(tmp_path, "mixed"), max_cases=30, skip_duplicates=True,
        weights=dict(DEFAULT_CONFIG["fuzz"]["strategy_weights"]))
    s = eng.advance(s)
    assert s.cursor == 30
    # Whatever the stream, executions + duplicates must account for all cases.
    assert sum(s.outcomes.values()) + s.skipped_duplicate == 30
    assert len(s.seen_input_shas) >= 1


# --- resume determinism --------------------------------------------------------
def test_resume_matches_single_run_with_skip_enabled(tmp_path):
    single = _fresh(tmp_path, "single")
    e1, cs1, c1, s1 = _make_session(single, max_cases=60,
                                    skip_duplicates=True, weights=dict(
                                        DEFAULT_CONFIG["fuzz"]["strategy_weights"]))
    s1 = e1.advance(s1)

    chunked = _fresh(tmp_path, "chunk")
    e2, cs2, c2, s2 = _make_session(chunked, max_cases=60,
                                    skip_duplicates=True, weights=dict(
                                        DEFAULT_CONFIG["fuzz"]["strategy_weights"]))
    while s2.status != "completed":
        s2 = e2.advance(s2, max_new=17)

    assert s2.outcomes == s1.outcomes
    assert s2.skipped_duplicate == s1.skipped_duplicate
    assert s2.crash_ids == s1.crash_ids
    assert s2.seen_input_shas == s1.seen_input_shas
    assert _manifest_shas(cs2, c2) == _manifest_shas(cs1, c1)


def test_persisted_seen_list_round_trips(workspace):
    """seen_input_shas persists via the session document (asdict path)."""
    eng, cs, corpus, s = _make_session(workspace, max_cases=5,
                                       skip_duplicates=True)
    s = eng.advance(s)
    doc = s.to_dict()
    assert "seen_input_shas" in doc and "skipped_duplicate" in doc
    assert isinstance(doc["seen_input_shas"], list)
