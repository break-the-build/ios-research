"""Workspace-global crash signature dedup (#264).

Locks in the #264 contract: the crash record id is derived from
``(target, signature)`` only — never from the discovering experiment — so two
experiments that hit the same diagnostic signature share ONE canonical record.
Re-discovery bumps ``count``/``last_seen`` and appends the contributing
experiment to ``experiment_ids``; legacy records persisted before #264 (no
``experiment_ids`` key) keep loading and scope exactly like single-contributor
records. The same signature under a different target stays distinct.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.crashes import CrashStore
from ios_research.errors import ExitCode, ValidationError
from ios_research.targets import create
from ios_research.targets.base import Outcome

# mock:parser defect-rule inputs with stable, distinct signatures:
NULL_DISPATCH = b"MOCK\x01\xff\x00\x00"       # rule 2 -> NULL_DEREFERENCE
OOB_READ = b"MOCK\x01\x01\xff\xff"            # rule 1 -> OUT_OF_BOUNDS_READ


def _crash(workspace, data, experiment_id="exp1", target="mock:parser"):
    store = CrashStore(workspace)
    res = create(target).execute(data)
    assert res.outcome == Outcome.CRASH, res.outcome
    return store.record(experiment_id=experiment_id, target=target,
                        fmt="mock-record", data=data, exec_result=res)


# --- one signature, two experiments => ONE record -----------------------------
def test_two_experiments_share_one_record_for_one_signature(workspace):
    store = CrashStore(workspace)
    c1 = _crash(workspace, NULL_DISPATCH, experiment_id="exp-a")
    c2 = _crash(workspace, NULL_DISPATCH, experiment_id="exp-b")

    assert c1.id == c2.id                        # canonical record is shared
    assert len(store.list()) == 1                # no duplicate record created
    merged = store.get(c1.id)
    assert merged.count == 2                     # occurrence rolled up
    assert sorted(merged.experiment_ids) == ["exp-a", "exp-b"]
    assert merged.experiment_id == "exp-a"       # first contributor is stable

    # Both contributing experiments see the record via scoped list()/get().
    for exp in ("exp-a", "exp-b"):
        assert [c.id for c in store.list(experiment_id=exp)] == [c1.id]
        assert store.get(c1.id, experiment_id=exp).id == c1.id


def test_bump_count_attributes_a_later_experiment(workspace):
    """The _flush_crashes re-discovery path: bumping a known record from a new
    experiment rolls the count forward AND records the attribution (#264)."""
    store = CrashStore(workspace)
    crash = _crash(workspace, OOB_READ, experiment_id="exp-a")

    store.bump_count(crash.id, 3, experiment_id="exp-b")
    merged = store.get(crash.id)
    assert merged.count == 4
    assert sorted(merged.experiment_ids) == ["exp-a", "exp-b"]
    assert [c.id for c in store.list(experiment_id="exp-b")] == [crash.id]

    # Scoping by an experiment that never contributed still fails closed.
    with pytest.raises(ValidationError, match="not in experiment"):
        store.get(crash.id, experiment_id="exp-c")
    assert store.list(experiment_id="exp-c") == []


def test_fuzz_sessions_across_experiments_converge_on_one_record(tmp_path):
    """End-to-end: two default fuzz sessions (fresh experiments) over the same
    deterministic stream produce ONE shared record per signature instead of
    one per session — the campaign amnesia from #264."""
    from ios_research import __version__
    from ios_research.workspace import Workspace

    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")

    def run_session(tag):
        from ios_research.corpus import CorpusStore
        from ios_research.experiment import ExperimentStore
        from ios_research.fuzz import FuzzEngine
        # Distinct config_hash per session => distinct experiment id even
        # under the suite's frozen clock.
        exp = ExperimentStore(ws).create(
            target="mock:parser", device="mock:device", os_version="17.0",
            config_hash=f"c-{tag}", seed=1)
        cs = CorpusStore(ws)
        corpus = cs.create(f"corp-{tag}")
        cs.add_bytes(corpus, b"MOCK\x01\x01\x00\x02ok", origin="seed")
        engine = FuzzEngine(ws)
        session = engine.create(experiment_id=exp.id, target="mock:parser",
                                corpus_id=corpus.id, seed=1, workers=1,
                                max_cases=200, duration_s=None)
        return engine.advance(session)

    s1 = run_session(tag="one")
    s2 = run_session(tag="two")                  # same stream, new experiment
    assert s1.experiment_id != s2.experiment_id

    assert s1.crash_ids and s2.crash_ids
    assert set(s1.crash_ids) == set(s2.crash_ids)
    store = CrashStore(ws)
    assert len(store.list()) == len(set(s1.crash_ids))
    for cid in set(s1.crash_ids):
        merged = store.get(cid)
        assert merged.count >= 2                 # seen by both sessions
        assert len(merged.experiment_ids) == 2   # both experiments attributed


# --- back-compat --------------------------------------------------------------
def test_legacy_record_without_experiment_ids_loads_and_scopes(workspace):
    """A record persisted before #264 has no ``experiment_ids`` key; it must
    load, list, and scope exactly like a single-contributor record."""
    crash = _crash(workspace, NULL_DISPATCH, experiment_id="exp-old")
    rel = f"crashes/{crash.id}/crash.json"
    doc = workspace.read_json(rel)
    del doc["experiment_ids"]
    workspace.write_json(rel, doc)

    store = CrashStore(workspace)
    loaded = store.get(crash.id)
    assert loaded.experiment_ids == ["exp-old"]  # backfilled at load time
    assert [c.id for c in store.list()] == [crash.id]
    assert [c.id for c in store.list(experiment_id="exp-old")] == [crash.id]
    assert store.get(crash.id, experiment_id="exp-old").id == crash.id
    # ...and an unrelated experiment still does not see it.
    assert store.list(experiment_id="exp-new") == []
    with pytest.raises(ValidationError, match="not in experiment"):
        store.get(crash.id, experiment_id="exp-new")


def test_same_signature_under_different_targets_stays_distinct(workspace):
    """#264 scopes the dedup key per TARGET: identical diagnostics reached via
    two targets (v2 shares defect rule 1 => identical signature) remain two
    records."""
    store = CrashStore(workspace)
    v1 = _crash(workspace, OOB_READ, experiment_id="e1",
                target="mock:parser")
    v2 = _crash(workspace, OOB_READ, experiment_id="e1",
                target="mock:parser-v2")

    assert v1.signature == v2.signature          # same diagnostics...
    assert v1.id != v2.id                        # ...but per-target identity
    assert len(store.list()) == 2


# --- CLI surface --------------------------------------------------------------
class TestCrashListNewOnly:
    """`crash list --new-only` through the real CLI JSON envelope."""

    def _run(self, ws, *argv, expect=ExitCode.OK):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([*argv, "--json", "--workspace", str(ws), "--yes"])
        payload = json.loads(buf.getvalue())
        assert code == expect, (argv, code, payload)
        return payload

    def test_new_only_returns_untouched_records(self, tmp_path):
        ws = tmp_path / ".ios-research"
        self._run(ws, "init")
        self._run(ws, "fuzz", "start", "--target", "mock:parser",
                  "--max-cases", "200", "--seed", "5")

        listed = self._run(ws, "crash", "list")
        fresh = self._run(ws, "crash", "list", "--new-only")

        assert listed["ok"] is True and listed["data"]["count"] >= 1
        # No stage transitions status today, so the new-only view matches all
        # records; each item carries its status so agents can verify.
        assert fresh["data"]["count"] == listed["data"]["count"]
        assert all(c["status"] == "new" for c in fresh["data"]["crashes"])
        assert {c["id"] for c in fresh["data"]["crashes"]} == \
            {c["id"] for c in listed["data"]["crashes"]}

    def test_new_only_excludes_worked_records(self, tmp_path):
        from ios_research.workspace import Workspace

        wspath = tmp_path / ".ios-research"
        self._run(wspath, "init")
        self._run(wspath, "fuzz", "start", "--target", "mock:parser",
                  "--max-cases", "200", "--seed", "5")
        cid = self._run(wspath, "crash", "list")["data"]["crashes"][0]["id"]

        # Simulate a future status transition ("worked"): the view must drop it.
        ws = Workspace(wspath)
        rel = f"crashes/{cid}/crash.json"
        doc = ws.read_json(rel)
        doc["status"] = "analyzed"
        ws.write_json(rel, doc)

        fresh = self._run(wspath, "crash", "list", "--new-only")
        assert cid not in {c["id"] for c in fresh["data"]["crashes"]}
        assert fresh["data"]["count"] == \
            self._run(wspath, "crash", "list")["data"]["count"] - 1
