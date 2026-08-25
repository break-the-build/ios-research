"""Issue #206 tests: opt-in post-run corpus distillation.

``Agent.run(distill_corpus=True)`` distills the ``agent-{target}`` pipeline
corpus *after* triage completes (never mid-advance), preserving
regression-origin entries verbatim. With the flag off, the returned dict is
unchanged.
"""

from __future__ import annotations

import json

from ios_research.agent import Agent
from ios_research.context import Context
from ios_research.corpus import CorpusStore
from ios_research.fuzz import DEFAULT_BASE
from ios_research.schema import build_cli_schema
from ios_research.cli import main


def _ctx(workspace) -> Context:
    return Context(workspace_path=str(workspace.root), assume_yes=True)


def _regression_shas(store: CorpusStore, corpus):
    return {tc["sha256"] for tc in store.get(corpus.id).testcases
            if tc.get("origin") == "regression"}


# --- flag-off golden equivalence ---------------------------------------------
def test_distill_off_omits_key_and_matches_baseline(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    runs = []
    for name, kwargs in (("base", {}),
                         ("off", {"distill_corpus": False})):
        ws = Workspace(tmp_path / name / ".ios-research")
        ws.init(framework_version=__version__, created_at="t")
        res = Agent(Context(workspace_path=str(ws.root))).run(
            target="mock:parser", seed=7, max_cases=150,
            minimize=False, **kwargs)
        assert "corpus_distillation" not in res
        res.pop("experiment_id")  # workspace-derived; irrelevant to the delta
        runs.append(res)
    assert runs[0] == runs[1]


def test_cli_run_without_flag_omits_key(workspace, capsys):
    main(["agent", "run", "--json", "--target", "mock:parser",
          "--max-cases", "60", "--workspace", str(workspace.root)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert "corpus_distillation" not in payload["data"]


# --- flag-on behavior ---------------------------------------------------------
def test_distill_on_reports_delta_math(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    agent = Agent(Context(workspace_path=str(ws.root)))
    res = agent.run(target="mock:parser", seed=3, max_cases=200,
                    minimize=False, distill_corpus=True)
    d = res["corpus_distillation"]
    assert d["ran"] is True
    assert d["before"] >= d["after"] >= 1
    assert d["behaviors"] >= 1 and d["kept_features"] >= 1
    # The manifest on disk matches the reported post-distillation size.
    store = CorpusStore(ws)
    corpus = agent._pipeline_corpus("mock:parser")
    assert len(store.get(corpus.id).testcases) == d["after"]


def test_distill_preserves_regression_entries_verbatim(tmp_path):
    from ios_research.workspace import Workspace
    from ios_research import __version__
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    agent = Agent(Context(workspace_path=str(ws.root)))
    store = CorpusStore(ws)
    corpus = agent._pipeline_corpus("mock:parser")

    # Regression-origin entries a plain minimization would drop: b"yyyy"
    # shares the reject-header feature AND the rejected behavior of b"zzzz".
    dropped = b"yyyy"
    kept_unique = b"MOCK\x07\x01\x00\x02uniq"  # not among the auto-seeds
    captured = {
        dropped: (b"zzzz", None),
        kept_unique: (b"MOCK\x02\x01\x00\x02x", "deadbeef"),
    }
    for data, (parent_seed, parent_sha) in (
            (dropped, (b"zzzz", None)), (kept_unique, (b"MOCK\x02\x01\x00\x02x", "deadbeef"))):
        parent = parent_sha or (
            __import__("hashlib").sha256(parent_seed).hexdigest())
        store.add_bytes(corpus, data, origin="regression", parent=parent)
    pre = {tc["sha256"]: tc for tc in store.get(corpus.id).testcases}
    regression_pre = {sha: tc for sha, tc in pre.items()
                      if tc.get("origin") == "regression"}
    assert len(regression_pre) == 2

    res = agent.run(target="mock:parser", seed=5, max_cases=150,
                    minimize=False, distill_corpus=True)
    assert res["corpus_distillation"]["ran"] is True

    after = {tc["sha256"]: tc for tc in store.get(corpus.id).testcases}
    # Every regression-origin entry survives verbatim: same bytes, same
    # origin, same parent lineage — even the one minimization dropped.
    from ios_research.hashing import sha256_bytes
    expected_bytes = {sha256_bytes(dropped): dropped,
                      sha256_bytes(kept_unique): kept_unique}
    for sha, tc in regression_pre.items():
        assert sha in after
        restored = after[sha]
        assert restored["origin"] == "regression"
        assert restored["parent"] == tc["parent"]
        assert store.read_bytes(store.get(corpus.id), sha) == \
            expected_bytes[sha]
    # And no regression lineage was lost relative to the pre-run manifest.
    assert set(regression_pre) <= set(after)


def test_distill_bounded_growth_shrinks_and_keeps_features(tmp_path):
    """Sequential-run accumulation collapses toward distinct behaviors while
    every originally-covered coverage_feature stays represented."""
    from ios_research.workspace import Workspace
    from ios_research import __version__
    ws = Workspace(tmp_path / ".ios-research")
    ws.init(framework_version=__version__, created_at="t")
    agent = Agent(Context(workspace_path=str(ws.root)))
    store = CorpusStore(ws)
    corpus = agent._pipeline_corpus("mock:parser")

    # Simulate several accumulated sessions: duplicate-behavior entries with
    # overlapping feature annotations (the metadata path fuzz retains).
    v = "mock-parser:v1"
    batches = [
        # accepted duplicates, overlapping features across entries
        [(b"MOCK\x01\x01\x00\x02aa", [f"{v}:valid-header"]),
         (b"MOCK\x03\x01\x00\x02bb", [f"{v}:valid-header", f"{v}:accepted"]),
         (b"MOCK\x04\x01\x00\x02cc", [f"{v}:accepted"])],
        # rejected duplicates sharing one feature
        [(b"zzzz", [f"{v}:reject-header"]),
         (b"yyyy", [f"{v}:reject-header"]),
         (b"wwww", [f"{v}:reject-header"])],
        # distinct behaviors
        [(b"MOCK\x01\x01\xff\xff", [f"{v}:valid-header", f"{v}:null-dispatch"])],
    ]
    for batch in batches:
        for data, features in batch:
            assert store.add_bytes(corpus, data, origin="seed",
                                   coverage_features=features) is not None
    before_manifest = store.get(corpus.id).testcases
    original_features = set()
    for tc in before_manifest:
        original_features.update(tc["coverage_features"])
    n_before = len(before_manifest)

    # max_cases=0 keeps the fuzz phase inert so the corpus at distillation
    # time is exactly the simulated accumulated state.
    res = agent.run(target="mock:parser", seed=9, max_cases=0,
                    minimize=False, distill_corpus=True)
    d = res["corpus_distillation"]
    assert d["ran"] is True
    assert d["before"] == n_before
    # Kept set = feature set-cover UNION one representative per distinct
    # behavior, so it is at least the behavior count and strictly smaller
    # than the accumulated corpus.
    assert d["after"] >= d["behaviors"]
    assert d["after"] < n_before
    # ...while every originally-covered feature remains represented.
    # Representation follows minimize()'s own semantics: entries with empty
    # stored metadata have their features re-derived from the target adapter.
    from ios_research.targets import create as target_create
    t = target_create("mock:parser")
    surviving = set()
    for tc in store.get(corpus.id).testcases:
        feats = set(tc["coverage_features"])
        if not feats:
            data = store.read_bytes(store.get(corpus.id), tc["sha256"])
            prov = t.coverage_features(data, t.execute(data))
            feats = set(prov or ())
        surviving.update(feats)
    assert original_features <= surviving
    assert d["kept_features"] == len(original_features)


# --- CLI / schema exposure ----------------------------------------------------
def test_cli_run_with_flag_reports_distillation(workspace, capsys):
    main(["agent", "run", "--json", "--target", "mock:parser",
          "--max-cases", "60", "--distill-corpus",
          "--workspace", str(workspace.root)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["data"]["corpus_distillation"]["ran"] is True


def test_agent_run_schema_exposes_distill_corpus():
    schema = build_cli_schema()
    run_cmd = schema["commands"]["agent"]["subcommands"]["run"]
    options = run_cmd["arguments"]["options"]
    flag = [o for o in options if "--distill-corpus" in o["flags"]]
    assert len(flag) == 1
    assert flag[0]["dest"] == "distill_corpus"
    assert flag[0]["required"] is False
    assert "between sessions" in flag[0]["help"]
    assert "mid-advance" in flag[0]["help"]
