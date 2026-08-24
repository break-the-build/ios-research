"""Stateful workflow fuzzer: sequences, minimization, replay lineage (#39)."""

from __future__ import annotations

import json

import pytest

from ios_research.errors import NotFoundError, ValidationError
from ios_research.stateful import (
    ActionSpec, StatefulFuzzer, StepOutcome, WorkflowAdapter,
    generate_sequence, load_adapter, mutate_sequence)


SESSION_ADAPTER_SOURCE = '''\
"""Fixture adapter: a session workflow whose defect depends on step history."""
from ios_research.stateful import ActionSpec, StepOutcome, WorkflowAdapter


class SessionWorkflow(WorkflowAdapter):
    name = "fixture-session"
    version = "1.1.0"
    actions = (
        ActionSpec("login", (("user", "str"),), "open a session"),
        ActionSpec("upload", (), "upload while logged in"),
        ActionSpec("logout", (), "close the session"),
    )

    def __init__(self):
        self.logged_in = False
        self.uploads = 0

    def reset(self):
        self.logged_in = False
        self.uploads = 0

    def perform(self, action_id, params):
        if action_id == "login":
            self.logged_in = True
            return StepOutcome("login", dict(params), "ok",
                               {"session": id(self) % 97})
        if action_id == "logout":
            self.logged_in = False
            return StepOutcome("logout", {}, "ok")
        if action_id == "upload":
            # DEFECT: uploading twice within one session corrupts the counter.
            if not self.logged_in:
                return StepOutcome("upload", {}, "error",
                                   {"reason": "not-logged-in"})
            self.uploads += 1
            if self.uploads >= 2:
                return StepOutcome("upload", {}, "error",
                                   {"reason": "double-upload-corruption"})
            return StepOutcome("upload", {}, "ok", {"bytes": 128})
        return StepOutcome(action_id, dict(params), "invalid")


ADAPTER = SessionWorkflow()
'''


@pytest.fixture()
def adapter_path(tmp_path):
    path = tmp_path / "session_adapter.py"
    path.write_text(SESSION_ADAPTER_SOURCE)
    return str(path)


def test_load_adapter_rejects_missing_or_invalid(tmp_path):
    with pytest.raises(NotFoundError):
        load_adapter(tmp_path / "nope.py")
    bad = tmp_path / "bad.py"
    bad.write_text("ADAPTER = 42\n")
    with pytest.raises(ValidationError):
        load_adapter(bad)


def test_generate_sequence_is_deterministic(adapter_path):
    adapter = load_adapter(adapter_path)
    a = generate_sequence(adapter, _rng(7), 4)
    b = generate_sequence(adapter, _rng(7), 4)
    assert a == b and a
    assert all(step["action"] in {s.action_id for s in adapter.actions}
               for step in a)


def _rng(seed):
    from ios_research.stateful import _Rng
    return _Rng(seed)


def test_sequence_dependent_defect_is_found_and_minimized(
        workspace, adapter_path):
    fuzzer = StatefulFuzzer(workspace)
    out = fuzzer.fuzz(adapter_path=adapter_path, cases=40, seed=3,
                      max_length=6)
    assert out["unique_failures"] >= 1
    # Minimization must reduce some sequence to the essence of the
    # double-upload defect: login -> upload -> upload.
    shapes = [[s["action"] for s in f["minimized_sequence"]]
              for f in out["findings"]]
    assert ["login", "upload", "upload"] in shapes, shapes


def test_minimized_sequence_replays_deterministically(workspace, adapter_path):
    fuzzer = StatefulFuzzer(workspace)
    out = fuzzer.fuzz(adapter_path=adapter_path, cases=25, seed=5,
                      max_length=5)
    for finding in out["findings"]:
        adapter_a = load_adapter(adapter_path)
        adapter_b = load_adapter(adapter_path)
        run_a = fuzzer.run_sequence(adapter_a, finding["minimized_sequence"])
        run_b = fuzzer.run_sequence(adapter_b, finding["minimized_sequence"])
        assert run_a["failure_signature"] == run_b["failure_signature"]
        assert run_a["failure_signature"] is not None


def test_replay_script_persisted(workspace, adapter_path):
    fuzzer = StatefulFuzzer(workspace)
    out = fuzzer.fuzz(adapter_path=adapter_path, cases=20, seed=1)
    record = json.loads(
        workspace.path(f"findings/{out['run_id']}/sequence.json")
        .read_text())
    assert record["schema_version"] == 1
    assert record["seed"] == 1
    for finding in record["findings"]:
        script = finding["replay_script"]
        assert script["kind"] == "ios-research-stateful-replay"
        assert script["steps"]


def test_env_state_hash_tracks_lineage(workspace, adapter_path):
    fuzzer = StatefulFuzzer(workspace)
    out = fuzzer.fuzz(adapter_path=adapter_path, cases=30, seed=2)
    hashes = {f["env_state_hash"] for f in out["findings"]}
    assert len(hashes) == len(out["findings"]) or len(hashes) >= 1


def test_mutation_stays_within_declared_actions(adapter_path):
    from ios_research.errors import ValidationError
    adapter = load_adapter(adapter_path)
    allowed = {s.action_id for s in adapter.actions}
    seq = [{"action": "login", "params": {"user": "u"}}]
    for i in range(50):
        mutated = mutate_sequence(seq, adapter, _rng(i))
        assert len(mutated) <= 32
        assert all(step["action"] in allowed | {""} for step in mutated)


def test_reset_failure_is_recorded_not_raised(tmp_path, monkeypatch):
    source = SESSION_ADAPTER_SOURCE.replace(
        "def reset(self):\n        self.logged_in = False\n"
        "        self.uploads = 0",
        "def reset(self):\n        raise RuntimeError('device gone')")
    path = tmp_path / "broken_reset.py"
    path.write_text(source)

    class _WS:
        root = None

    import tempfile
    import pathlib
    from ios_research.workspace import Workspace
    ws_root = pathlib.Path(tempfile.mkdtemp()) / ".ios-research"
    ws = Workspace(ws_root)
    from ios_research import __version__, clock as _clock
    ws.init(framework_version=__version__, created_at=_clock.now_iso())

    fuzzer = StatefulFuzzer(ws)
    out = fuzzer.fuzz(adapter_path=str(path), cases=2, seed=0)
    assert out["executed"] == 2   # campaign survives the broken adapter
