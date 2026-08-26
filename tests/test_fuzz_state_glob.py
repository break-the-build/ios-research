"""Regression: dictionary sidecars must not be read as fuzz session records.

A guided-fuzz session persists its dictionary next to the session record as
``fuzz/<id>.dict.json``. ``Workspace.list_json("fuzz")`` globs ``*.json``, so
the sidecar was swept up as a "session" and ``_session_from_dict`` raised
``StateError("fuzz session record is corrupt or from an incompatible
version")`` — breaking `fuzz status`, `fuzz stats` and `fuzz list` for the
whole workspace as soon as ANY session used a dictionary (#289).
"""

from __future__ import annotations

import pytest

from ios_research.errors import StateError
from ios_research.fuzz import FuzzEngine, FuzzSession


def _session(sid="fz_regtest") -> FuzzSession:
    return FuzzSession(
        id=sid, experiment_id="exp_x", target="test:t", corpus_id="cor_x",
        seed=1, workers=1, max_cases=10, duration_s=None)


def test_dict_sidecar_is_not_a_session(workspace):
    eng = FuzzEngine(workspace)
    eng.save(_session())
    ws = workspace
    ws.write_json("fuzz/fz_regtest.dict.json",
                  {"schema": 1, "tokens": [{"kw": "IDAT", "b": "SUQB"}]})

    sessions = eng.list()
    assert [s.id for s in sessions] == ["fz_regtest"]


def test_sidecar_tokens_still_loadable(workspace):
    """The exclusion only affects list(); tokens_for() keeps working."""
    eng = FuzzEngine(workspace)
    s = _session()
    eng.save(s)
    workspace.write_json(eng._dict_rel(s.id),
                         {"schema": 1,
                          "tokens": [{"name": "moov", "hex": "6d6f6f76"}]})
    toks = eng.tokens_for(s)
    assert toks is not None and len(toks) == 1


def test_broken_real_session_still_raises_stateerror(workspace):
    """The guard for genuinely corrupt records stays intact."""
    eng = FuzzEngine(workspace)
    workspace.write_json("fuzz/fz_bad.json", {"schema": 1})
    with pytest.raises(StateError):
        eng.list()
