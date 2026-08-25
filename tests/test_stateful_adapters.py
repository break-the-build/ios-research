"""Campaign-config adapters for the stateful engine (#228 §5).

The adapters in tools/stateful/ model PQ3 and Wi-Fi Aware sessions over the
framework's own CI-safe mock targets. These tests pin their contracts:
ordering defects only fire with the right history, and the engine finds them
deterministically.
"""

from __future__ import annotations

from pathlib import Path

from ios_research.stateful import StatefulFuzzer, load_adapter

REPO = Path(__file__).resolve().parents[1]
PQ3 = REPO / "tools" / "stateful" / "pq3_session_adapter.py"
WA = REPO / "tools" / "stateful" / "wifiaware_session_adapter.py"


def _adapter(path):
    a = load_adapter(path)
    a.reset()
    return a


def test_pq3_ordering_defects_need_history():
    a = _adapter(PQ3)
    # rekey before handshake -> session-state error
    out = a.perform("rekey", {})
    assert out.status == "error" and out.observation["reason"] == \
        "not-handshaked"
    # replay before anything was freed -> nothing-stale
    out = a.perform("replay_stale", {})
    assert out.status == "invalid"

    # correct history: handshake frees epoch 0, then poisoned replay is the
    # use-after-free family
    assert a.perform("handshake", {}).status == "ok"
    assert a.perform("advance_epoch", {}).status == "ok"
    out = a.perform("replay_stale", {"poison": True})
    assert out.status == "error"
    assert "use_after_free" in out.observation["detail"] or \
        "stale" in out.observation["detail"]


def test_wifiaware_reclaim_then_use_is_uaf_family():
    a = _adapter(WA)
    assert a.perform("start_publish", {"service": "s"}).status == "ok"
    # send before reclaim uses a live buffer -> ok
    assert a.perform("send_frame", {"stage": 1}).status == "ok"
    assert a.perform("reclaim", {}).status == "ok"
    # send after reclaim touches the dead buffer -> error family
    out = a.perform("send_frame", {"stage": 1})
    assert out.status == "error"


def test_wifiaware_subscribe_requires_publish():
    a = _adapter(WA)
    out = a.perform("subscribe", {})
    assert out.status == "error" and out.observation["reason"] == \
        "not-publishing"


def test_engine_finds_designed_defects_deterministically(tmp_path):
    ws_dir = tmp_path / "ws"
    ws_dir.mkdir()
    from ios_research.workspace import Workspace
    fuzzer = StatefulFuzzer(Workspace(ws_dir))
    for path in (PQ3, WA):
        result = fuzzer.fuzz(adapter_path=str(path), cases=24, seed=7,
                             max_length=6)
        sigs = {f["signature"] for f in result["findings"]}
        assert result["executed"] == 24
        # both adapters must surface at least one genuine ordering defect
        assert sigs, f"{path.name}: engine found no defects"
