"""Tests for tools/smb-rig: Durable case storage (cases.py), run stats and byte-exact replay (triage.py)."""

from __future__ import annotations

import os
import random
import struct
import threading
from pathlib import Path

import pytest
from smb_rig_support import (
    FuzzSession,
    K,
    Knobs,
    cases,
    corpus,
    make_seeds,
    mutators,
    qi_body,
    record_conn,
    req,
    rsp,
    smb2,
    triage,
)


@pytest.fixture()
def seeds(tmp_path):
    """Seed corpus directory shared by this file's tests."""
    return make_seeds(tmp_path)


def test_case_writer_unique_runs_and_index(tmp_path):
    w1 = cases.CaseWriter(str(tmp_path), 1, {})
    w2 = cases.CaseWriter(str(tmp_path), 1, {})
    assert w1.dir != w2.dir                                  # restart never overwrites
    saved = w1.save(0, "CREATE", b"abc", "len@80:0x0->0x1\twith tab")
    assert saved.number == 1 and Path(saved.path).read_bytes() == b"abc"
    lines = (Path(w1.dir) / "INDEX.tsv").read_text().splitlines()
    assert lines[0].split("\t") == list(cases.CaseWriter.INDEX_COLUMNS)
    assert len(lines[1].split("\t")) == len(cases.CaseWriter.INDEX_COLUMNS)


def test_durable_write_fsyncs_before_return(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    cases.durable_write(str(tmp_path / "c.rsp"), b"x")
    assert len(synced) >= 2                                  # file + directory


def test_read_index_roundtrip_and_torn_line(seeds, tmp_path):
    w = record_conn(seeds, tmp_path, K(budget=1, p_mutate=1.0))
    with open(w.index, "a") as f:
        f.write("0000999\t2026-")                             # torn by a panic mid-write
    rows = cases.read_index(w.dir)
    assert len(rows) == w.n and rows[-1].kind == "UNKNOWN_REQ" and rows[-1].path.endswith(".unknown")
    assert sum(r.mutated for r in rows) >= 1 and rows[0].req == 1
    assert cases.latest_run(str(tmp_path / "cases")) == w.dir
    assert cases.latest_run(str(tmp_path / "nothing")) is None


def test_run_stats_depth_and_suspects(seeds, tmp_path):
    w = record_conn(seeds, tmp_path, K(budget=2, p_mutate=1.0))
    st = triage.run_stats(cases.read_index(w.dir))
    assert st.conns == 1 and st.reached["CREATE"] == 1 and st.reached["QUERY_INFO"] == 1
    assert st.reached["READ"] == 0 and st.mutated >= 1 and st.suspects
    text = "\n".join(triage.format_stats(st))
    assert "CREATE=1(100%)" in text and "panic suspects" in text
    assert triage.format_stats(triage.run_stats([]))[0].startswith("connections=0")


def test_patch_message_ids_preserves_corrupt_chain_and_notifications():
    good = smb2.join_chain([rsp(smb2.CREATE, 1, b"x" * 8), rsp(smb2.CLOSE, 2)])
    patched = smb2.split_chain(triage.patch_message_ids(good, [70, 71]))
    assert [e.header.message_id for e in patched] == [70, 71]
    corrupt = smb2.join_chain([rsp(smb2.CREATE, 1, b"x" * 8), rsp(smb2.CLOSE, 2)], {0: 0xFFFFFFF8})
    out = triage.patch_message_ids(corrupt, [70, 71])
    assert out[:24] == corrupt[:24] and out[32:] == corrupt[32:]          # only MessageId moved
    assert struct.unpack_from("<Q", out, 24)[0] == 70
    brk, _ = mutators.oplock_break(b"F" * 16, random.Random(1))
    note = smb2.join_chain([brk])
    assert triage.patch_message_ids(note, [5]) == note


def test_replay_reserves_recorded_bytes_then_falls_back_clean(seeds, tmp_path):
    w = record_conn(seeds, tmp_path, K(budget=2, p_mutate=1.0, p_next=1.0), n=6)
    rows = cases.read_index(w.dir)
    corp = corpus.load_corpus(str(seeds))
    rs = triage.ReplaySession(rows, FuzzSession(corp, random.Random(0), Knobs.clean()))
    # live client re-sends the same 6 compounds, but with different MessageIds
    live = []
    for i in range(7):
        mid = 900 + 3 * i
        live.append(rs.respond(smb2.join_chain([
            req(smb2.CREATE, mid), req(smb2.QUERY_INFO, mid + 1, qi_body(1, 0x12), flags=smb2.FLAG_RELATED),
            req(smb2.CLOSE, mid + 2, flags=smb2.FLAG_RELATED)])))
    recorded = [r for r in rows if r.req == 1]
    first = live[0]
    assert len(first) == len(recorded)
    orig = Path(recorded[0].path).read_bytes()
    zero = [0, 0, 0]
    assert triage.patch_message_ids(first[0].pdu, zero) == triage.patch_message_ids(orig, zero)
    assert struct.unpack_from("<Q", first[0].pdu, 24)[0] == 900
    assert any(o.mutated for group in live[:6] for o in group)
    assert not any(o.mutated for o in live[6]) and live[6][0].desc.startswith("CREATE:clean")
    assert not rs.saw_echo


def test_case_writer_is_thread_safe(tmp_path):
    w = cases.CaseWriter(str(tmp_path), 1, {})
    threads = [threading.Thread(target=lambda c=c: [w.save(c, "CREATE", b"x", "d") for _ in range(10)])
               for c in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    rows = cases.read_index(w.dir)
    assert [r.case for r in rows] == [f"{i:07d}" for i in range(1, 41)]
    assert all(Path(r.path).exists() for r in rows)
