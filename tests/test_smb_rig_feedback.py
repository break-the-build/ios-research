"""Tests for tools/smb-rig: Kernel-log coverage feedback (klog.py) and favored replies (favored.py)."""

from __future__ import annotations

import json
import random
import threading

import pytest
from smb_rig_support import (
    FuzzSession,
    K,
    corpus,
    create_req_body,
    create_rsp_body,
    favored,
    klog,
    make_seeds,
    req,
    rsp,
    smb2,
    triage,
)


@pytest.fixture()
def seeds(tmp_path):
    """Seed corpus directory shared by this file's tests."""
    return make_seeds(tmp_path)


def test_normalize_collapses_instance_values():
    a = klog.normalize("smb2_smb_parse_create: failed 22 id 7 on <TheRooT:probe-3> at 0x1f")
    b = klog.normalize("smb2_smb_parse_create: failed 5 id 12 on <x> at 0xdead")
    assert a == b == "smbN_smb_parse_create: failed N id N on <S> at X"


def test_klog_tap_flags_new_templates_once_and_persists(tmp_path):
    seen = tmp_path / "seen.txt"
    hits = []
    with klog.KernelLogTap(str(tmp_path), str(seen), lambda: 42,
                           lambda t, c: hits.append((t, c))) as tap:
        assert tap.handle_line("Filtering the log data using ...\n") is None
        assert tap.handle_line('{"eventMessage": ""}') is None
        for msg in ("parse_x: bad len 4", "parse_x: bad len 9", "parse_y: oops"):
            tap.handle_line(json.dumps({"eventMessage": msg}))
    assert hits == [("parse_x: bad len N", 42), ("parse_y: oops", 42)]
    assert tap.new_templates == 2 and tap.lines == 3
    with klog.KernelLogTap(str(tmp_path), str(seen), lambda: 1) as again:
        again.handle_line(json.dumps({"eventMessage": "parse_x: bad len 77"}))
    assert again.new_templates == 0                            # remembered across runs
    rows = (tmp_path / "klog.tsv").read_text().splitlines()
    assert rows[0].split("\t")[1:3] == ["42", "NEW"] and rows[1].split("\t")[2] == ""


def test_normalize_bare_hex_without_0x():
    a = klog.normalize("smb_fid_get_kernel_fid: No SMB 2/3 fid found for fid 4f2a3f1a9c")
    b = klog.normalize("smb_fid_get_kernel_fid: No SMB 2/3 fid found for fid bd17bd0")
    assert a == b == "smb_fid_get_kernel_fid: No SMB N/N fid found for fid X"
    assert klog.normalize("bad dead add 12") == "bad dead add N"   # hex-letter words survive


def test_klog_alert_flags_memory_safety_messages(tmp_path):
    alerts = []
    with klog.KernelLogTap(str(tmp_path), str(tmp_path / "s.txt"), lambda: 9,
                           on_alert=lambda m, c: alerts.append((m, c))) as tap:
        tap.handle_line(json.dumps({"eventMessage": "smb_rq: buffer overflow detected len 9"}))
        tap.handle_line(json.dumps({"eventMessage": "smb2_parse: Bad struct size: 9"}))
    assert alerts == [("smb_rq: buffer overflow detected len 9", 9)] and tap.alerts == 1
    first, second = (tmp_path / "klog.tsv").read_text().splitlines()
    assert first.split("\t")[2] == "NEW,ALERT" and second.split("\t")[2] == "NEW"
    lines = triage.format_klog(str(tmp_path))
    assert "1 ALERT" in lines[0] and lines[1].startswith("  ALERT @case 9")


def test_klog_tap_reads_a_subprocess_stream(tmp_path):
    stream = tmp_path / "stream.ndjson"
    stream.write_text("banner\n" + "".join(json.dumps({"eventMessage": m}) + "\n"
                                           for m in ("m1: z", "m2: z", "other: q")))
    hits = []
    tap = klog.KernelLogTap(str(tmp_path), str(tmp_path / "s.txt"), lambda: 0,
                            lambda t, c: hits.append(t), command=("/bin/cat", str(stream)))
    tap.start()
    tap._proc.wait(timeout=5)
    for _ in range(100):
        if tap.lines == 3 and tap._proc.stdout.closed and tap._out is None:
            break                                     # pump drained and closed klog.tsv
        threading.Event().wait(0.02)
    tap.stop()
    assert tap.lines == 3 and hits == ["mN: z", "other: q"]
    assert len((tmp_path / "klog.tsv").read_text().splitlines()) == 3


def test_favored_store_dedupes_caps_and_persists(tmp_path):
    store = favored.FavoredStore(str(tmp_path))
    el = rsp(smb2.CREATE, 1, b"x" * 8)
    store.add((smb2.CREATE, None), el, "tmpl", 5)
    store.add((smb2.CREATE, None), el, "tmpl", 6)                 # duplicate ignored
    assert len(store) == 1 and store.pick((smb2.CREATE, None), random.Random(1)) == el
    assert store.pick((smb2.READ, None), random.Random(1)) is None
    for i in range(favored.CAP_PER_KEY + 5):
        store.add((smb2.READ, None), rsp(smb2.READ, 1, bytes([i % 256]) * 9), "t", i)
    assert len(store) == 1 + favored.CAP_PER_KEY
    assert (tmp_path / "favored" / "favored.tsv").read_text().count("\n") == 1 + favored.CAP_PER_KEY + 5
    assert favored.FavoredStore(None).pick((0, None), random.Random(0)) is None


def test_recent_mutations_window():
    r = favored.RecentMutations()
    el = ((smb2.CREATE, None), rsp(smb2.CREATE, 1)),
    r.add(1, el, now=100.0)
    r.add(2, (), now=100.5)                                     # nothing to attribute: ignored
    r.add(3, el, now=101.5)
    assert [c for c, _ in r.window(now=102.0)] == [1, 3]
    assert [c for c, _ in r.window(now=103.0)] == [3]


def test_mutation_stacks_on_favored_reply(seeds):
    store = favored.FavoredStore(None)
    fav = rsp(smb2.CREATE, 1, create_rsp_body() + b"FAVORED-MARKER")
    store.add((smb2.CREATE, None), fav, "t", 1)
    knobs = K(budget=1, p_mutate=1.0, p_favored=1.0, p_status=0, p_pending=0, p_next=0,
                  p_oplock=0, p_credit=0)
    s = FuzzSession(corpus.load_corpus(str(seeds)), random.Random(4), knobs, store)
    (out,) = s.respond(smb2.join_chain([req(smb2.CREATE, 700, create_req_body("zz"))]))
    assert "fav+" in out.desc and out.mutated
    (key, el), = out.mutated_elements
    assert key == (smb2.CREATE, None) and el.header.command == smb2.CREATE


def test_format_klog(tmp_path):
    assert "not captured" in triage.format_klog(str(tmp_path))[0]
    (tmp_path / "klog.tsv").write_text("t\t3\tNEW\tparse_a: N\traw\nt\t4\t\tparse_a: N\traw\nt\t5\n")
    lines = triage.format_klog(str(tmp_path))
    assert "2 smbfs messages, 1 templates, 1 new" in lines[0] and "NEW @case 3" in lines[1]
