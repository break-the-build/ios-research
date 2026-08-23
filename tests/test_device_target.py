"""Tests for the black-box on-device target and iOS ``.ips`` report parsing.

The ``.ips`` parser (:mod:`ios_research.targets.ips`) needs no hardware or
toolchain, so it runs everywhere. The device target
(:mod:`ios_research.targets.device`) is exercised end-to-end through an injected
fake :class:`DeviceBackend`, so the staging/matching/normalization logic is
covered deterministically without a phone or ``libimobiledevice``.
"""

from __future__ import annotations

import contextlib
import io
import json

import pytest

from ios_research.cli import main
from ios_research.errors import ExitCode

from ios_research.targets import ips, create, is_registered, list_targets
from ios_research.targets.base import Outcome
from ios_research.targets.device import (
    IosDeviceTarget, DEVICE_SURFACES, LibimobiledeviceBackend)


# --- realistic .ips fixtures -----------------------------------------------

def _json_ips(*, proc="MediaPlaybackd", exc="EXC_BAD_ACCESS", signal="SIGSEGV",
              subtype="KERN_INVALID_ADDRESS at 0x0000000123456780",
              os_build="21A329", os_version="17.0", ts="2026-08-23 10:15:00.00 -0700",
              symbol="decode_scanline"):
    header = {
        "app_name": proc, "timestamp": ts, "app_version": "",
        "bug_type": "309", "os_version": f"iPhone OS {os_version} ({os_build})",
        "incident_id": "ABCDEF01-2345-6789-ABCD-EF0123456789", "name": proc,
    }
    body = {
        "procName": proc,
        "exception": {"type": exc, "signal": signal, "subtype": subtype,
                      "codes": "0x0000000000000001, 0x0000000000000010"},
        "faultingThread": 0,
        "threads": [{
            "triggered": True, "id": 100,
            "threadState": {
                "pc": {"value": 0x1a2b3c4d5e},
                "lr": {"value": 0x1a2b3c0000},
                "x": [{"value": 0x10}, {"value": 0x20}, {"value": 0x0}],
            },
            "frames": [
                {"imageIndex": 0, "symbol": symbol, "imageOffset": 0x120},
                {"imageIndex": 1, "symbol": "CGImageSourceCreateImageAtIndex",
                 "imageOffset": 0x2a4b1},
            ],
        }],
        "usedImages": [
            {"name": "ImageIO", "base": 0x1a2b000000, "arch": "arm64"},
            {"name": "CoreGraphics", "base": 0x1a2c000000, "arch": "arm64"},
        ],
    }
    return json.dumps(header) + "\n" + json.dumps(body, indent=1)


LEGACY_IPS = """\
Incident Identifier: DEADBEEF-0000-1111-2222-333344445555
Process:             AudioParser [431]
OS Version:          iPhone OS 16.4 (20E247)
Date/Time:           2026-08-23 09:00:00.000 -0700

Exception Type:  EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype: KERN_INVALID_ADDRESS at 0x0000000000000000
Exception Codes: 0x0000000000000001, 0x0000000000000000

Thread 0 Crashed:
0   AudioToolbox    0x00000001a0011000 ParseAudioFile + 240
1   AudioParser     0x0000000102003000 main + 64

Thread 1:
0   libsystem_kernel.dylib  0x00000001b0000000 mach_msg2_trap + 8

Binary Images:
0x1a0000000 - 0x1a0fff000 AudioToolbox arm64  <uuid> /System/.../AudioToolbox
"""

ABORT_IPS = json.dumps({"bug_type": "309", "name": "Foo",
                        "os_version": "iPhone OS 17.0 (21A329)"}) + "\n" + json.dumps({
    "procName": "Foo",
    "exception": {"type": "EXC_CRASH", "signal": "SIGABRT", "subtype": ""},
    "faultingThread": 0,
    "threads": [{"triggered": True, "threadState": {"pc": {"value": 0x1000}},
                 "frames": [{"imageIndex": 0, "symbol": "__assert_rtn"}]}],
    "usedImages": [{"name": "libsystem_c.dylib"}],
})


# --- parser: format detection ----------------------------------------------

def test_is_crash_report_json_and_legacy():
    assert ips.is_crash_report(_json_ips())
    assert ips.is_crash_report(LEGACY_IPS)
    assert not ips.is_crash_report("")
    assert not ips.is_crash_report("   ")
    assert not ips.is_crash_report("just some console noise\n")


def test_is_crash_report_rejects_plain_json():
    assert not ips.is_crash_report('{"hello": "world"}')


# --- parser: modern JSON ---------------------------------------------------

def test_parse_json_bad_access_non_null_is_unknown():
    d = ips.parse(_json_ips(), module="imageio")
    # Black-box: a non-null bad access cannot be classified as OOB vs UAF.
    assert d.classification_hint == "UNKNOWN"
    assert d.exception_type == "EXC_BAD_ACCESS"
    assert d.signal == "SIGSEGV"
    assert d.faulting_address == "0x0000000123456780"
    assert d.instruction_address == "0x0000001a2b3c4d5e"
    assert d.registers["pc"] == "0x0000001a2b3c4d5e"
    assert any("decode_scanline" in f for f in d.stack_trace)
    assert "ImageIO" in d.modules
    assert d.access_type == "none"          # no read/write signal on device
    assert d.signature.startswith("ips_")


def test_parse_json_null_deref():
    d = ips.parse(_json_ips(subtype="KERN_INVALID_ADDRESS at 0x0000000000000000"),
                  module="imageio")
    assert d.classification_hint == "NULL_DEREFERENCE"
    assert d.faulting_address == "0x0000000000000000"
    assert d.access_type == "read"


def test_parse_json_abort_is_assertion():
    d = ips.parse(ABORT_IPS, module="file")
    assert d.classification_hint == "ASSERTION"
    assert d.signal == "SIGABRT"
    assert any("__assert_rtn" in f for f in d.stack_trace)


def test_parse_json_arithmetic_is_integer_error():
    d = ips.parse(_json_ips(exc="EXC_ARITHMETIC", signal="SIGFPE", subtype=""),
                  module="file")
    assert d.classification_hint == "INTEGER_ERROR"


# --- parser: legacy text ---------------------------------------------------

def test_parse_legacy_null_deref():
    d = ips.parse(LEGACY_IPS, module="audiotoolbox")
    assert d.classification_hint == "NULL_DEREFERENCE"
    assert d.faulting_address == "0x0000000000000000"
    assert any("ParseAudioFile" in f for f in d.stack_trace)
    assert "AudioToolbox" in d.modules
    # Only the crashed thread's frames are parsed, not Thread 1.
    assert not any("mach_msg2_trap" in f for f in d.stack_trace)


def test_parse_unrecognized_report_is_graceful():
    d = ips.parse("totally unrecognized text", module="file")
    assert d.classification_hint == "UNKNOWN"
    assert d.signature.startswith("ips_")
    assert d.stack_trace == []


# --- parser: metadata (matching heuristics) --------------------------------

def test_parse_metadata_json():
    meta = ips.parse_metadata(_json_ips(proc="MediaPlaybackd"))
    assert meta["process"] == "MediaPlaybackd"
    assert meta["os_build"] == "21A329"
    assert meta["os_version"] == "17.0"
    assert meta["timestamp"].startswith("2026-08-23")


def test_parse_metadata_legacy():
    meta = ips.parse_metadata(LEGACY_IPS)
    assert meta["process"] == "AudioParser"
    assert meta["os_build"] == "20E247"
    assert meta["os_version"] == "16.4"


def test_same_input_same_signature():
    a = ips.parse(_json_ips(), module="imageio")
    b = ips.parse(_json_ips(), module="imageio")
    assert a.signature == b.signature


# --- registration ----------------------------------------------------------

def test_device_targets_registered():
    for surface in DEVICE_SURFACES:
        assert is_registered(f"ios-device:{surface}")
    ids = {t["id"] for t in list_targets()}
    assert "ios-device:imageio" in ids


def test_device_target_is_not_mock():
    t = create("ios-device:file")
    assert t.mock is False
    assert t.describe()["available"] is False   # no device in CI


def test_known_imageio_surface_pins_its_expected_process():
    t = IosDeviceTarget("imageio", backend=FakeBackend())
    assert t.expected_process == "MediaPlaybackd"
    assert t.describe()["expected_process"] == "MediaPlaybackd"


def test_generic_file_surface_exposes_ambiguous_matching_warning():
    d = IosDeviceTarget("file", backend=FakeBackend()).describe()
    assert d["expected_process"] == "(any)"
    assert "inconclusive" in d["matching_warning"]


def test_unknown_surface_raises():
    from ios_research.errors import NotFoundError
    with pytest.raises(NotFoundError):
        IosDeviceTarget("nope")


# --- fake backend for end-to-end target tests ------------------------------

class FakeBackend:
    """In-memory DeviceBackend: scripts what the device "produces"."""

    def __init__(self, *, available=True, blocker="", udid="AAAA1111BBBB2222",
                 info=None, existing=None, new_report=None, new_process="Proc"):
        self._available = available
        self._blocker = blocker
        self._udid = udid
        self._info = info or {"model": "iPhone14,2", "os_name": "iOS",
                              "os_version": "17.0", "os_build": "21A329"}
        self._existing = set(existing or ())
        self._new_report = new_report          # (identifier, text), list, or None
        self._new_process = new_process
        self.delivered: list[tuple[str, str, str]] = []

    def available(self):
        return self._available

    def blocker(self):
        return self._blocker

    def udid(self):
        return self._udid if self._available else None

    def device_info(self, udid):
        return self._info

    def snapshot_reports(self, udid):
        return set(self._existing)

    def deliver(self, surface, input_path, udid):
        self.delivered.append((surface, input_path, udid))

    def collect_new_reports(self, udid, since, process):
        if self._new_report is None:
            return []
        reports = (self._new_report if isinstance(self._new_report, list)
                   else [self._new_report])
        out = []
        for ident, text in reports:
            if ident in since:
                continue
            if process and ips.parse_metadata(text).get("process") != process:
                continue
            out.append((ident, text))
        return out


def _target(backend, surface="file", **kw):
    return IosDeviceTarget(surface, backend=backend, timeout_s=0.2,
                           poll_s=0.01, **kw)


def test_unavailable_backend_is_blocked_not_fabricated():
    t = _target(FakeBackend(available=False, blocker="no device connected"))
    res = t.execute(b"data")
    assert res.outcome == Outcome.ABNORMAL
    assert "no device connected" in res.detail
    assert res.diagnostics is None


def test_non_crashing_input_is_accepted():
    backend = FakeBackend(new_report=None)
    res = _target(backend).execute(b"benign")
    assert res.outcome == Outcome.ACCEPTED
    assert "no crash report" in res.detail
    assert res.diagnostics is None
    # input was actually staged to the surface
    assert backend.delivered and backend.delivered[0][0] == "file"


def test_crash_is_detected_and_stamped():
    report = ("MediaPlaybackd-2026-08-23-101500.ips",
              _json_ips(proc="MediaPlaybackd"))
    backend = FakeBackend(new_report=report, new_process="MediaPlaybackd")
    res = _target(backend, surface="imageio").execute(b"crashy")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics is not None
    assert res.diagnostics.classification_hint == "UNKNOWN"
    # device provenance is stamped onto the diagnostics + detail
    assert res.diagnostics.thread["device"].startswith("iOS 17.0 (21A329)")
    assert res.diagnostics.thread["report"] == report[0]
    assert "21A329" in res.detail
    assert "MediaPlaybackd" in res.detail


def test_baseline_report_is_not_reattributed():
    # A crash report that already existed before delivery must not be treated as
    # newly produced by our input.
    ident = "old.ips"
    backend = FakeBackend(new_report=(ident, _json_ips()), existing={ident})
    res = _target(backend).execute(b"data")
    assert res.outcome == Outcome.ACCEPTED
    assert res.diagnostics is None


def test_process_filter_excludes_unrelated_crash():
    # A new report from an unrelated process is filtered out when the surface
    # pins an expected process.
    report = ("other.ips", _json_ips(proc="SpringBoard"))
    backend = FakeBackend(new_report=report, new_process="SpringBoard")
    res = _target(backend, surface="file", process="MediaPlaybackd").execute(b"d")
    assert res.outcome == Outcome.ACCEPTED


def test_process_filter_is_exact_not_a_substring():
    report = ("other.ips", _json_ips(proc="MediaServer"))
    backend = FakeBackend(new_report=report, new_process="MediaServer")
    res = _target(backend, surface="file", process="Media").execute(b"d")
    assert res.outcome == Outcome.ACCEPTED


def test_newest_report_is_ranked_by_parsed_timestamp_not_identifier():
    # Identifiers sort by process name first, so lexical order would pick the
    # older SpringBoard report. Both are scoped to the same pinned target
    # process to exercise the target's recency tie-break.
    older = ("SpringBoard-2026-08-23-090000.ips",
             _json_ips(proc="Target", ts="2026-08-23 09:00:00 -0700"))
    newer = ("MediaPlaybackd-2026-08-23-101500.ips",
             _json_ips(proc="Target", ts="2026-08-23 10:15:00 -0700"))
    backend = FakeBackend(new_report=[older, newer])
    res = _target(backend, surface="file", process="Target").execute(b"d")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.thread["report"] == newer[0]


def test_multiple_unpinned_reports_are_an_explicit_blocker_not_a_crash():
    reports = [
        ("a.ips", _json_ips(proc="A")),
        ("b.ips", _json_ips(proc="B")),
    ]
    res = _target(FakeBackend(new_report=reports), surface="file").execute(b"d")
    assert res.outcome == Outcome.ABNORMAL
    assert res.diagnostics is None
    assert "attribution is inconclusive" in res.detail


def test_crash_routes_through_ips_parser_module_tag():
    report = ("c.ips", _json_ips(proc="P"))
    backend = FakeBackend(new_report=report, new_process="P")
    res = _target(backend, surface="coregraphics").execute(b"x")
    assert res.outcome == Outcome.CRASH
    assert res.diagnostics.signature.startswith("ips_")


# --- real backend: availability gating (no tools required to test) ----------

def test_real_backend_blocker_when_tools_missing(monkeypatch):
    import ios_research.targets.device as devmod
    monkeypatch.setattr(devmod.shutil, "which", lambda name: None)
    backend = LibimobiledeviceBackend()
    assert not backend.available()
    assert "libimobiledevice not installed" in backend.blocker()


class _Proc:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.returncode = 0


def test_real_backend_udid_and_info_parsing(monkeypatch):
    import ios_research.targets.device as devmod
    monkeypatch.setattr(devmod.shutil, "which", lambda name: f"/usr/bin/{name}")

    def fake_run(args, **kw):
        tool = args[0]
        if tool.endswith("idevice_id"):
            return _Proc("00008110-000A1B2C3D4E5F6G\n")
        if tool.endswith("ideviceinfo"):
            return _Proc("ProductType: iPhone15,2\n"
                         "ProductVersion: 17.1\n"
                         "BuildVersion: 21B74\n"
                         "ProductName: iPhone OS\n")
        return _Proc("")

    monkeypatch.setattr(devmod.subprocess, "run", fake_run)
    backend = LibimobiledeviceBackend()
    assert backend.available()
    assert backend.blocker() == ""
    udid = backend.udid()
    assert udid == "00008110-000A1B2C3D4E5F6G"
    info = backend.device_info(udid)
    assert info == {"model": "iPhone15,2", "os_name": "iPhone OS",
                    "os_version": "17.1", "os_build": "21B74"}


def test_real_backend_udid_env_override(monkeypatch):
    import ios_research.targets.device as devmod
    monkeypatch.setattr(devmod.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setenv("IOS_RESEARCH_DEVICE_UDID", "ENVUDID123")
    backend = LibimobiledeviceBackend()
    assert backend.udid() == "ENVUDID123"


def test_real_backend_collect_new_reports_filters(monkeypatch, tmp_path):
    import ios_research.targets.device as devmod
    monkeypatch.setattr(devmod.shutil, "which", lambda name: f"/usr/bin/{name}")

    # idevicecrashreport "extracts" reports: simulate by writing files into the
    # temp dir the backend creates. We patch mkdtemp to a dir we control and
    # populate it on the copy call.
    crash_dir = tmp_path / "crashes"
    crash_dir.mkdir()
    (crash_dir / "old.ips").write_text(_json_ips(proc="Old"))
    (crash_dir / "new.ips").write_text(_json_ips(proc="Target"))
    (crash_dir / "unrelated.ips").write_text(_json_ips(proc="SpringBoard"))
    (crash_dir / "noise.ips").write_text("not a crash report")

    monkeypatch.setattr(devmod.tempfile, "mkdtemp",
                        lambda prefix="": str(crash_dir))
    monkeypatch.setattr(devmod.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(devmod.subprocess, "run", lambda *a, **k: _Proc(""))

    backend = LibimobiledeviceBackend()
    reports = backend.collect_new_reports("udid", {"old.ips"}, "Target")
    names = {ident for ident, _ in reports}
    assert names == {"new.ips"}      # old filtered by baseline; others by process/parse


def test_real_backend_process_filter_is_exact(monkeypatch, tmp_path):
    import ios_research.targets.device as devmod
    monkeypatch.setattr(devmod.shutil, "which", lambda name: f"/usr/bin/{name}")
    crash_dir = tmp_path / "crashes"
    crash_dir.mkdir()
    (crash_dir / "near.ips").write_text(_json_ips(proc="TargetHelper"))
    monkeypatch.setattr(devmod.tempfile, "mkdtemp", lambda prefix="": str(crash_dir))
    monkeypatch.setattr(devmod.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(devmod.subprocess, "run", lambda *a, **k: _Proc(""))
    assert LibimobiledeviceBackend().collect_new_reports("udid", set(), "Target") == []


# --- CLI: fuzz start against an unavailable device is a clean blocker --------

def test_fuzz_start_on_unavailable_device_is_clean_blocker(tmp_path):
    ws = tmp_path / ".ios-research"
    assert main(["init", "--json", "--workspace", str(ws)]) == ExitCode.OK

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(["fuzz", "start", "--target", "ios-device:file",
                     "--max-cases", "5", "--json", "--workspace", str(ws)])
    payload = json.loads(buf.getvalue())

    # STATE exit code, an actionable blocker, and — critically — no fabricated
    # crash records were written.
    assert code == ExitCode.STATE
    assert payload["ok"] is False
    assert "not available" in payload["error"]

    buf2 = io.StringIO()
    with contextlib.redirect_stdout(buf2):
        main(["crash", "list", "--json", "--workspace", str(ws)])
    assert json.loads(buf2.getvalue())["data"]["count"] == 0
