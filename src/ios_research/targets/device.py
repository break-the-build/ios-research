"""Black-box on-device target: stage an input, harvest the crash report over USB.

The macOS in-process fuzzer (:mod:`ios_research.targets.mac`) *finds and
analyzes* bugs with full sanitizer instrumentation. This target does the
complementary half: it **confirms reproduction on real hardware/OS**. It stages
one input to a chosen surface on a USB-attached, *authorized* iPhone and then
harvests the resulting platform crash report (``.ips``), normalizing it into the
same :class:`~ios_research.targets.base.Diagnostics` every other subsystem
consumes (via :mod:`ios_research.targets.ips`).

On a stock retail device you can pull ``.ips`` crash logs, stream the console,
and capture a sysdiagnose — but you **cannot instrument memory**: no sanitizer,
no debugger attach to system processes, no read/write discrimination. So this
path yields **confirmation, not analysis**. That is still valuable: it validates
that a Mac-discovered crash reproduces on the real target OS/hardware before a
report is written, and stamps the finding with the device id + OS build.

Like :class:`~ios_research.targets.mac.MacFuzzTarget` this is **not a mock**
(``mock = False``) and is *opt-in*: it needs a connected, authorized device and
``libimobiledevice`` (``idevicecrashreport`` / ``ideviceinfo``). With neither
present it degrades gracefully to an ``ABNORMAL`` result carrying a clear blocker
— it never fabricates a crash.

Safety: **authorized devices only** (your own or explicitly authorized). This
target never bypasses permissions, never installs persistence, and never
performs covert access — it only stages an input to a surface and reads the
crash reporter's own output. See ``SECURITY.md``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .base import Diagnostics, ExecResult, Outcome, Target
from . import ips

# Surfaces exposed as ``ios-device:<surface>`` targets. ``process`` is the crash
# reporter process name we expect to see fault (``None`` = no reliable default).
# Only the in-repo ImageIO delivery profile has a known process; generic files
# and delivery-dependent surfaces must be pinned by the authorized operator.
# Surfaces mirror the ``mac:<framework>`` families so a Mac-discovered crash can
# be confirmed on the same logical surface on-device.
_SURFACES = {
    "file": {
        "process": None,
        "formats": ("bin",),
        "description": ("generic file staged to a chosen app; confirms any new "
                        "crash produced on the device"),
    },
    "imageio": {
        "process": "MediaPlaybackd",
        "formats": ("png", "jpeg", "gif", "tiff", "heic", "webp"),
        "description": "image staged via Photos/QuickLook; confirm an ImageIO decode crash",
    },
    "audiotoolbox": {
        "process": None,
        "formats": ("wav", "mp3", "aac", "caf", "m4a"),
        "description": "audio staged to a player; confirm an AudioToolbox decode crash",
    },
    "coregraphics": {
        "process": None,
        "formats": ("pdf", "raw"),
        "description": "document staged to a viewer; confirm a CoreGraphics decode crash",
    },
}

_DEFAULT_TIMEOUT_S = 30.0
_DEFAULT_POLL_S = 1.0
_PROCESS_ENV = "IOS_RESEARCH_DEVICE_PROCESS"
_UDID_ENV = "IOS_RESEARCH_DEVICE_UDID"


class _InconclusiveAttribution(Exception):
    """A report cannot be attributed safely to the delivered input."""


class DeviceBackend(Protocol):
    """Boundary between the target's logic and the USB device toolchain.

    A real implementation shells out to ``libimobiledevice``; tests inject a
    fake. Keeping every device interaction behind this protocol is what lets the
    matching/normalization logic be exercised deterministically without hardware.
    """

    def available(self) -> bool:
        """True when the toolchain is installed *and* a device is connected."""
        ...

    def blocker(self) -> str:
        """Human-readable reason the backend is unavailable (empty if available)."""
        ...

    def udid(self) -> str | None:
        """UDID of the target device, or None if none is connected."""
        ...

    def device_info(self, udid: str) -> dict[str, str]:
        """Return ``{model, os_name, os_version, os_build}`` for the device."""
        ...

    def snapshot_reports(self, udid: str) -> set[str]:
        """Return the set of crash-report identifiers already on the device."""
        ...

    def deliver(self, surface: str, input_path: str, udid: str) -> None:
        """Stage ``input_path`` to ``surface`` on the device (best-effort)."""
        ...

    def collect_new_reports(self, udid: str, since: set[str],
                            process: str | None) -> list[tuple[str, str]]:
        """Return ``[(identifier, ips_text)]`` for reports not in ``since``.

        If ``process`` is given, only reports whose faulting process matches are
        returned. Newest-relevant ordering is the caller's concern.
        """
        ...


class LibimobiledeviceBackend:
    """Real backend over ``libimobiledevice`` (USB). Never used in CI.

    Requires ``idevice_id``/``ideviceinfo``/``idevicecrashreport`` on ``PATH``.
    Crash reports are copied off the device into a temp dir and read back; the
    device's own copies are left in place (no destructive ``--keep`` toggle here).
    """

    _TOOLS = ("idevice_id", "ideviceinfo", "idevicecrashreport")

    def __init__(self, *, timeout_s: float = 20.0) -> None:
        self.timeout_s = timeout_s

    def _tool(self, name: str) -> str | None:
        return shutil.which(name)

    def available(self) -> bool:
        return not self.blocker()

    def blocker(self) -> str:
        missing = [t for t in self._TOOLS if self._tool(t) is None]
        if missing:
            return ("libimobiledevice not installed (missing: "
                    + ", ".join(missing)
                    + "); install via `brew install libimobiledevice`")
        if self.udid() is None:
            return "no authorized device connected over USB"
        return ""

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=self.timeout_s)

    def udid(self) -> str | None:
        env = os.environ.get(_UDID_ENV)
        if env:
            return env
        tool = self._tool("idevice_id")
        if not tool:
            return None
        try:
            proc = self._run([tool, "-l"])
        except (OSError, subprocess.SubprocessError):
            return None
        ids = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        return ids[0] if ids else None

    def device_info(self, udid: str) -> dict[str, str]:
        tool = self._tool("ideviceinfo")
        info = {"model": "", "os_name": "iOS", "os_version": "", "os_build": ""}
        if not tool:
            return info
        try:
            proc = self._run([tool, "-u", udid])
        except (OSError, subprocess.SubprocessError):
            return info
        for line in proc.stdout.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key == "ProductType":
                info["model"] = value
            elif key == "ProductVersion":
                info["os_version"] = value
            elif key == "BuildVersion":
                info["os_build"] = value
            elif key == "ProductName":
                info["os_name"] = value
        return info

    def _copy_reports(self, udid: str) -> Path:
        tool = self._tool("idevicecrashreport")
        dest = Path(tempfile.mkdtemp(prefix="ios-research-crash-"))
        if not tool:
            return dest
        try:
            # -e extracts (does not move) reports; keeps device copies in place.
            self._run([tool, "-u", udid, "-e", str(dest)])
        except (OSError, subprocess.SubprocessError):
            pass
        return dest

    def snapshot_reports(self, udid: str) -> set[str]:
        dest = self._copy_reports(udid)
        try:
            return {p.name for p in dest.rglob("*.ips")}
        finally:
            shutil.rmtree(dest, ignore_errors=True)

    def deliver(self, surface: str, input_path: str, udid: str) -> None:
        # Delivery to an on-device surface is environment-specific (an installed
        # research app, a share-sheet automation, a local file open). The real
        # wiring is intentionally out of scope for the framework core: with no
        # delivery mechanism configured this is a no-op, and the harvest step
        # simply observes whatever the device produced. Override this backend to
        # attach a concrete, authorized delivery path.
        return None

    def collect_new_reports(self, udid: str, since: set[str],
                            process: str | None) -> list[tuple[str, str]]:
        dest = self._copy_reports(udid)
        try:
            out: list[tuple[str, str]] = []
            for path in sorted(dest.rglob("*.ips")):
                if path.name in since:
                    continue
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                if not ips.is_crash_report(text):
                    continue
                if process:
                    meta = ips.parse_metadata(text)
                    # A substring match can turn a report from e.g.
                    # ``MediaServer`` into a false confirmation for ``Media``.
                    # A pinned process is a precision guard, so it must be exact.
                    if meta.get("process") != process:
                        continue
                out.append((path.name, text))
            return out
        finally:
            shutil.rmtree(dest, ignore_errors=True)


class IosDeviceTarget(Target):
    """Stage one input to an on-device surface and harvest its crash report."""

    kind = "ios-device"
    mock = False

    def __init__(self, surface: str, *, backend: DeviceBackend | None = None,
                 timeout_s: float = _DEFAULT_TIMEOUT_S,
                 poll_s: float = _DEFAULT_POLL_S,
                 process: str | None = None) -> None:
        if surface not in _SURFACES:
            from ..errors import NotFoundError
            raise NotFoundError(
                f"unknown device surface '{surface}'; known: "
                f"{', '.join(sorted(_SURFACES))}")
        meta = _SURFACES[surface]
        self.surface = surface
        self.target_id = f"ios-device:{surface}"
        self.formats = meta["formats"]
        self.description = meta["description"]
        self.expected_process = (process or os.environ.get(_PROCESS_ENV)
                                 or meta["process"])
        self.timeout_s = timeout_s
        self.poll_s = poll_s
        self._backend = backend or LibimobiledeviceBackend()
        self._udid: str | None = None
        self._baseline: set[str] = set()

    # --- discovery -------------------------------------------------------
    def available(self) -> bool:
        return self._backend.available()

    def blocker(self) -> str:
        """Why this target cannot run right now (empty string if it can)."""
        return self._backend.blocker()

    def describe(self):
        d = super().describe()
        d["surface"] = self.surface
        d["expected_process"] = self.expected_process or "(any)"
        if self.expected_process is None:
            d["matching_warning"] = (
                "no expected process is pinned; multiple new reports are "
                "inconclusive and will not be recorded as a crash")
        d["available"] = self.available()
        d["signal"] = "confirmation only (no memory instrumentation on device)"
        d["note"] = ("black-box on-device confirmation; authorized devices only; "
                     "requires a connected device + libimobiledevice")
        return d

    # --- lifecycle -------------------------------------------------------
    def prepare(self) -> None:
        if not self._backend.available():
            self._udid = None
            return
        self._udid = self._backend.udid()
        if self._udid is not None:
            self._baseline = self._backend.snapshot_reports(self._udid)

    def cleanup(self) -> None:
        self._udid = None
        self._baseline = set()

    def _blocked(self) -> ExecResult:
        blocker = (self._backend.blocker()
                   or "no authorized device / libimobiledevice available")
        return ExecResult(
            outcome=Outcome.ABNORMAL,
            detail=(f"{self.target_id} unavailable: {blocker} "
                    f"(see docs/ON-DEVICE-TARGET.md)"),
            duration_ms=0)

    def _run(self, data: bytes) -> ExecResult:
        if self._udid is None:
            return self._blocked()

        udid = self._udid
        info = self._backend.device_info(udid)
        stamp = self._device_stamp(udid, info)

        start = time.monotonic()
        tmp = tempfile.NamedTemporaryFile(
            prefix="ios-research-device-", suffix=".input", delete=False)
        try:
            tmp.write(data)
            tmp.flush()
            tmp.close()
            self._backend.deliver(self.surface, tmp.name, udid)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        try:
            report = self._poll_for_report(udid, start)
        except _InconclusiveAttribution as exc:
            dur = int((time.monotonic() - start) * 1000)
            return ExecResult(outcome=Outcome.ABNORMAL, detail=str(exc),
                              duration_ms=max(dur, 1))
        dur = int((time.monotonic() - start) * 1000)

        if report is None:
            # Non-crashing input: no new matching crash report was produced.
            return ExecResult(
                outcome=Outcome.ACCEPTED,
                detail=f"no crash report on {stamp} within {self.timeout_s}s",
                duration_ms=max(dur, 1))

        identifier, text = report
        diag = ips.parse(text, module=self.surface)
        self._stamp_diagnostics(diag, stamp, identifier)
        meta = ips.parse_metadata(text)
        proc = meta.get("process") or "?"
        return ExecResult(
            outcome=Outcome.CRASH,
            detail=(f"crash in {proc} on {stamp} "
                    f"(report {identifier}, {diag.classification_hint})")[:500],
            duration_ms=max(dur, 1), diagnostics=diag)

    def _poll_for_report(self, udid: str,
                         start: float) -> tuple[str, str] | None:
        """Poll for a new matching crash report until the timeout elapses.

        Returns the newest matching ``(identifier, ips_text)`` or None. Best
        effort by design: matching is a timestamp + process heuristic, so the
        most-recent new report attributable to the surface wins.
        """
        deadline = start + self.timeout_s
        while True:
            new = self._backend.collect_new_reports(
                udid, self._baseline, self.expected_process)
            if new:
                if self.expected_process is None and len(new) > 1:
                    # Generic/unpinned delivery cannot distinguish its own
                    # report from concurrent device activity.  Fail closed;
                    # selecting one would fabricate a crash attribution.
                    raise _InconclusiveAttribution(
                        "multiple new crash reports without an expected process; "
                        "attribution is inconclusive (set "
                        f"{_PROCESS_ENV} to the exact process name)")
                return max(new, key=self._report_recency)
            if time.monotonic() >= deadline:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(self.poll_s, remaining))

    @staticmethod
    def _report_recency(report: tuple[str, str]) -> tuple[bool, float, str]:
        """Sort a report by parsed capture time, then stable identifier.

        iOS crash filenames begin with the process name, so lexical filename
        order is not chronological.  A missing/unparseable timestamp is still
        deterministic, but only wins the tie-break against another such report.
        """
        identifier, text = report
        raw = ips.parse_metadata(text).get("timestamp", "")
        try:
            # ``.ips`` commonly uses a space before a compact numeric offset
            # (``... 10:15:00.00 -0700``), which older supported Python
            # versions do not accept in ``fromisoformat``.
            for pattern in (
                "%Y-%m-%d %H:%M:%S.%f %z",
                "%Y-%m-%d %H:%M:%S %z",
            ):
                try:
                    return (True, datetime.strptime(raw, pattern).timestamp(),
                            identifier)
                except ValueError:
                    pass
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return (True, parsed.timestamp(), identifier)
        except (TypeError, ValueError, OverflowError):
            return (False, float("-inf"), identifier)

    # --- stamping --------------------------------------------------------
    @staticmethod
    def _device_stamp(udid: str, info: dict[str, str]) -> str:
        os_name = info.get("os_name") or "iOS"
        version = info.get("os_version") or "?"
        build = info.get("os_build") or "?"
        short_udid = udid[:8] if udid else "?"
        return f"{os_name} {version} ({build}) [{short_udid}]"

    @staticmethod
    def _stamp_diagnostics(diag: Diagnostics, stamp: str,
                           identifier: str) -> None:
        # Record device provenance on the thread metadata so it survives into
        # the crash record without changing the Diagnostics schema.
        diag.thread = dict(diag.thread or {})
        diag.thread["device"] = stamp
        diag.thread["report"] = identifier


def build_targets() -> dict[str, dict]:
    """Return the ``{surface: meta}`` mapping for registration."""
    return _SURFACES


DEVICE_SURFACES = _SURFACES
