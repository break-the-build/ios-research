"""Research target abstraction and registry.

A *target* is a controlled, authorized thing under test that accepts an input
and reports a normalized outcome. Targets implement a generic lifecycle:

    prepare() -> execute(input) -> collect_result() -> cleanup()

All targets shipped with the framework are **mock** targets suitable for CI and
for research without physical iOS hardware. Real research-device targets can be
registered later behind the same interface (see docs/PROMPT-03-audio-module.md).
"""

from __future__ import annotations

from typing import Callable

from .base import ExecResult, Outcome, Target, Diagnostics
from .mock import MockParserTarget, MockParserV2Target

# registry maps a target id (e.g. "mock:parser") to a factory callable.
_REGISTRY: dict[str, Callable[[], Target]] = {}


def register(target_id: str, factory: Callable[[], Target]) -> None:
    _REGISTRY[target_id] = factory


def create(target_id: str) -> Target:
    from ..errors import NotFoundError
    # Composite network-transport family: "net:<inner-target-id>" delivers
    # inputs to the wrapped target over a loopback TCP socket (#57).
    if target_id.startswith("net:"):
        from ..nettransport import LoopbackTcpTarget
        inner_id = target_id[len("net:"):]
        if not inner_id or inner_id.startswith("net:"):
            raise NotFoundError(f"invalid transport target '{target_id}'")
        return LoopbackTcpTarget(create(inner_id))
    if target_id not in _REGISTRY:
        raise NotFoundError(
            f"unknown target '{target_id}'; known: {', '.join(sorted(_REGISTRY))}")
    return _REGISTRY[target_id]()


def list_targets() -> list[dict]:
    out = []
    for tid in sorted(_REGISTRY):
        target = _REGISTRY[tid]()
        out.append(target.describe())
    return out


def is_registered(target_id: str) -> bool:
    if target_id.startswith("net:"):
        inner = target_id[len("net:"):]
        return bool(inner) and not inner.startswith("net:") \
            and inner in _REGISTRY
    return target_id in _REGISTRY


# --- built-in mock targets -------------------------------------------------
register("mock:parser", lambda: MockParserTarget())
register("mock:parser-v2", lambda: MockParserV2Target())

from .audio import AUDIO_TARGETS  # noqa: E402
for _tid, _cls in AUDIO_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock Bluetooth frame-parser targets (mock = True). CI-safe by construction:
# they parse bytes only and never touch a Bluetooth controller.
from .bluetooth import BLUETOOTH_TARGETS  # noqa: E402
for _tid, _cls in BLUETOOTH_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock Wi-Fi management-frame parser targets (mock = True). CI-safe by
# construction: they parse bytes only and never touch a Wi-Fi radio.
from .wifi import WIFI_TARGETS  # noqa: E402
for _tid, _cls in WIFI_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock communication-message parser targets (#85; network zero-click
# profiles). CI-safe by construction: they parse bytes only and never touch a
# messaging transport, account, or network.
from .messaging import MESSAGING_TARGETS  # noqa: E402
for _tid, _cls in MESSAGING_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock locked-device surface targets (#86; physical-access profiles). CI-safe
# by construction: they parse bytes only and never touch a device, accessory,
# passcode, or stored data.
from .lockeddevice import LOCKED_DEVICE_TARGETS  # noqa: E402
for _tid, _cls in LOCKED_DEVICE_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock NFC/NDEF record parser targets (mock = True). CI-safe by construction:
# they parse bytes only and never touch tag hardware or an RF field.
from .nfc import NFC_TARGETS  # noqa: E402
for _tid, _cls in NFC_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Real macOS in-process fuzzing targets (mock = False). Opt-in: they require a
# built native libFuzzer/ASan harness and are skipped in CI. Registering the
# factory is cheap and does not require the harness to be present.
from .mac import MacFuzzTarget, MAC_FRAMEWORKS  # noqa: E402
for _key in MAC_FRAMEWORKS:
    register(f"mac:{_key}", (lambda k: (lambda: MacFuzzTarget(k)))(_key))

# Real black-box on-device targets (mock = False). Opt-in: they require a
# connected, authorized device + libimobiledevice and are skipped in CI.
# Registering the factory is cheap and needs no device present. This path
# *confirms* a Mac-discovered crash on real hardware; it does not analyze.
from .device import IosDeviceTarget, DEVICE_SURFACES  # noqa: E402
for _surface in DEVICE_SURFACES:
    register(f"ios-device:{_surface}",
             (lambda s: (lambda: IosDeviceTarget(s)))(_surface))

# Kernel-boundary simulation target (mock = True). CI-safe: models XNU
# mach_msg descriptor/bounds logic in-process; never touches a kernel (#68).
from .machsim import MachMessageSimTarget  # noqa: E402
register("mach:sim", lambda: MachMessageSimTarget())

__all__ = [
    "ExecResult", "Outcome", "Target", "Diagnostics",
    "register", "create", "list_targets", "is_registered",
]

# Mock IP-stack input-path parser targets (mock = True). CI-safe by construction:
# bytes-only parsing; no sockets or network access.
from .netip import NETIP_TARGETS  # noqa: E402
for _tid, _cls in NETIP_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock Wi-Fi Aware frame-parser targets (mock = True). CI-safe by construction:
# bytes-only parsing; no RF transmission or association.
from .wifiaware import WIFIAWARE_TARGETS  # noqa: E402
for _tid, _cls in WIFIAWARE_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock PQ3-style ratchet transcript targets (mock = True). Synthetic transcripts only;
# no decryption or third-party traffic analysis.
from .pq3 import PQ3_TARGETS  # noqa: E402
for _tid, _cls in PQ3_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock Continuity beacon record targets (mock = True). Synthetic records only;
# no tracking of third-party devices, no real-radio advertising.
from .continuity import CONTINUITY_TARGETS  # noqa: E402
for _tid, _cls in CONTINUITY_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock trust-boundary payload-envelope targets (mock = True). Decode modeling only;
# no permission/TCC mechanics; templates intended for authorized owned apps.
from .ipc import IPC_TARGETS  # noqa: E402
for _tid, _cls in IPC_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock XPC/Mach message-schema targets (mock = True). Local chain-tail tooling;
# v1 sends nothing to system daemons (offline schema harvest only).
from .xpc import XPC_TARGETS  # noqa: E402
for _tid, _cls in XPC_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock document-importer targets (mock = True). Bytes-only parsing;
# no quarantine/launch simulation.
from .docimp import DOCIMP_TARGETS  # noqa: E402
for _tid, _cls in DOCIMP_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock signed-document targets (mock = True). Verify-only structural parsing
# of synthetic documents; no key material, no signing oracle.
from .signeddoc import SIGNEDDOC_TARGETS  # noqa: E402
for _tid, _cls in SIGNEDDOC_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock proximity application-protocol targets (mock = True). No real accessory
# connections, no RF transmission; bytes-only parse modeling.
from .proxapp import PROXAPP_TARGETS  # noqa: E402
for _tid, _cls in PROXAPP_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock filesystem-client parser targets (mock = True). Bytes-only;
# loopback templates only; nothing mounts against unowned hosts.
from .fsclient import FSCLIENT_TARGETS  # noqa: E402
for _tid, _cls in FSCLIENT_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock geodata/workout importer targets (mock = True). Synthetic coordinates;
# parses bytes only; tracks no person or device.
from .geo import GEO_TARGETS  # noqa: E402
for _tid, _cls in GEO_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))

# Mock lockscreen voice-assistant record targets (mock = True). Text/intent
# records only; never activates microphone or audio capture (SECURITY.md).
from .voiceassist import VOICEASSIST_TARGETS  # noqa: E402
for _tid, _cls in VOICEASSIST_TARGETS.items():
    register(_tid, (lambda c: (lambda: c()))(_cls))
