"""Kernel-boundary simulation target: XNU Mach-message handling (CI-safe).

Exercises the same *logic shapes* that produce real XNU kernel-boundary
defects — descriptor accounting, OOL region bounds, send-right budgets and
revoked-memory reuse — against an in-process model of ``mach_msg`` input.
No kernel, driver, device or privilege boundary is touched; outcomes are
computed deterministically from the packed message bytes.
"""

from __future__ import annotations

from .. import machmsg
from .base import Diagnostics, ExecResult, Outcome, Target
from . import diagnostics as diag_builder

_MODULE = "MachSim"


class MachMessageSimTarget(Target):
    target_id = "mach:sim"
    kind = "kernel-boundary"
    description = ("Deterministic XNU mach_msg boundary model "
                   "(CI-safe; no kernel involvement)")
    formats = ("mach-msg",)
    mock = True

    def seeds(self) -> list[bytes]:
        base = machmsg.MachMessage(
            bits=machmsg.COMPLEX_FLAG,
            ports=[machmsg.PortDescriptor(name=0x103)],
            ool_regions=[machmsg.OOLDescriptor(address=0x4000, size=8)],
            payload=b"\xde\xad" + b"A" * 6,
        )
        return [machmsg.pack(base)]

    def structure_mutate(self, data: bytes, rng):
        """Format-aware mutation: perturb header fields, keep packability."""
        try:
            status, _detail, msg = machmsg.parse(data)
            if msg is None:
                return None
        except Exception:
            return None
        choice = rng.randrange(5)
        if choice == 0:
            msg.bits ^= (rng.randrange(1, 4) << 8)          # port-count drift
        elif choice == 1:
            msg.bits |= rng.choice([0x01, 0x02])            # phantom OOL count
        elif choice == 2:
            msg.msg_id = rng.choice([0xFFFF, 0, 0x7FFFFFFF])
        elif choice == 3 and msg.ool_regions:
            msg.ool_regions[0].size = rng.choice([0xFFFF, 0, 0x10000])
        else:
            msg.remote = rng.choice([0, 1, 0xFFFFFFFF])
        try:
            return machmsg.pack(msg)
        except machmsg.MachMessageError:
            return None

    def coverage_features(self, data: bytes, result: ExecResult):
        prefix = "mach-sim:v1"
        status, detail, msg = machmsg.parse(data)
        features = [f"{prefix}:{status}"]
        if msg is not None:
            if msg.complex:
                features.append(f"{prefix}:complex")
            if msg.ports:
                features.append(f"{prefix}:has-ports")
            if msg.ool_regions:
                features.append(f"{prefix}:has-ool")
            if b"\xde\xad" in msg.payload:
                features.append(f"{prefix}:revoked-marker")
        return tuple(features)

    def _crash(self, data: bytes, classification: str, symbols: list[str],
               detail: str) -> ExecResult:
        diag = diag_builder.build(data, classification, _MODULE, symbols)
        return ExecResult(outcome=Outcome.CRASH, detail=detail,
                          duration_ms=1, diagnostics=diag)

    def _run(self, data: bytes) -> ExecResult:
        status, detail, msg = machmsg.parse(data)

        if status == "err_short_header":
            # A kernel would fault reading the fixed header.
            return self._crash(data, "NULL_DEREFERENCE",
                               ["ipc_kmsg_copyin", "mach_msg"],
                               f"short header rejected: {detail}")
        if status in ("err_size_underflow", "err_truncated_body"):
            return self._crash(data, "INTEGER_ERROR",
                               ["ipc_kmsg_alloc", "mach_msg"],
                               f"size accounting failure: {detail}")
        if status == "err_complex_empty":
            return self._crash(data, "TYPE_CONFUSION",
                               ["ipc_kmsg_copyin", "descriptor_walk"],
                               "complex bit without descriptors")
        if status in ("err_descriptor_bounds", "err_ool_overflow"):
            return self._crash(data, "OUT_OF_BOUNDS_READ",
                               ["ipc_kmsg_copyin", "copyin_ool_region",
                                "vm_map_copyin"],
                               f"descriptor bounds violation: {detail}")
        if status == "err_right_overflow":
            return self._crash(data, "ASSERTION",
                               ["ipc_right_copyin", "assert_send_rights"],
                               detail)

        # Parsed fine; model the revoked-OOL reuse defect on the marker.
        assert msg is not None
        if b"\xde\xad" in msg.payload and msg.ool_regions:
            return self._crash(data, "USE_AFTER_FREE",
                               ["ipc_kmsg_copyout", "map_reuse_page"],
                               "payload references a revoked OOL page")

        if msg.msg_id == 0xFFFF:
            return ExecResult(outcome=Outcome.TIMEOUT,
                              detail="reserved id 0xFFFF models slow path",
                              duration_ms=1000)

        return ExecResult(outcome=Outcome.ACCEPTED,
                          detail=f"message handled ({status})", duration_ms=1)
