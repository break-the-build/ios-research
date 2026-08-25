from __future__ import annotations

import hashlib
import struct
import time
from pathlib import Path
from typing import Any

from .base import Target, ExecResult, Diagnostics


class MockParserTarget(Target):
    """Mock parser target with deterministic 'crashes' based on input hash."""

    mock = True
    name = "mock:parser"
    description = "Mock record parser (deterministic crashes from input hash)"

    def __init__(self, workspace: Path, config: dict[str, Any] | None = None, version: int = 1):
        super().__init__(workspace, config)
        self.version = version
        self.name = f"mock:parser-v{version}" if version > 1 else "mock:parser"

    def prepare(self) -> None:
        """No preparation needed for mock target."""
        pass

    def _run(self, data: bytes) -> ExecResult:
        """Simulate parsing; crash deterministically based on input hash."""
        # Deterministic 'crash' decision from hash
        h = hashlib.sha256(data).digest()
        crash_byte = h[0]
        crashed = crash_byte < 10  # ~3.9% crash rate

        if not crashed:
            return ExecResult(
                crashed=False,
                diagnostics=None,
                stdout="",
                stderr="",
                exit_code=0,
                duration_ms=1,
            )

        # Synthesize diagnostics from hash
        diagnostics = self._synthesize_diagnostics(h, data)
        return ExecResult(
            crashed=True,
            diagnostics=diagnostics,
            stdout="",
            stderr="Mock crash triggered",
            exit_code=-11,  # SIGSEGV
            duration_ms=1,
        )

    def _synthesize_diagnostics(self, hash_bytes: bytes, data: bytes) -> Diagnostics:
        """Create deterministic fake diagnostics from hash."""
        # Faulting address from first 8 bytes of hash
        faulting_addr = struct.unpack("<Q", hash_bytes[:8])[0] & 0x7FFFFFFFFFFF
        
        # Registers from hash
        registers = {}
        reg_names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"]
        for i, name in enumerate(reg_names):
            offset = (i * 8) % len(hash_bytes)
            registers[name] = struct.unpack("<Q", hash_bytes[offset:offset+8] + b"\x00" * max(0, 8 - (len(hash_bytes) - offset)))[0]
        
        # Stack trace from hash
        stack_trace = []
        for frame_idx in range(5):
            offset = (frame_idx * 16) % len(hash_bytes)
            addr = struct.unpack("<Q", hash_bytes[offset:offset+8] + b"\x00" * max(0, 8 - (len(hash_bytes) - offset)))[0]
            stack_trace.append({
                "frame": frame_idx,
                "address": addr & 0x7FFFFFFFFFFF,
                "function": f"mock_function_{frame_idx}",
                "module": "mock_parser",
                "offset": addr & 0xFFF,
            })
        
        # Modules
        modules = [
            {
                "name": "mock_parser",
                "base_address": 0x100000000,
                "size": 0x100000,
                "uuid": hashlib.sha256(b"mock_parser").hexdigest()[:32],
            }
        ]
        
        return Diagnostics(
            exception_type="EXC_BAD_ACCESS",
            exception_message="Mock KERN_INVALID_ADDRESS at " + hex(faulting_addr),
            faulting_address=faulting_addr,
            registers=registers,
            stack_trace=stack_trace,
            modules=modules,
            raw_output=f"Mock crash synthesized from hash {hash_bytes.hex()[:32]}",
        )

    def get_corpus(self) -> list[bytes]:
        """Return seed corpus."""
        return [
            b"RECORD\x01\x00\x00\x00",
            b"RECORD\x02\x00\x00\x00data",
            b"HEADER\x00\x00\x00\x00",
        ]
