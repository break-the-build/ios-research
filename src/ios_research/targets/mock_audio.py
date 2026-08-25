from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from .base import Target, ExecResult, Diagnostics


class MockAudioTarget(Target):
    """Mock audio format parser target."""

    mock = True
    description = "Mock audio format parser"

    FORMAT_SIGNATURES = {
        "wav": b"RIFF",
        "mp3": b"ID3",
        "aac": b"\xff\xf1",
        "alac": b"alac",
    }

    def __init__(self, format_name: str, workspace: Path, config: dict[str, Any] | None = None):
        super().__init__(workspace, config)
        self.format_name = format_name
        self.name = f"mock:audio:{format_name}"
        self.signature = self.FORMAT_SIGNATURES.get(format_name, b"")

    def prepare(self) -> None:
        pass

    def _run(self, data: bytes) -> ExecResult:
        """Simulate audio parsing; crash deterministically based on input hash."""
        h = hashlib.sha256(data).digest()
        crash_byte = h[0]
        crashed = crash_byte < 8  # ~3% crash rate

        if not crashed:
            return ExecResult(
                crashed=False,
                diagnostics=None,
                stdout="",
                stderr="",
                exit_code=0,
                duration_ms=1,
            )

        diagnostics = self._synthesize_diagnostics(h, data)
        return ExecResult(
            crashed=True,
            diagnostics=diagnostics,
            stdout="",
            stderr=f"Mock {self.format_name} crash",
            exit_code=-11,
            duration_ms=1,
        )

    def _synthesize_diagnostics(self, hash_bytes: bytes, data: bytes) -> Diagnostics:
        faulting_addr = struct.unpack("<Q", hash_bytes[:8])[0] & 0x7FFFFFFFFFFF
        
        registers = {}
        reg_names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags"]
        for i, name in enumerate(reg_names):
            offset = (i * 8) % len(hash_bytes)
            registers[name] = struct.unpack("<Q", hash_bytes[offset:offset+8] + b"\x00" * max(0, 8 - (len(hash_bytes) - offset)))[0]
        
        stack_trace = []
        for frame_idx in range(5):
            offset = (frame_idx * 16) % len(hash_bytes)
            addr = struct.unpack("<Q", hash_bytes[offset:offset+8] + b"\x00" * max(0, 8 - (len(hash_bytes) - offset)))[0]
            stack_trace.append({
                "frame": frame_idx,
                "address": addr & 0x7FFFFFFFFFFF,
                "function": f"mock_{self.format_name}_parse_frame_{frame_idx}",
                "module": f"mock_{self.format_name}",
                "offset": addr & 0xFFF,
            })
        
        modules = [
            {
                "name": f"mock_{self.format_name}",
                "base_address": 0x100000000,
                "size": 0x100000,
                "uuid": hashlib.sha256(f"mock_{self.format_name}".encode()).hexdigest()[:32],
            }
        ]
        
        return Diagnostics(
            exception_type="EXC_BAD_ACCESS",
            exception_message=f"Mock KERN_INVALID_ADDRESS at {hex(faulting_addr)}",
            faulting_address=faulting_addr,
            registers=registers,
            stack_trace=stack_trace,
            modules=modules,
            raw_output=f"Mock {self.format_name} crash from hash {hash_bytes.hex()[:32]}",
        )

    def get_corpus(self) -> list[bytes]:
        base = [self.signature + b"\x00" * 100]
        if self.format_name == "wav":
            base.append(b"RIFF\x24\x00\x00\x00WAVEfmt ")
        elif self.format_name == "mp3":
            base.append(b"ID3\x03\x00\x00\x00\x00\x00")
        return base
