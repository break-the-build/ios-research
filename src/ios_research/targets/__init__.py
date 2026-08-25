from __future__ import annotations

from .base import Target, ExecResult, Diagnostics
from .mock_parser import MockParserTarget
from .mock_audio import MockAudioTarget

__all__ = [
    "Target",
    "ExecResult",
    "Diagnostics",
    "MockParserTarget",
    "MockAudioTarget",
]

TARGET_REGISTRY = {
    "mock:parser": MockParserTarget,
    "mock:parser-v2": lambda: MockParserTarget(version=2),
    "mock:audio:wav": lambda: MockAudioTarget("wav"),
    "mock:audio:mp3": lambda: MockAudioTarget("mp3"),
    "mock:audio:aac": lambda: MockAudioTarget("aac"),
    "mock:audio:alac": lambda: MockAudioTarget("alac"),
}

def get_target(name: str) -> Target:
    """Get a target instance by name."""
    if name not in TARGET_REGISTRY:
        raise ValueError(f"Unknown target: {name}")
    return TARGET_REGISTRY[name]()

def list_targets() -> list[str]:
    return list(TARGET_REGISTRY.keys())
