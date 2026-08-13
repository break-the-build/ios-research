"""Stable exit codes and the framework exception hierarchy.

Exit codes are part of the machine-readable contract and MUST remain stable so
that LLM agents and CI systems can depend on them.
"""

from __future__ import annotations


class ExitCode:
    """Stable process exit codes."""

    OK = 0
    ERROR = 1          # generic/unexpected failure
    USAGE = 2          # invalid CLI usage / bad arguments
    NOT_FOUND = 3      # requested resource does not exist
    VALIDATION = 4     # input or artifact failed validation
    SAFETY = 5         # request violated a safety boundary
    INTERRUPTED = 6    # operation interrupted / requires confirmation
    STATE = 7          # invalid state transition / precondition failed


class IosResearchError(Exception):
    """Base class for all framework errors.

    Carries a stable exit code so the CLI can translate any raised error into a
    deterministic process result.
    """

    exit_code = ExitCode.ERROR

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class UsageError(IosResearchError):
    exit_code = ExitCode.USAGE


class NotFoundError(IosResearchError):
    exit_code = ExitCode.NOT_FOUND


class ValidationError(IosResearchError):
    exit_code = ExitCode.VALIDATION


class SafetyError(IosResearchError):
    """Raised when a request crosses an authorized-research safety boundary."""

    exit_code = ExitCode.SAFETY


class InterruptedError_(IosResearchError):
    exit_code = ExitCode.INTERRUPTED


class StateError(IosResearchError):
    exit_code = ExitCode.STATE
