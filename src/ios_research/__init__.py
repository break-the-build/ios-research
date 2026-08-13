"""ios-research: an authorized iOS security research framework.

This package provides a CLI-driven framework for authorized security research
against controlled, mock research targets. It is designed for both human
researchers and LLM agents (such as Claude Code).

Safety boundary: this framework performs fuzzing, crash discovery, triage,
minimization, differential testing, and responsible reporting against mock or
explicitly authorized research targets only. It contains no exploit-generation,
persistence, surveillance, or sandbox/TCC-bypass capabilities.
"""

__version__ = "0.1.0"

FRAMEWORK_NAME = "ios-research"
