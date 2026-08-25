"""Execution context shared by all command handlers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .config import Config
from .logging_util import Logger
from .workspace import Workspace


class Context:
    """Bundles workspace, configuration, logging and global flags.

    Handlers receive a Context and never read global state directly, which keeps
    commands testable and deterministic.
    """

    def __init__(self, *, as_json: bool = False, verbose: bool = False,
                 quiet: bool = False, workspace_path: str | None = None,
                 config_path: str | None = None, assume_yes: bool = False):
        self.as_json = as_json
        self.verbose = verbose
        self.quiet = quiet
        self.assume_yes = assume_yes
        self.workspace_path = workspace_path
        self.config_path = config_path
        self._workspace: Workspace | None = None
        self._config: Config | None = None
        self.logger = Logger(verbose=verbose, quiet=quiet)

    # workspace -----------------------------------------------------------
    def workspace(self, *, required: bool = True) -> Workspace | None:
        """Resolve the workspace for this invocation.

        Pinning precedence (#268): an explicit ``--workspace`` flag wins, then
        the ``IOS_RESEARCH_WORKSPACE`` environment variable, then the
        cwd-relative fallback (``Workspace.require()/locate()``). The env var
        lets agents pin a workspace once per session instead of repeating
        ``--workspace`` on every command — a single forgotten flag otherwise
        silently operates on whatever workspace is nearest the cwd.
        """
        if self._workspace is not None:
            return self._workspace
        pinned = self.workspace_path or os.environ.get("IOS_RESEARCH_WORKSPACE")
        if pinned:
            ws = Workspace(Path(pinned))
            if required and not ws.initialized:
                from .errors import NotFoundError
                raise NotFoundError(f"no initialized workspace at {pinned}")
        elif required:
            ws = Workspace.require()
        else:
            ws = Workspace.locate()
        self._workspace = ws
        return ws

    # config --------------------------------------------------------------
    def config(self) -> Config:
        if self._config is not None:
            return self._config
        values: dict[str, Any] = {}
        ws = self.workspace(required=False)
        if ws is not None and ws.path("config/config.json").exists():
            values = ws.read_json("config/config.json")
        self._config = Config(values)
        return self._config

    def confirm(self, prompt: str) -> bool:
        """Confirmation gate for destructive operations.

        Non-interactive by default: unless ``--yes`` was supplied the operation
        is refused, which keeps agents from performing destructive actions
        without explicit researcher confirmation.
        """
        return bool(self.assume_yes)
