"""On-disk locations for cookiesync's config dir, state file, RPC socket, and reconcile lock.

The config dir honours ``XDG_CONFIG_HOME`` (falling back to ``~/.config``) and holds a
``cookiesync`` subdirectory shared by every writer of ``state.json``.
"""

from __future__ import annotations

import os
from pathlib import Path

CONFIG_SUBDIR = "cookiesync"
STATE_FILE = "state.json"
SOCK_FILE = "rpc.sock"
LOCK_FILE = "reconcile.lock"


def config_dir() -> Path:
    """The cookiesync config directory under ``XDG_CONFIG_HOME`` or ``~/.config``."""
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / CONFIG_SUBDIR


def state_path() -> Path:
    """The ``state.json`` file holding this host's cookiesync configuration."""
    return config_dir() / STATE_FILE


def sock_path() -> Path:
    """The daemon's RPC unix socket."""
    return config_dir() / SOCK_FILE


def lock_path() -> Path:
    """The reconcile lock file every cross-process ``state.json`` writer serializes on."""
    return config_dir() / LOCK_FILE
