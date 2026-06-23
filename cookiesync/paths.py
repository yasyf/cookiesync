"""On-disk locations for cookiesync's config dir, state file, RPC socket, reconcile lock, and signed helper.

The config dir honours ``XDG_CONFIG_HOME`` (falling back to ``~/.config``) and holds a
``cookiesync`` subdirectory shared by every writer of ``state.json``. The signed
Secure-Enclave helper ships as a Homebrew cask (``yasyf/tap/cookiesync-keyhelper``) and
installs its ``.app`` into the Homebrew cask appdir — ``/Applications`` by default, or
``~/Applications`` when brew runs without admin rights.
"""

from __future__ import annotations

import os
from pathlib import Path

CONFIG_SUBDIR = "cookiesync"
DATA_SUBDIR = "cookiesync"
STATE_FILE = "state.json"
SOCK_FILE = "rpc.sock"
LOCK_FILE = "reconcile.lock"
HELPER_APP = "cookiesync-keyhelper.app"
HELPER_EXECUTABLE = "cookiesync-keyhelper"


class HelperError(Exception):
    """The signed Secure-Enclave helper is not installed; run ``cookiesync install`` to fetch it."""


def config_dir() -> Path:
    """The cookiesync config directory under ``XDG_CONFIG_HOME`` or ``~/.config``."""
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / CONFIG_SUBDIR


def data_dir() -> Path:
    """The cookiesync data directory under ``XDG_DATA_HOME`` or ``~/.local/share``."""
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / DATA_SUBDIR


def cask_app_dirs() -> tuple[Path, ...]:
    """The Homebrew cask appdirs an ``app`` stanza may install into, most-specific first."""
    return Path("/Applications"), Path.home() / "Applications"


def helper_app_path() -> Path:
    """The cask-installed ``cookiesync-keyhelper.app`` bundle path.

    ``brew install yasyf/tap/cookiesync-keyhelper`` moves the signed ``.app`` into the
    Homebrew cask appdir — ``/Applications`` by default, or ``~/Applications`` when brew
    runs without admin rights. Returns the first appdir that holds the bundle, falling back
    to the default appdir so a not-yet-installed helper still reports a stable path.
    """
    dirs = cask_app_dirs()
    return next((app for d in dirs if (app := d / HELPER_APP).is_dir()), dirs[0] / HELPER_APP)


def helper_binary() -> Path:
    """The signed helper's inner executable, e.g. ``…/cookiesync-keyhelper.app/Contents/MacOS/cookiesync-keyhelper``."""
    return helper_app_path() / "Contents" / "MacOS" / HELPER_EXECUTABLE


def require_helper() -> Path:
    """The signed helper executable, or raise :class:`HelperError` if it is not installed.

    The Secure-Enclave key vault and key cache run inside a Developer-ID-signed,
    notarized ``.app``; an ad-hoc build is SIGKILLed at exec by AMFI and cannot touch
    the Enclave. Callers fail closed on a missing helper rather than degrading to an
    unsigned fallback.
    """
    if not (binary := helper_binary()).is_file():
        raise HelperError(
            f"cookiesync key helper not found at {binary}; run 'cookiesync install' to fetch the signed helper"
        )
    return binary


def state_path() -> Path:
    """The ``state.json`` file holding this host's cookiesync configuration."""
    return config_dir() / STATE_FILE


def sock_path() -> Path:
    """The daemon's RPC unix socket."""
    return config_dir() / SOCK_FILE


def lock_path() -> Path:
    """The reconcile lock file every cross-process ``state.json`` writer serializes on."""
    return config_dir() / LOCK_FILE
