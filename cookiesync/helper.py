"""Install and classify the signed Secure-Enclave key helper ``.app``.

``cookiesync install`` installs the helper through Homebrew —
``brew install yasyf/tap/cookiesync-keyhelper`` against the shared central tap. Homebrew
downloads the release asset, verifies its checksum, and lays the stapled, notarized
``.app`` down in the cask appdir; cookiesync then asserts the installed bundle carries a
valid Developer-ID anchor before trusting it. An ad-hoc, unsigned, or wrong-anchor bundle
is refused — macOS 15/26 SIGKILL an ad-hoc signature at exec and refuse it the Secure
Enclave.

The Developer-ID anchor check is the same designated-requirement OID
(``1.2.840.113635.100.6.2.6``) the release workflow seals against, so a bundle that
``codesign --verify --strict`` would pass on its own (e.g. an ad-hoc signature) still
classifies as ``UNSIGNED`` here.
"""

from __future__ import annotations

import re
import shutil
from enum import Enum
from pathlib import Path

import anyio

from cookiesync import paths

CODESIGN = "/usr/bin/codesign"
DEVELOPER_ID_REQUIREMENT = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
BREW_CASK = "yasyf/tap/cookiesync-keyhelper"
PROBE_VAULT = "cookiesync-doctor-probe"
CONTRACT_LINE = re.compile(rb"^biometry=(?:true|false) passcode=(?:true|false) vault=(?:true|false)$", re.MULTILINE)


class HelperState(Enum):
    OK = "ok"
    UNSIGNED = "unsigned"
    MISSING = "missing"


class HelperInstallError(Exception):
    """The signed key helper could not be installed or verified."""


async def developer_id_signed(app_path: Path) -> bool:
    """Whether ``app_path`` has an intact signature anchored to Apple's Developer ID.

    Runs ``codesign --verify --strict`` with the Developer-ID designated-requirement
    OID, so an ad-hoc or wrong-anchor signature (which a bare ``--verify`` would accept)
    returns ``False``.
    """
    result = await anyio.run_process(
        # -R takes the requirement inline via `-R=<req>`; as a separate argv (`-R`, `<req>`)
        # codesign reads it as a requirement *file* path and fails "invalid requirement".
        [CODESIGN, "--verify", "--strict", f"-R={DEVELOPER_ID_REQUIREMENT}", str(app_path)],
        check=False,
    )
    return result.returncode == 0


async def helper_state() -> HelperState:
    """Classify the installed key helper as ``OK`` (Developer-ID signed), ``UNSIGNED``, or ``MISSING``."""
    if not paths.helper_binary().is_file():
        return HelperState.MISSING
    return HelperState.OK if await developer_id_signed(paths.helper_app_path()) else HelperState.UNSIGNED


async def supports_contract() -> bool:
    """Whether the installed helper honours the key-helper subcommand contract cookiesync depends on.

    The cask version can lag the package version, and cookiesync resolves the helper by name,
    so a stale or incompatible bundle may sit at the expected path. Runs the read-only
    ``vault-status`` subcommand against a fake vault — it never triggers a Touch ID prompt —
    and passes iff the helper exits 0 and emits the documented
    ``biometry=<bool> passcode=<bool> vault=<bool>`` contract line.
    """
    result = await anyio.run_process(
        [str(paths.helper_binary()), "vault-status", PROBE_VAULT],
        check=False,
    )
    # vault-status prints the contract line then exits 2 ("unavailable") for a vault that
    # doesn't exist — our probe vault never does — so the contract line on stdout, not the
    # exit code, is the capability signal. A helper lacking the subcommand prints usage to
    # stderr and emits no such line.
    return CONTRACT_LINE.search(result.stdout) is not None


async def install_helper() -> Path:
    """Install the signed Secure-Enclave key helper via Homebrew, then verify its Developer-ID anchor.

    Runs ``brew install yasyf/tap/cookiesync-keyhelper`` — Homebrew downloads the release
    asset, checksum-verifies it, and lays the stapled, notarized ``.app`` into the cask
    appdir — then locates the installed bundle and asserts it is Developer-ID signed. Raises
    :class:`HelperInstallError` if Homebrew is absent, the install fails, the bundle cannot
    be located, or the anchor check fails: an unverified bundle is never trusted.

    Returns:
        The installed ``cookiesync-keyhelper.app`` path.
    """
    if (brew := shutil.which("brew")) is None:
        raise HelperInstallError(
            "Homebrew is required to install the signed key helper; install it from "
            "https://brew.sh, then rerun 'cookiesync install'"
        )
    result = await anyio.run_process([brew, "install", "--cask", BREW_CASK], check=False)
    if result.returncode != 0:
        raise HelperInstallError(f"'brew install --cask {BREW_CASK}' failed: {result.stderr.decode().strip()}")
    app_path = paths.helper_app_path()
    if not await anyio.Path(app_path).is_dir():
        raise HelperInstallError(
            f"'brew install --cask {BREW_CASK}' reported success but no bundle is present at {app_path}"
        )
    if not await developer_id_signed(app_path):
        raise HelperInstallError(
            f"refusing to trust {app_path.name}: it is not Developer-ID-signed "
            "(codesign --verify --strict and the Developer-ID anchor must both pass)"
        )
    return app_path
