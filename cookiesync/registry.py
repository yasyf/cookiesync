"""Bridge to the ``reposync`` host registry over its ``--json`` contract.

``reposync host ls --json`` and ``reposync self --json`` emit a versioned envelope
(``{"version": 1, "self": ..., "hosts": [...]}``); we pin ``version == 1`` and fail
loud on any drift so a contract change can never be silently mis-parsed.
"""

from __future__ import annotations

import json
from subprocess import CalledProcessError
from typing import TYPE_CHECKING

import anyio

from cookiesync.state import SshTarget

if TYPE_CHECKING:
    from collections.abc import Sequence

REGISTRY_VERSION = 1


class RegistryError(Exception):
    """The ``reposync`` registry could not be read or violated its ``--json`` contract."""


async def _reposync(*args: str) -> dict:
    cmd = f"reposync {' '.join(args)}"
    try:
        proc = await anyio.run_process(["reposync", *args])
    except FileNotFoundError as exc:
        raise RegistryError("reposync is not installed or not on PATH") from exc
    except CalledProcessError as exc:
        raise RegistryError(f"{cmd} failed: {exc.stderr.decode().strip() or f'exit {exc.returncode}'}") from exc
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{cmd} emitted non-JSON output") from exc
    match payload:
        case {"version": version, **rest} if version == REGISTRY_VERSION:
            return rest
        case {"version": version}:
            raise RegistryError(f"{cmd} reported version {version}, expected {REGISTRY_VERSION}")
        case _:
            raise RegistryError(f"{cmd} omitted the version field")


def _targets(hosts: Sequence[str]) -> tuple[SshTarget, ...]:
    return tuple(SshTarget(host) for host in hosts)


async def reposync_registry() -> tuple[SshTarget, tuple[SshTarget, ...]]:
    """The local target and every peer host, parsed from ``reposync host ls --json``.

    Returns:
        A ``(self_target, peer_hosts)`` pair; ``peer_hosts`` is empty when this host
        stands alone.

    Raises:
        RegistryError: The envelope is missing or pins a version other than ``1``.

    Example:
        >>> self_target, hosts = await reposync_registry()
    """
    data = await _reposync("host", "ls", "--json")
    return SshTarget(data["self"]), _targets(data["hosts"])


async def reposync_self() -> SshTarget:
    """This machine's own SSH target, parsed from ``reposync self --json``.

    Raises:
        RegistryError: The envelope is missing or pins a version other than ``1``.

    Example:
        >>> await reposync_self()
    """
    return SshTarget((await _reposync("self", "--json"))["self"])
