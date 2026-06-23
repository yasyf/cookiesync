"""Async SSH transport: run a remote command over ssh and fan out across hosts.

Mirrors reposync's host transport — the same BatchMode/keepalive flag set and the
``brew shellenv`` wrap, since a non-interactive ssh on macOS lacks brew (and thus
brew-installed cookiesync) on ``PATH``.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from cookiesync.state import SshTarget

SSH_OPTS = (
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
)

BREW_SHELLENV = "/opt/homebrew/bin/brew shellenv"

MAX_CONCURRENT_HOSTS = 8


class SshError(Exception):
    """An ssh command exited non-zero, carrying the target and the remote stderr."""

    def __init__(self, target: SshTarget, returncode: int, stderr: str) -> None:
        self.target = target
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"ssh {target}: exit {returncode}: {stderr}")


@dataclass(frozen=True, slots=True)
class HostResult[T]:
    """The outcome of running a fan-out function against one host.

    ``ok`` is ``True`` and ``value`` holds the return when the function succeeded;
    ``ok`` is ``False`` and ``value`` holds the raised exception when it failed.
    """

    target: SshTarget
    ok: bool
    value: T | BaseException


def shell_quote(s: str) -> str:
    """Quote ``s`` so it survives intact as one argument to a remote shell."""
    return shlex.quote(s)


async def ssh(target: SshTarget, remote_cmd: str, *, stdin: bytes | None = None) -> str:
    """Run ``remote_cmd`` on ``target`` over ssh and return its stdout.

    The remote command is wrapped to source brew's shellenv first. ``stdin``, when
    given, is piped to the remote command's standard input.

    Raises:
        SshError: the ssh process exited non-zero; carries the target and stderr.
    """
    result = await anyio.run_process(
        ["ssh", *SSH_OPTS, target, f'eval "$({BREW_SHELLENV})" && {remote_cmd}'],
        input=stdin,
        check=False,
    )
    if result.returncode != 0:
        raise SshError(target, result.returncode, result.stderr.decode().strip())
    return result.stdout.decode()


async def each_host[T](
    targets: Sequence[SshTarget],
    fn: Callable[[SshTarget], Awaitable[T]],
    *,
    limit: int = MAX_CONCURRENT_HOSTS,
) -> list[HostResult[T]]:
    """Run ``fn`` against every target concurrently, bounded by ``limit``.

    Each target's outcome is captured into a ``HostResult`` so one failing host
    never aborts the batch. Results come back in input order.
    """
    semaphore = anyio.Semaphore(limit)
    collected: dict[int, HostResult[T]] = {}

    async def run(index: int, target: SshTarget) -> None:
        async with semaphore:
            try:
                collected[index] = HostResult(target, True, await fn(target))
            except Exception as exc:  # noqa: BLE001 — per-host failures are collected, not swallowed
                collected[index] = HostResult(target, False, exc)

    async with anyio.create_task_group() as tg:
        for index, target in enumerate(targets):
            tg.start_soon(run, index, target)
    return [collected[index] for index in range(len(targets))]
