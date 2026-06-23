from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NewType

import anyio
import pytest

from cookiesync import transport
from cookiesync.transport import SshError, each_host, shell_quote, ssh

if TYPE_CHECKING:
    from collections.abc import Sequence

pytestmark = pytest.mark.anyio

SshTarget = NewType("SshTarget", str)

HOST = SshTarget("alice@laptop")

EXPECTED_ARGV = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=5",
    "-o",
    "ServerAliveInterval=5",
    "-o",
    "ServerAliveCountMax=3",
    HOST,
    'eval "$(/opt/homebrew/bin/brew shellenv)" && cookiesync --version',
]


@dataclass(frozen=True, slots=True)
class FakeCompleted:
    returncode: int
    stdout: bytes
    stderr: bytes


def fake_run_process(*, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
    calls: list[dict[str, object]] = []

    async def _run(command, *, input=None, check=True, **kwargs):  # noqa: A002 — mirrors anyio's signature
        calls.append({"command": command, "input": input, "check": check})
        return FakeCompleted(returncode, stdout, stderr)

    _run.calls = calls
    return _run


async def test_ssh_builds_exact_argv_and_returns_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    run = fake_run_process(stdout=b"cookiesync 0.1.0\n")
    monkeypatch.setattr(anyio, "run_process", run)

    out = await ssh(HOST, "cookiesync --version")

    assert out == "cookiesync 0.1.0\n"
    assert len(run.calls) == 1
    assert run.calls[0]["command"] == EXPECTED_ARGV
    assert run.calls[0]["check"] is False
    assert run.calls[0]["input"] is None


async def test_ssh_pipes_stdin_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    run = fake_run_process(stdout=b"ok")
    monkeypatch.setattr(anyio, "run_process", run)

    payload = b'{"cookies": []}'
    out = await ssh(HOST, "cookiesync apply", stdin=payload)

    assert out == "ok"
    assert run.calls[0]["input"] == payload


async def test_ssh_nonzero_exit_raises_with_target_and_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    run = fake_run_process(returncode=255, stderr=b"  ssh: connect to host laptop port 22: refused\n")
    monkeypatch.setattr(anyio, "run_process", run)

    with pytest.raises(SshError) as excinfo:
        await ssh(HOST, "true")

    err = excinfo.value
    assert err.target == HOST
    assert err.returncode == 255
    assert err.stderr == "ssh: connect to host laptop port 22: refused"
    assert HOST in str(err)
    assert "ssh: connect to host laptop port 22: refused" in str(err)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("has space", "'has space'"),
        ("it's", "'it'\"'\"'s'"),
        ("$(rm -rf /)", "'$(rm -rf /)'"),
        ("a;b|c", "'a;b|c'"),
    ],
    ids=["plain", "space", "single-quote", "command-sub", "metachars"],
)
def test_shell_quote_escapes(raw: str, expected: str) -> None:
    assert shell_quote(raw) == expected


async def test_each_host_runs_concurrently_and_collects_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    targets: Sequence[SshTarget] = [SshTarget(f"u@h{i}") for i in range(5)]
    barrier = anyio.Event()
    peak = 0
    live = 0

    async def fn(target: SshTarget) -> str:
        nonlocal peak, live
        live += 1
        peak = max(peak, live)
        if target == "u@h2":
            live -= 1
            raise RuntimeError(f"down: {target}")
        await barrier.wait()
        live -= 1
        return f"ran {target}"

    async def release() -> None:
        # let every task register its concurrency before any of them completes
        while peak < 4 and not barrier.is_set():
            await anyio.sleep(0)
        barrier.set()

    async with anyio.create_task_group() as tg:
        tg.start_soon(release)
        results = await each_host(targets, fn, limit=8)

    assert [r.target for r in results] == list(targets)
    assert peak >= 4  # the four healthy tasks overlapped, not serialized

    ok = {r.target: r.value for r in results if r.ok}
    failed = [r for r in results if not r.ok]
    assert ok == {
        SshTarget("u@h0"): "ran u@h0",
        SshTarget("u@h1"): "ran u@h1",
        SshTarget("u@h3"): "ran u@h3",
        SshTarget("u@h4"): "ran u@h4",
    }
    assert len(failed) == 1
    assert failed[0].target == SshTarget("u@h2")
    assert isinstance(failed[0].value, RuntimeError)
    assert str(failed[0].value) == "down: u@h2"


async def test_each_host_bounds_concurrency_at_limit() -> None:
    live = 0
    peak = 0
    gate = anyio.Event()

    async def fn(target: SshTarget) -> int:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await gate.wait()
        live -= 1
        return 1

    async def release() -> None:
        while peak < 2 and not gate.is_set():
            await anyio.sleep(0)
        gate.set()

    targets = [SshTarget(f"u@h{i}") for i in range(6)]
    async with anyio.create_task_group() as tg:
        tg.start_soon(release)
        results = await each_host(targets, fn, limit=2)

    assert peak <= 2  # never more than `limit` in flight at once
    assert all(r.ok for r in results)
    assert len(results) == 6


def test_ssh_opts_match_reposync() -> None:
    assert transport.SSH_OPTS == (
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=3",
    )
