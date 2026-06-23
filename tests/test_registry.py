from __future__ import annotations

import json
from subprocess import CalledProcessError, CompletedProcess
from typing import TYPE_CHECKING

import pytest

from cookiesync import registry
from cookiesync.registry import RegistryError, reposync_registry, reposync_self

if TYPE_CHECKING:
    from collections.abc import Sequence

LS = {"version": 1, "self": "yasyf@yasyf", "hosts": ["yasyf@yasyf-home", "yasyf@yasyf-work"]}
SELF = {"version": 1, "self": "yasyf@yasyf"}


class FakeRunProcess:
    def __init__(self, payload: object) -> None:
        self.stdout = json.dumps(payload).encode("utf-8")
        self.calls: list[Sequence[str]] = []

    async def __call__(self, command: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        self.calls.append(command)
        return CompletedProcess(args=command, returncode=0, stdout=self.stdout, stderr=b"")


def canned(monkeypatch: pytest.MonkeyPatch, payload: object) -> FakeRunProcess:
    monkeypatch.setattr(registry.anyio, "run_process", fake := FakeRunProcess(payload))
    return fake


async def test_registry_parses_self_and_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = canned(monkeypatch, LS)

    self_target, hosts = await reposync_registry()

    assert self_target == "yasyf@yasyf"
    assert hosts == ("yasyf@yasyf-home", "yasyf@yasyf-work")
    assert fake.calls == [["reposync", "host", "ls", "--json"]]


async def test_registry_empty_hosts_is_empty_tuple(monkeypatch: pytest.MonkeyPatch) -> None:
    canned(monkeypatch, {"version": 1, "self": "yasyf@yasyf", "hosts": []})

    self_target, hosts = await reposync_registry()

    assert self_target == "yasyf@yasyf"
    assert hosts == ()


async def test_self_parses_target(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = canned(monkeypatch, SELF)

    assert await reposync_self() == "yasyf@yasyf"
    assert fake.calls == [["reposync", "self", "--json"]]


@pytest.mark.parametrize(
    ("entrypoint", "payload"),
    [
        pytest.param(reposync_registry, {"version": 2, "self": "yasyf@yasyf", "hosts": []}, id="ls-version-2"),
        pytest.param(reposync_self, {"version": 2, "self": "yasyf@yasyf"}, id="self-version-2"),
    ],
)
async def test_version_mismatch_raises(monkeypatch: pytest.MonkeyPatch, entrypoint: object, payload: object) -> None:
    canned(monkeypatch, payload)

    with pytest.raises(RegistryError, match="version 2"):
        await entrypoint()


@pytest.mark.parametrize(
    ("entrypoint", "payload"),
    [
        pytest.param(reposync_registry, {"self": "yasyf@yasyf", "hosts": []}, id="ls-no-version"),
        pytest.param(reposync_self, {"self": "yasyf@yasyf"}, id="self-no-version"),
    ],
)
async def test_missing_version_raises(monkeypatch: pytest.MonkeyPatch, entrypoint: object, payload: object) -> None:
    canned(monkeypatch, payload)

    with pytest.raises(RegistryError, match="omitted the version field"):
        await entrypoint()


async def test_missing_binary_raises_registry_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(command: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(registry.anyio, "run_process", boom)

    with pytest.raises(RegistryError, match="not installed or not on PATH"):
        await reposync_registry()


async def test_nonzero_exit_raises_registry_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(command: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        raise CalledProcessError(1, command, output=b"", stderr=b"unknown flag: --json")

    monkeypatch.setattr(registry.anyio, "run_process", boom)

    with pytest.raises(RegistryError, match="unknown flag: --json"):
        await reposync_registry()


async def test_non_json_output_raises_registry_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def garbage(command: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        return CompletedProcess(args=command, returncode=0, stdout=b"not json at all", stderr=b"")

    monkeypatch.setattr(registry.anyio, "run_process", garbage)

    with pytest.raises(RegistryError, match="non-JSON"):
        await reposync_registry()
