from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync.cookie import consent
from cookiesync.cookie.browsers import REGISTRY, BrowserName
from cookiesync.cookie.consent import ConsentError, TouchIDConsent, compose_reason
from cookiesync.cookie.crypto import derive_key
from cookiesync.cookie.models import SafeStorageKey

if TYPE_CHECKING:
    from collections.abc import Sequence

CHROME = REGISTRY[BrowserName("chrome")]
VAULT = f"cookiesync.vault.{CHROME.name}"
PASSWORD = "peanuts-safe-storage-key"
HELPER = Path("/fake/bin/keyvault")


class FakeRunner:
    """A stand-in for ``anyio.run_process`` that scripts each command's result by verb.

    ``status``/``retrieve``/``enroll`` are dispatched on ``argv[1]``; the ``security``
    fallback on ``argv[0]``. Every invocation is recorded so tests can assert call counts.
    """

    def __init__(self, *, status: tuple[int, bytes], retrieve: tuple[int, bytes], security: tuple[int, bytes]):
        self.status = status
        self.retrieve = retrieve
        self.security = security
        self.calls: list[list[str]] = []

    async def __call__(
        self, command: Sequence[str], *, check: bool = True, env: dict[str, str] | None = None, **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        argv = list(command)
        self.calls.append(argv)
        if argv[0] == consent.SECURITY:
            code, out = self.security
        else:
            match argv[1]:
                case "status":
                    code, out = self.status
                case "retrieve":
                    code, out = self.retrieve
                case "enroll":
                    code, out = 0, b""
                case _:
                    raise AssertionError(f"unexpected command: {argv}")
        if check and code != 0:
            raise subprocess.CalledProcessError(code, argv, output=out)
        return subprocess.CompletedProcess(argv, code, stdout=out, stderr=b"")

    def verb_count(self, verb: str) -> int:
        return sum(1 for argv in self.calls if (argv[0] if argv[0] == consent.SECURITY else argv[1]) == verb)


@pytest.fixture
def patched_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_compile() -> Path:
        return HELPER

    monkeypatch.setattr(consent, "compile_helper", fake_compile)


def _install(monkeypatch: pytest.MonkeyPatch, runner: FakeRunner) -> None:
    monkeypatch.setattr(consent.anyio, "run_process", runner)


async def test_retrieve_returns_derived_key_and_prompts_once(
    monkeypatch: pytest.MonkeyPatch, patched_helper: None
) -> None:
    runner = FakeRunner(
        status=(0, b"biometry=true passcode=true vault=true\n"),
        retrieve=(0, PASSWORD.encode()),
        security=(1, b""),
    )
    _install(monkeypatch, runner)

    key = await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")

    assert key == derive_key(SafeStorageKey(PASSWORD))
    assert runner.verb_count("retrieve") == 1
    assert runner.verb_count("enroll") == 0
    assert runner.verb_count(consent.SECURITY) == 0


async def test_enroll_then_retrieve_when_vault_missing(monkeypatch: pytest.MonkeyPatch, patched_helper: None) -> None:
    runner = FakeRunner(
        status=(2, b"biometry=true passcode=true vault=false\n"),
        retrieve=(0, PASSWORD.encode()),
        security=(1, b""),
    )
    _install(monkeypatch, runner)

    key = await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")

    assert key == derive_key(SafeStorageKey(PASSWORD))
    assert runner.verb_count("enroll") == 1
    assert runner.verb_count("retrieve") == 1
    enroll = next(argv for argv in runner.calls if argv[1] == "enroll")
    assert enroll == [str(HELPER), "enroll", VAULT, CHROME.keychain_service]


async def test_decline_raises_consent_error(monkeypatch: pytest.MonkeyPatch, patched_helper: None) -> None:
    runner = FakeRunner(
        status=(0, b"biometry=true passcode=true vault=true\n"),
        retrieve=(1, b""),
        security=(1, b""),
    )
    _install(monkeypatch, runner)

    with pytest.raises(ConsentError):
        await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")

    assert runner.verb_count("retrieve") == 1
    assert runner.verb_count(consent.SECURITY) == 0


async def test_unavailable_falls_back_to_security_read(monkeypatch: pytest.MonkeyPatch, patched_helper: None) -> None:
    runner = FakeRunner(
        status=(2, b"biometry=false passcode=false vault=false\n"),
        retrieve=(0, b"should-not-be-used"),
        security=(0, PASSWORD.encode() + b"\n"),
    )
    _install(monkeypatch, runner)

    key = await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")

    assert key == derive_key(SafeStorageKey(PASSWORD))
    assert runner.verb_count(consent.SECURITY) == 1
    assert runner.verb_count("retrieve") == 0
    assert runner.verb_count("enroll") == 0
    security = next(argv for argv in runner.calls if argv[0] == consent.SECURITY)
    assert security == [consent.SECURITY, "find-generic-password", "-w", "-s", CHROME.keychain_service]


async def test_security_fallback_failure_raises(monkeypatch: pytest.MonkeyPatch, patched_helper: None) -> None:
    runner = FakeRunner(
        status=(2, b"biometry=false passcode=false vault=false\n"),
        retrieve=(0, b""),
        security=(44, b""),
    )
    _install(monkeypatch, runner)

    with pytest.raises(ConsentError, match="Keychain"):
        await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")


async def test_invalidated_vault_reenrolls_then_retrieves(
    monkeypatch: pytest.MonkeyPatch, patched_helper: None
) -> None:
    # status says the item exists, but retrieve hits errSecItemNotFound (exit 2):
    # the biometryCurrentSet ACL invalidated. obtain_key must re-enroll and retry.
    retrieve_results = iter([(2, b""), (0, PASSWORD.encode())])

    runner = FakeRunner(
        status=(0, b"biometry=true passcode=true vault=true\n"),
        retrieve=(0, b""),
        security=(1, b""),
    )

    async def scripted_retrieve(
        command: Sequence[str], *, check: bool = True, env: dict[str, str] | None = None, **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        argv = list(command)
        runner.calls.append(argv)
        if argv[1] == "retrieve":
            code, out = next(retrieve_results)
            return subprocess.CompletedProcess(argv, code, stdout=out, stderr=b"")
        if argv[1] == "enroll":
            return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=runner.status[1], stderr=b"")

    monkeypatch.setattr(consent.anyio, "run_process", scripted_retrieve)

    key = await TouchIDConsent().obtain_key(CHROME, reason="post a tweet")

    assert key == derive_key(SafeStorageKey(PASSWORD))
    assert runner.verb_count("enroll") == 1
    assert runner.verb_count("retrieve") == 2


async def test_obtain_key_unprompted_does_a_bare_security_read_no_touch_id(
    monkeypatch: pytest.MonkeyPatch, patched_helper: None
) -> None:
    # SF1: the owning-host non-interactive release reads Safe Storage directly via `security`
    # and never invokes the Touch ID vault helper (status/retrieve/enroll).
    runner = FakeRunner(
        status=(0, b"biometry=true passcode=true vault=true\n"),
        retrieve=(0, b"should-not-be-used"),
        security=(0, PASSWORD.encode() + b"\n"),
    )
    _install(monkeypatch, runner)

    key = await TouchIDConsent().obtain_key_unprompted(CHROME)

    assert key == derive_key(SafeStorageKey(PASSWORD))
    assert runner.verb_count(consent.SECURITY) == 1
    assert runner.verb_count("retrieve") == 0
    assert runner.verb_count("status") == 0
    assert runner.verb_count("enroll") == 0
    security = next(argv for argv in runner.calls if argv[0] == consent.SECURITY)
    assert security == [consent.SECURITY, "find-generic-password", "-w", "-s", CHROME.keychain_service]


def test_compose_reason_collapses_whitespace_and_caps() -> None:
    assert compose_reason("Chrome", "post   a\n\ttweet") == "access your Chrome session to post a tweet"
    long = "x" * 300
    composed = compose_reason("Chrome", long)
    assert composed == f"access your Chrome session to {'x' * consent.REASON_CAP}"
    assert composed.endswith("x" * consent.REASON_CAP)


def test_data_dir_honors_claude_plugin_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", "/data/plugin")
    assert consent.data_dir() == Path("/data/plugin")


def test_data_dir_falls_back_to_xdg_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", "/xdg/cache")
    assert consent.data_dir() == Path("/xdg/cache/cookiesync")
