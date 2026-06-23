from __future__ import annotations

from click.testing import CliRunner

from cookiesync.cli import main


def test_help_exits_cleanly() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith("Usage: main")


def test_help_lists_daemon_commands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    for command in ("watch", "install", "uninstall", "reconcile", "sync", "auth", "cookies", "rpc", "self"):
        assert command in result.output


def test_hello_is_gone() -> None:
    result = CliRunner().invoke(main, ["hello"])
    assert result.exit_code != 0
