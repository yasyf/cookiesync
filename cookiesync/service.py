"""Manage the two macOS LaunchAgents that drive cookiesync: a long-lived watch daemon and a periodic reconcile tick.

Mirrors reposync's service layer. Plist generation is a pure function so tests assert
the exact XML; the launchctl boundary is an injected :class:`Launcher` so tests never
bootstrap real agents. Three sharp edges are deliberate and must survive any cleanup:

* ``EnvironmentVariables.PATH`` prepends ``/opt/homebrew/bin`` — launchd strips the
  Homebrew prefixes where ``reposync`` and the browsers live, so the daemon would fail
  to resolve them otherwise.
* the program path is **not** symlink-resolved (it points at the stable installed
  ``cookiesync`` entrypoint), so a ``uv`` or ``brew`` upgrade that relinks the binary
  never strands the agent at a deleted versioned path.
* ``LimitLoadToSessionType`` is ``Aqua`` (the GUI session), required for the keychain
  and Touch-ID access the consent layer needs.
"""

from __future__ import annotations

import os
import plistlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NewType, Protocol

import anyio

if TYPE_CHECKING:
    from collections.abc import Sequence

Label = NewType("Label", str)

WATCH_LABEL = Label("com.github.yasyf.cookiesync.watch")
RECONCILE_LABEL = Label("com.github.yasyf.cookiesync.reconcile")

LAUNCH_AGENTS = Path("Library/LaunchAgents")

DAEMON_PATH = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin"

SESSION_TYPE = "Aqua"

RECONCILE_INTERVAL = 900

# launchctl bootout returns exit 3 (ESRCH) when the target agent isn't loaded — the only
# tolerated failure, so uninstall and re-install of an absent agent are idempotent. Install
# boots out before bootstrap (bootstrap_agent), so bootstrap never races an already-loaded
# agent; any nonzero bootstrap exit is a real error (a malformed plist also exits nonzero).
NOT_LOADED_EXIT = 3


class ServiceError(Exception):
    """A ``launchctl`` invocation failed for a reason other than an already-loaded or not-loaded agent."""


@dataclass(frozen=True, slots=True)
class AgentSpec:
    """One LaunchAgent: its label, the ``cookiesync`` subcommand it runs, and the launchd keys unique to it.

    The watch daemon carries ``KeepAlive``; the reconcile tick carries ``StartInterval``.
    Everything common — the PATH override, the Aqua session limit, ``RunAtLoad`` — lives
    in :func:`render` so the two agents can never diverge on it.
    """

    label: Label
    command: str
    extra: tuple[tuple[str, object], ...]

    def render(self) -> bytes:
        return plistlib.dumps(
            {
                "Label": self.label,
                "ProgramArguments": [program_path(), self.command],
                "EnvironmentVariables": {"PATH": DAEMON_PATH},
                "RunAtLoad": True,
                "LimitLoadToSessionType": SESSION_TYPE,
                "ProcessType": "Background",
                "StandardOutPath": str(log_path(self.label)),
                "StandardErrorPath": str(log_path(self.label)),
            }
            | dict(self.extra),
            sort_keys=True,
        )


RECONCILE_AGENT = AgentSpec(RECONCILE_LABEL, "reconcile", (("StartInterval", RECONCILE_INTERVAL),))
WATCH_AGENT = AgentSpec(WATCH_LABEL, "watch", (("KeepAlive", True),))
AGENTS: tuple[AgentSpec, ...] = (RECONCILE_AGENT, WATCH_AGENT)


class Launcher(Protocol):
    """The ``launchctl`` boundary: bootstraps and boots out LaunchAgents.

    Tests inject a fake so install/uninstall never touch the real launchd domain.
    """

    async def bootstrap(self, plist: Path) -> None:
        """Load the agent described by ``plist`` into this user's GUI launchd domain."""
        ...

    async def bootout(self, label: Label) -> None:
        """Remove the agent ``label`` from this user's GUI launchd domain."""
        ...


@dataclass(frozen=True, slots=True)
class LaunchctlLauncher:
    """The production :class:`Launcher`: shells out to ``launchctl bootstrap``/``bootout``.

    Both verbs target the caller's ``gui/<uid>`` domain. ``bootout`` tolerates exit 3
    (``ESRCH`` — the agent wasn't loaded) so uninstall and re-install stay idempotent;
    ``bootstrap`` tolerates nothing, since install boots out first. Any other non-zero
    exit raises :class:`ServiceError`.
    """

    async def bootstrap(self, plist: Path) -> None:
        await run_launchctl("bootstrap", gui_domain(), str(plist))

    async def bootout(self, label: Label) -> None:
        await run_launchctl("bootout", f"{gui_domain()}/{label}", ok=(NOT_LOADED_EXIT,))


def gui_domain() -> str:
    return f"gui/{os.getuid()}"


def launch_agents_dir() -> Path:
    return Path.home() / LAUNCH_AGENTS


def log_path(label: Label) -> Path:
    return Path.home() / "Library" / "Logs" / f"{label}.log"


def plist_path(label: Label) -> Path:
    """The on-disk ``~/Library/LaunchAgents/<label>.plist`` path for ``label``."""
    return launch_agents_dir() / f"{label}.plist"


def program_path() -> str:
    """The stable ``cookiesync`` entrypoint, deliberately NOT symlink-resolved.

    Resolving the symlink would bake a versioned ``uv``/Homebrew path into the plist
    that the next upgrade purges; pointing at the installed entrypoint keeps the agent
    valid across upgrades.
    """
    return shutil.which("cookiesync") or os.environ["COOKIESYNC_BIN"]


async def write_plist(label: Label, program_args: Sequence[str]) -> Path:
    """Render the agent for ``label`` running ``program_args`` and write it to its plist path.

    Args:
        label: The LaunchAgent label, which selects its launchd-key profile.
        program_args: The ``cookiesync`` subcommand the agent runs, e.g. ``["watch"]``.

    Returns:
        The ``~/Library/LaunchAgents/<label>.plist`` path the plist was written to.
    """
    await anyio.Path(launch_agents_dir()).mkdir(parents=True, exist_ok=True)
    await (path := anyio.Path(plist_path(label))).write_bytes(agent_for(label, program_args).render())
    return Path(path)


def agent_for(label: Label, program_args: Sequence[str]) -> AgentSpec:
    match next(agent for agent in AGENTS if agent.label == label):
        case agent if [agent.command] == list(program_args):
            return agent
        case agent:
            raise ServiceError(f"{label} runs {agent.command!r}, not {list(program_args)!r}")


async def run_launchctl(*args: str, ok: tuple[int, ...] = ()) -> None:
    result = await anyio.run_process(["launchctl", *args], check=False)
    if (code := result.returncode) and code not in ok:
        raise ServiceError(f"launchctl {args[0]}: exit {code}: {result.stderr.decode().strip()}")


async def install(launcher: Launcher, *, tick_only: bool = False) -> None:
    """Write and bootstrap the reconcile tick, and unless ``tick_only`` the watch daemon.

    Each agent is booted out before bootstrap so a re-install picks up plist changes,
    tolerating the not-loaded case on a first install.

    Args:
        launcher: The launchctl boundary that loads the agents.
        tick_only: Install only the periodic reconcile tick, skipping the watch daemon.
    """
    await bootstrap_agent(launcher, RECONCILE_AGENT)
    if tick_only:
        return
    await bootstrap_agent(launcher, WATCH_AGENT)


async def uninstall(launcher: Launcher) -> None:
    """Boot out both LaunchAgents and remove their plist files; a missing file is not an error.

    Args:
        launcher: The launchctl boundary that boots out the agents.
    """
    async with anyio.create_task_group() as tg:
        for agent in AGENTS:
            tg.start_soon(remove_agent, launcher, agent.label)


async def bootstrap_agent(launcher: Launcher, agent: AgentSpec) -> None:
    path = await write_plist(agent.label, [agent.command])
    await launcher.bootout(agent.label)
    await launcher.bootstrap(path)


async def remove_agent(launcher: Launcher, label: Label) -> None:
    await launcher.bootout(label)
    await anyio.Path(plist_path(label)).unlink(missing_ok=True)
