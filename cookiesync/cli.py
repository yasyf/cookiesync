from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import anyio
import click
from loguru import logger

from cookiesync import paths, state
from cookiesync.cookie import OutputFormat, StorageState, render
from cookiesync.cookie.browsers import REGISTRY
from cookiesync.daemon import rpc
from cookiesync.daemon.rpc import RpcError
from cookiesync.daemon.wire import cookie_from_wire
from cookiesync.registry import RegistryError, reposync_registry, reposync_self
from cookiesync.state import BrowserEndpoint, BrowserId, SshTarget, parse_duration

if TYPE_CHECKING:
    from cookiesync.daemon.wire import Response

CODESIGN = "/usr/bin/codesign"


@click.group()
@click.version_option(package_name="cookiesync")
def main() -> None:
    """Sync your browser cookies across machines."""


async def daemon_call(method: str, params: dict | None = None) -> dict | list | None:
    """Call ``method`` on the resident daemon, raising a clean :class:`click.ClickException` on failure."""
    try:
        response = await rpc.call(method, params or {})
    except RpcError as exc:
        raise click.ClickException(f"{exc}; is the daemon running? (cookiesync install)") from exc
    return response_result(response)


def response_result(response: Response) -> dict | list | None:
    if not response.ok:
        raise click.ClickException(response.error or "daemon error")
    return response.result


@main.group()
def browser() -> None:
    """Track the browser profiles cookiesync syncs across hosts."""


@browser.command("add")
@click.argument("host")
@click.argument("browser_name")
@click.option("--profile", default="Default", help="Profile directory name.")
def browser_add(host: str, browser_name: str, profile: str) -> None:
    """Track a browser profile on HOST for syncing."""
    anyio.run(add_endpoint, SshTarget(host), browser_name, profile)


@browser.command("ls")
@click.option("--json", "as_json", is_flag=True, help="Emit the endpoints as JSON.")
def browser_ls(as_json: bool) -> None:
    """List the tracked browser endpoints."""
    anyio.run(list_endpoints, as_json)


@browser.command("rm")
@click.argument("host")
@click.argument("browser_name")
@click.option("--profile", default="Default", help="Profile directory name.")
def browser_rm(host: str, browser_name: str, profile: str) -> None:
    """Stop tracking a browser profile on HOST."""
    anyio.run(remove_endpoint, SshTarget(host), browser_name, profile)


async def add_endpoint(host: SshTarget, browser_name: str, profile: str) -> None:
    if browser_name not in REGISTRY:
        raise click.ClickException(f"unknown browser {browser_name!r}; choose from {', '.join(sorted(REGISTRY))}")
    try:
        self_target, hosts = await reposync_registry()
    except RegistryError as exc:
        raise click.ClickException(str(exc)) from exc
    if host != self_target and host not in hosts:
        raise click.ClickException(f"unknown host {host!r}; choose from {', '.join((self_target, *hosts))}")
    endpoint = BrowserEndpoint(host, BrowserId(browser_name), profile)
    await state.update(
        lambda s: replace(
            s,
            self_target=self_target,
            browsers=(*(e for e in s.browsers if e.id != endpoint.id), endpoint),
        )
    )
    logger.debug("tracked {}", endpoint.id)
    click.echo(f"Tracking {endpoint.id}")


async def list_endpoints(as_json: bool) -> None:
    browsers = (await state.load()).browsers
    if as_json:
        click.echo(json.dumps([endpoint.to_json() for endpoint in browsers], indent=2))
        return
    click.echo("\n".join(endpoint.id for endpoint in browsers) if browsers else "No tracked browsers.")


async def remove_endpoint(host: SshTarget, browser_name: str, profile: str) -> None:
    target = BrowserEndpoint(host, BrowserId(browser_name), profile).id
    await state.update(lambda s: replace(s, browsers=tuple(e for e in s.browsers if e.id != target)))
    logger.debug("untracked {}", target)
    click.echo(f"Untracked {target}")


@main.command()
def watch() -> None:
    """Run the resident sync daemon: watch local stores and serve the RPC socket."""
    anyio.run(run_watch)


async def run_watch() -> None:
    from cookiesync.daemon import Daemon

    logger.debug("starting cookiesync daemon")
    await (await Daemon.build()).watch()


@main.command()
@click.option("--tick-only", is_flag=True, help="Install only the periodic reconcile tick, not the watch daemon.")
def install(tick_only: bool) -> None:
    """Install the cookiesync LaunchAgents (watch daemon and reconcile tick)."""
    anyio.run(run_install, tick_only)


async def run_install(tick_only: bool) -> None:
    from cookiesync.service import LaunchctlLauncher, install

    await report_helper()
    await install(LaunchctlLauncher(), tick_only=tick_only)
    click.echo("Installed cookiesync agents." if not tick_only else "Installed the cookiesync reconcile tick.")


@main.command()
def doctor() -> None:
    """Check that the signed Secure-Enclave key helper is installed and Developer-ID-signed."""
    anyio.run(run_doctor)


async def run_doctor() -> None:
    match await helper_state():
        case "ok":
            click.echo(f"key helper OK: {paths.helper_app_path()} (Developer ID signed)")
        case "unsigned":
            raise click.ClickException(
                f"key helper at {paths.helper_app_path()} is not Developer-ID-signed; reinstall the notarized .app"
            )
        case "missing":
            raise click.ClickException(
                f"key helper not installed at {paths.helper_app_path()}; run 'cookiesync install' to fetch it"
            )


async def helper_state() -> str:
    """Classify the installed key helper as ``ok`` (signed), ``unsigned``, or ``missing``."""
    if not paths.helper_binary().is_file():
        return "missing"
    result = await anyio.run_process([CODESIGN, "--verify", "--strict", str(paths.helper_app_path())], check=False)
    return "ok" if result.returncode == 0 else "unsigned"


async def report_helper() -> None:
    match await helper_state():
        case "ok":
            return
        case "unsigned":
            click.echo(
                f"Warning: key helper at {paths.helper_app_path()} is not Developer-ID-signed; "
                "reinstall the notarized .app — Secure-Enclave operations will fail closed.",
                err=True,
            )
        case "missing":
            click.echo(
                f"Warning: key helper not installed at {paths.helper_app_path()}; "
                "Touch-ID consent and the key cache will fail closed until it is installed.",
                err=True,
            )


@main.command()
def uninstall() -> None:
    """Remove the cookiesync LaunchAgents."""
    anyio.run(run_uninstall)


async def run_uninstall() -> None:
    from cookiesync.service import LaunchctlLauncher, uninstall

    await uninstall(LaunchctlLauncher())
    click.echo("Uninstalled cookiesync agents.")


@main.command()
def reconcile() -> None:
    """Ask the daemon to run a full reconcile pass over every tracked browser group."""
    anyio.run(run_reconcile)


async def run_reconcile() -> None:
    result = await daemon_call("reconcile")
    click.echo(json.dumps(result, indent=2))


@main.command("sync")
@click.option("--browser", "browser_name", required=True, help="The browser group to converge.")
def sync_cmd(browser_name: str) -> None:
    """Ask the daemon to converge one browser group across this host and its peers."""
    anyio.run(run_sync, browser_name)


async def run_sync(browser_name: str) -> None:
    result = await daemon_call("sync", {"browser": browser_name})
    click.echo(json.dumps(result, indent=2))


@main.command()
@click.option("--browser", "browser_name", default="chrome", show_default=True, help="The browser to authenticate.")
@click.option("--profile", default="Default", show_default=True, help="The profile to authenticate.")
@click.option("--ttl", default=None, help="Override the cache TTL (Go-style duration, e.g. 15m).")
def auth(browser_name: str, profile: str, ttl: str | None) -> None:
    """Release the Safe Storage key behind one Touch ID tap and cache it for a short window."""
    anyio.run(run_auth, browser_name, profile, ttl)


async def run_auth(browser_name: str, profile: str, ttl: str | None) -> None:
    if ttl is not None:
        await state.update(lambda s: replace(s, settings=replace(s.settings, auth_ttl=parse_duration(ttl))))
    result = await daemon_call("prime_auth", {"browser": browser_name, "profile": profile})
    click.echo(f"Authenticated {result['endpoint']}.")


@main.command()
@click.argument("url")
@click.option(
    "--browser", "browser_name", default="chrome", show_default=True, help="The browser to read cookies from."
)
@click.option("--profile", default="Default", show_default=True, help="The profile to read cookies from.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice([f.value for f in OutputFormat]),
    default=OutputFormat.PLAYWRIGHT.value,
    show_default=True,
    help="The output wire format.",
)
def cookies(url: str, browser_name: str, profile: str, fmt: str) -> None:
    """Stream URL's cookies in the chosen format, decrypting with the daemon's cached key."""
    anyio.run(run_cookies, url, browser_name, profile, fmt)


async def run_cookies(url: str, browser_name: str, profile: str, fmt: str) -> None:
    result = await daemon_call("get_cookies", {"url": url, "browser": browser_name, "profile": profile})
    state_obj = StorageState(tuple(cookie_from_wire(c) for c in result["cookies"]))
    for line in render(state_obj, OutputFormat(fmt)):
        click.echo(line)


@main.group()
def rpc_group() -> None:
    """Low-level RPC client: drive the resident daemon over its unix socket."""


main.add_command(rpc_group, name="rpc")


@rpc_group.command("extract")
@click.option("--browser", "browser_name", required=True)
@click.option("--profile", default="Default")
@click.option("--origin", default=None)
def rpc_extract(browser_name: str, profile: str, origin: str | None) -> None:
    """Return this host's decrypted cookies for a browser as wire records (used by peers over ssh)."""
    anyio.run(run_rpc_passthrough, "extract", {"browser": browser_name, "profile": profile, "origin": origin})


@rpc_group.command("apply")
@click.option("--browser", "browser_name", required=True)
@click.option("--profile", default="Default")
@click.option("--origin", default=None)
def rpc_apply(browser_name: str, profile: str, origin: str | None) -> None:
    """Ingest a merged wire cookie array from stdin into this host's store (used by peers over ssh)."""
    cookies_in = json.loads(click.get_text_stream("stdin").read())
    anyio.run(
        run_rpc_passthrough,
        "apply",
        {"browser": browser_name, "profile": profile, "origin": origin, "cookies": cookies_in},
    )


@rpc_group.command("sync")
@click.option("--browser", "browser_name", required=True)
@click.option("--origin", default=None)
def rpc_sync(browser_name: str, origin: str | None) -> None:
    """Ask the daemon to converge one browser group, tagged with the notifying peer's origin."""
    anyio.run(run_rpc_passthrough, "sync", {"browser": browser_name, "origin": origin})


@rpc_group.command("reconcile")
def rpc_reconcile() -> None:
    """Ask the daemon to run a full reconcile pass."""
    anyio.run(run_rpc_passthrough, "reconcile", {})


@rpc_group.command("whoami")
def rpc_whoami() -> None:
    """Report this host's console session state."""
    anyio.run(run_rpc_passthrough, "whoami", {})


@rpc_group.command("request_consent")
@click.option("--browser", "browser_name", required=True)
@click.option("--profile", default="Default")
@click.option("--nonce", required=True)
@click.option("--endpoint", required=True)
def rpc_request_consent(browser_name: str, profile: str, nonce: str, endpoint: str) -> None:
    """Show the Touch ID prompt for BROWSER here and echo the requester's nonce + endpoint."""
    anyio.run(
        run_rpc_passthrough,
        "request_consent",
        {"browser": browser_name, "profile": profile, "nonce": nonce, "endpoint": endpoint},
    )


async def run_rpc_passthrough(method: str, params: dict) -> None:
    click.echo(json.dumps(await daemon_call(method, params)))


@main.command(name="self")
def self_cmd() -> None:
    """Print this host's own SSH target, as reposync reports it."""
    anyio.run(run_self)


async def run_self() -> None:
    try:
        target = await reposync_self()
    except RegistryError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(target)
