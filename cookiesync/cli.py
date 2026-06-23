from __future__ import annotations

import json
from dataclasses import replace

import anyio
import click
from loguru import logger

from cookiesync import state
from cookiesync.cookie.browsers import REGISTRY
from cookiesync.registry import RegistryError, reposync_registry
from cookiesync.state import BrowserEndpoint, BrowserId, SshTarget


@click.group()
@click.version_option(package_name="cookiesync")
def main() -> None:
    """Sync your browser cookies across machines."""


@main.command()
def hello() -> None:
    """Print a greeting — the starter command."""
    logger.debug("hello invoked")
    click.echo("Hello from cookiesync!")


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
