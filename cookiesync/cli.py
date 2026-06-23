from __future__ import annotations

import click
from loguru import logger


@click.group()
@click.version_option(package_name="cookiesync")
def main() -> None:
    """Sync your browser cookies across machines."""


@main.command()
def hello() -> None:
    """Print a greeting — the starter command."""
    logger.debug("hello invoked")
    click.echo("Hello from cookiesync!")
