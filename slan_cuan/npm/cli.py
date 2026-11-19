"""npm ecosystem CLI group."""

from __future__ import annotations

import click

from slan_cuan.npm.extract import extract


@click.group("npm")
def npm_cli() -> None:
    """Npm ecosystem release commands."""


npm_cli.add_command(extract)
