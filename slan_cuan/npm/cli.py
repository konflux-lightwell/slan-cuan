"""npm ecosystem CLI group."""

from __future__ import annotations

import click

from slan_cuan.npm.closure import closure_cli
from slan_cuan.npm.extract import extract
from slan_cuan.npm.upload import upload


@click.group("npm")
def npm_cli() -> None:
    """Npm ecosystem release commands."""


npm_cli.add_command(extract)
npm_cli.add_command(upload)
npm_cli.add_command(closure_cli)
