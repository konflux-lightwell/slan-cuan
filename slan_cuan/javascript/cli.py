"""javascript ecosystem CLI group."""

from __future__ import annotations

import click

from slan_cuan.javascript.extract import extract
from slan_cuan.javascript.upload import upload


@click.group("javascript")
def javascript_cli() -> None:
    """JavaScript ecosystem release commands."""


javascript_cli.add_command(extract)
javascript_cli.add_command(upload)
