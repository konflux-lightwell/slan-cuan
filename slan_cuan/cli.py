"""CLI entry point and group definition."""

import click

from slan_cuan.context import GlobalContext
from slan_cuan.extract import extract


@click.group(context_settings={"auto_envvar_prefix": "SLAN_CUAN"})
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose output.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Perform a dry run without making any changes.",
)
@click.pass_context
def main(ctx: click.Context, verbose: bool, dry_run: bool) -> None:
    """Release pipeline for Red Hat Lightwell Java artifacts."""
    ctx.obj = GlobalContext(verbose=verbose, dry_run=dry_run)


main.add_command(extract)
