"""CLI entry point and group definition."""

from pathlib import Path

import click

from slan_cuan.context import GlobalContext
from slan_cuan.extract import extract
from slan_cuan.publish import publish
from slan_cuan.sign import sign


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
@click.option(
    "--ca-cert",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a custom CA certificate bundle for TLS verification.",
)
@click.pass_context
def main(
    ctx: click.Context,
    verbose: bool,
    dry_run: bool,
    ca_cert: Path | None,
) -> None:
    """Release pipeline for Red Hat Lightwell Java artifacts."""
    ctx.obj = GlobalContext(
        verbose=verbose,
        dry_run=dry_run,
        ca_cert=ca_cert,
    )


main.add_command(extract)
main.add_command(publish)
main.add_command(sign)

if __name__ == "__main__":
    main()
