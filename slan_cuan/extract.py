"""Extract subcommand for pulling artifacts from PNC container images."""

import click

from slan_cuan.context import GlobalContext


@click.command()
@click.option(
    "--image",
    required=True,
    type=str,
    help="Container image reference to extract artifacts from.",
)
@click.pass_obj
def extract(ctx: GlobalContext, image: str) -> None:
    """Extract artifacts from a PNC container image."""
    click.echo(
        f"extract: image={image} verbose={ctx.verbose} dry_run={ctx.dry_run}"
    )
