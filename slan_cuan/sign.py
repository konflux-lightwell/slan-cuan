"""Sign subcommand for signing Maven artifacts on RADAS."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import click
from novabucks.logging import setup_logging
from novabucks.workflows import (
    sign_in_radas_workflow,
    sign_individual_artifacts_workflow,
)

from slan_cuan.context import GlobalContext


@click.command()
@click.option(
    "--repo-url",
    "-u",
    required=True,
    type=str,
    help=(
        "The pullspec of the image containing the maven repository."
        " E.g. quay.io/someorg/maven:latest"
    ),
)
@click.option(
    "--repo-path",
    "-p",
    required=True,
    type=str,
    help=(
        "The directory (or ZIP file) containing the downloaded maven repository."
    ),
)
@click.option(
    "--signing-key",
    "-k",
    required=True,
    type=str,
    help="The signing key name for RADAS.",
)
@click.option(
    "--output-path",
    "-o",
    required=True,
    type=str,
    help="The path to output the signed file(s).",
)
@click.option(
    "--radas-config",
    "-c",
    required=True,
    envvar="RADAS_CONFIG_PATH",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The path to the RADAS configuration file (JSON).",
)
@click.option(
    "--requester-id",
    "-r",
    default="slan-cuan@redhat.com",
    type=str,
    help="The requester ID to use for the signature.",
)
@click.option(
    "--zip-root-path",
    "-z",
    default="repository",
    type=str,
    help="The path to the root of maven's repository tree in the ZIP file.",
)
@click.option(
    "--product-key",
    "-b",
    default="slan-cuan",
    type=str,
    help="The product key to use for metadata generation.",
)
@click.option(
    "--ignore-patterns",
    "-i",
    multiple=True,
    help="Regex patterns to filter out files from signing.",
)
@click.pass_obj
def sign(
    ctx: GlobalContext,
    repo_url: str,
    repo_path: str,
    signing_key: str,
    output_path: str,
    radas_config: Path,
    requester_id: str,
    zip_root_path: str,
    product_key: str,
    ignore_patterns: list[str],
) -> None:
    """Sign Maven artifacts on RADAS."""
    try:
        # 0 - Setup logging
        log_level = logging.DEBUG if ctx.verbose else logging.INFO
        setup_logging("sign", "slan-cuan", log_level, use_logfile=False)

        # 1 - Sign the repository in RADAS
        click.echo("Signing the repository in RADAS...")
        sign_in_radas_workflow(
            repo_url=repo_url,
            requester=requester_id,
            sign_key=signing_key,
            result_path=output_path,
            ignore_patterns=ignore_patterns,
            radas_config=radas_config,
        )
        # 2 - Find the signed JSON files in the output path
        click.echo("Finding the signed JSON files in the output path...")
        signed_json_files = list(Path(output_path).rglob("*.json"))
        if not signed_json_files:
            raise click.ClickException(
                "No signed JSON file found in the output path"
            )
        signed_json_file = signed_json_files[0]

        # 3 - Sign the individual artifacts in RADAS
        click.echo("Signing the individual artifacts in RADAS...")
        with tempfile.TemporaryDirectory(prefix="slan-cuan-sign-") as tmp_dir:
            sign_individual_artifacts_workflow(
                repos=[repo_path],
                product_key=product_key,
                root_path=zip_root_path,
                sign_result=signed_json_file,
                destination_dir=output_path,
                tmp_dir=tmp_dir,
                ignore_patterns=ignore_patterns,
            )
    except Exception as e:
        raise click.ClickException(f"Error signing artifacts: {e}") from e
    click.echo("Sign command completed successfully.")
