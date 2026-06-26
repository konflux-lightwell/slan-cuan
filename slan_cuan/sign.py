"""Sign subcommand for signing Maven artifacts on RADAS."""

from __future__ import annotations

import io
import json
import logging
import tempfile
from pathlib import Path
from typing import IO

import click
from novabucks.utils.logs import set_logging
from novabucks.workflows import (
    sign_in_radas_workflow,
    sign_individual_artifacts_workflow,
)

from slan_cuan.context import GlobalContext


def _split_ignore_patterns(
    ctx: click.Context,
    param: click.Parameter,
    value: tuple[str, ...],
) -> tuple[str, ...]:
    """Split comma-separated patterns from environment variables."""
    if len(value) == 1 and "," in value[0]:
        return tuple(p.strip() for p in value[0].split(",") if p.strip())
    return value


def _build_radas_config_from_env(
    radas_umb_host: str,
    radas_result_queue: str,
    radas_request_channel: str,
    radas_client_ca: str,
    radas_client_key: str,
    radas_client_key_pass_file: str,
    radas_root_ca: str,
    radas_receiver_timeout: int,
) -> IO[str]:
    """Build a RADAS JSON config as a file-like object."""
    config = {
        "umb_host": radas_umb_host,
        "result_queue": radas_result_queue,
        "request_channel": radas_request_channel,
        "client_ca": radas_client_ca,
        "client_key": radas_client_key,
        "client_key_pass_file": radas_client_key_pass_file,
        "root_ca": radas_root_ca,
        "radas_receiver_timeout": radas_receiver_timeout,
    }
    return io.StringIO(json.dumps(config))


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
    "--radas-umb-host",
    envvar="SLAN_CUAN_RADAS_UMB_HOST",
    required=True,
    type=str,
    help="The host of the RADAS UMB service.",
)
@click.option(
    "--radas-result-queue",
    envvar="SLAN_CUAN_RADAS_RESULT_QUEUE",
    required=True,
    type=str,
    help="The result queue name for RADAS.",
)
@click.option(
    "--radas-request-channel",
    envvar="SLAN_CUAN_RADAS_REQUEST_CHANNEL",
    required=True,
    type=str,
    help="The request channel name for RADAS.",
)
@click.option(
    "--radas-client-ca",
    envvar="SLAN_CUAN_RADAS_CLIENT_CA",
    required=True,
    type=str,
    help="The path to the RADAS client CA certificate.",
)
@click.option(
    "--radas-client-key",
    envvar="SLAN_CUAN_RADAS_CLIENT_KEY",
    required=True,
    type=str,
    help="The path to the RADAS client key.",
)
@click.option(
    "--radas-client-key-pass-file",
    envvar="SLAN_CUAN_RADAS_CLIENT_KEY_PASS_FILE",
    required=True,
    type=str,
    help="The path to the file containing the RADAS client key password.",
)
@click.option(
    "--radas-root-ca",
    envvar="SLAN_CUAN_RADAS_ROOT_CA",
    required=True,
    type=str,
    help="The path to the RADAS root CA certificate.",
)
@click.option(
    "--radas-receiver-timeout",
    envvar="SLAN_CUAN_RADAS_RECEIVER_TIMEOUT",
    default=3600,
    type=int,
    help="The timeout for the RADAS receiver.",
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
    callback=_split_ignore_patterns,
    help="Regex patterns to filter out files from signing.",
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to container registry authentication file.",
)
@click.pass_obj
def sign(
    ctx: GlobalContext,
    repo_url: str,
    repo_path: str,
    signing_key: str,
    output_path: str,
    radas_umb_host: str,
    radas_result_queue: str,
    radas_request_channel: str,
    radas_client_ca: str,
    radas_client_key: str,
    radas_client_key_pass_file: str,
    radas_root_ca: str,
    radas_receiver_timeout: int,
    requester_id: str,
    zip_root_path: str,
    product_key: str,
    ignore_patterns: tuple[str, ...],
    registry_auth_file: Path | None,
) -> None:
    """Sign Maven artifacts on RADAS."""
    radas_config = None
    try:
        # 0 - Setup logging
        log_level = logging.DEBUG if ctx.verbose else logging.INFO
        set_logging("sign", "slan-cuan", log_level, use_log_file=False)
        # Also set up logging for novabucks to propagate its logs
        set_logging("sign", "novabucks", log_level, use_log_file=False)

        # 1 - Sign the repository in RADAS
        radas_config = _build_radas_config_from_env(
            radas_umb_host=radas_umb_host,
            radas_result_queue=radas_result_queue,
            radas_request_channel=radas_request_channel,
            radas_client_ca=radas_client_ca,
            radas_client_key=radas_client_key,
            radas_client_key_pass_file=radas_client_key_pass_file,
            radas_root_ca=radas_root_ca,
            radas_receiver_timeout=radas_receiver_timeout,
        )
        click.echo("Signing the repository in RADAS...")
        sign_in_radas_workflow(
            repo_url=repo_url,
            requester=requester_id,
            sign_key=signing_key,
            result_path=output_path,
            ignore_patterns=list(ignore_patterns),
            # upstream annotates as RadasConfig but calls json.load() on it
            radas_config=radas_config,  # type: ignore[arg-type]
            registry_auth_config_path=registry_auth_file,
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
                sign_result_file=str(signed_json_file),
                destination_dir=output_path,
                temp_dir=tmp_dir,
                ignore_patterns=list(ignore_patterns),
            )
    except Exception as e:
        raise click.ClickException(f"Error signing artifacts: {e}") from e
    click.echo("Sign command completed successfully.")
