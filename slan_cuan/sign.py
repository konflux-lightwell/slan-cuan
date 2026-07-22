"""Sign subcommand for signing Maven artifacts on RADAS."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
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
from slan_cuan.models import EXTRACT_RESULT_FILENAME


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


def _sign_in_radas(
    repo_url: str,
    signing_key: str,
    radas_umb_host: str,
    radas_result_queue: str,
    radas_request_channel: str,
    radas_client_ca: str,
    radas_client_key: str,
    radas_client_key_pass_file: str,
    radas_root_ca: str,
    radas_receiver_timeout: int,
    requester_id: str,
    ignore_patterns: tuple[str, ...],
    registry_auth_file: Path | None,
    tmp_dir_sign_url: str,
    sign_artifact_dir: str,
) -> None:
    # Sign the repository in RADAS workflow
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
    click.echo(f"  - registry_auth_file: {registry_auth_file}")
    if registry_auth_file is not None:
        with open(registry_auth_file, "rb") as f:
            file_hash = hashlib.file_digest(f, "sha256")
        click.echo(f"  - sha256 creds: {file_hash.hexdigest()}")
    click.echo(f"  - repo_url: {repo_url}")
    click.echo(f"  - requester: {requester_id}")
    click.echo(f"  - sign_key: {signing_key}")
    click.echo(f"  - result_path: {sign_artifact_dir}")
    click.echo(f"  - ignore_patterns: {list(ignore_patterns)}")
    click.echo(f"  - radas_config: {radas_config}")

    sign_in_radas_workflow(
        repo_url=repo_url,
        requester=requester_id,
        sign_key=signing_key,
        result_path=tmp_dir_sign_url,
        ignore_patterns=list(ignore_patterns),
        # upstream annotates as RadasConfig but calls json.load() on it
        radas_config=radas_config,  # type: ignore[arg-type]
        registry_auth_config_path=registry_auth_file,
    )


def _sign_directly(
    repo_url: str,
    signing_key: str,
    requester_id: str,
    ignore_patterns: tuple[str, ...],
    registry_auth_file: Path | None,
    direct_sign_pipeline_name: str,
    direct_sign_pipeline_image: str,
    direct_sign_task_git_url: str,
    intention: str,
    sign_artifact_dir: str,
) -> None:
    # Sign the repository directly via internal-request pipeline
    click.echo("Signing the repository directly via internal-request...")
    click.echo(f"  - registry_auth_file: {registry_auth_file}")
    if registry_auth_file is not None:
        with open(registry_auth_file, "rb") as f:
            file_hash = hashlib.file_digest(f, "sha256")
        click.echo(f"  - sha256 creds: {file_hash.hexdigest()}")
    click.echo(f"  - repo_url: {repo_url}")
    click.echo(f"  - requester: {requester_id}")
    click.echo(f"  - sign_key: {signing_key}")
    click.echo(f"  - result_path: {sign_artifact_dir}")
    click.echo(f"  - ignore_patterns: {list(ignore_patterns)}")

    cmd = [
        "internal-request",
        "--pipeline",
        direct_sign_pipeline_name,
        "-l",
        "internal-services.appstudio.openshift.io/rate-limited='true'",
        "-l",
        "internal-services.appstudio.openshift.io/rate-limiting-group='signing-server'",
        "-l",
        f"internal-services.appstudio.openshift.io/intention={intention}",
        "-p",
        f"pipeline_image={direct_sign_pipeline_image}",
        "-p",
        f"taskGitUrl={direct_sign_task_git_url}",
        "-p",
        f"repoURL={repo_url}",
        "-p",
        f"requester={requester_id}",
        "-p",
        f"signKey={signing_key}",
        "-p",
        f"resultPath={sign_artifact_dir}",
        "-p",
        f"ignorePatterns={list(ignore_patterns)}",
        "-p",
        f"registryAuthFile={registry_auth_file}" if registry_auth_file else "",
        "-s",
        "true",  # Will wait for the pipeline to complete
    ]

    click.echo(f"  - cmd: {cmd}")
    cmd_args = {
        "capture_output": True,
        "text": True,
        "check": True,
        "universal_newlines": True,
        "stderr": subprocess.STDOUT,
        "stdout": subprocess.PIPE,
    }

    response = subprocess.run(cmd, **cmd_args)
    if response.returncode != 0:
        raise click.ClickException(
            f"Error signing the repository directly via internal-request: {response.stdout}"  # noqa: E501
        )
    click.echo(f"  - response: {response.stdout}")


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
@click.option(
    "--direct-sign",
    is_flag=True,
    default=False,
    show_default=True,
    help="Directly sign the repository using the internal-request script instead of RADAS.",  # noqa: E501
)
@click.option(
    "--direct-sign-pipeline-name",
    default="direct-lightwell-signing",
    type=str,
    show_default=True,
    help="The name of the pipeline to use for direct signing.",
)
@click.option(
    "--direct-sign-pipeline-image",
    default="quay.io/konflux-ci/signing:latest",
    type=str,
    show_default=True,
    help="The image to use for direct signing.",
)
@click.option(
    "--direct-sign-task-git-url",
    default="gitlab.cee.redhat.com/signing/signing.git",
    type=str,
    show_default=True,
    help="The Git URL to use for direct signing.",
)
@click.option(
    "--intention",
    default="production",
    type=str,
    show_default=True,
    help="The intention to use for direct signing.",
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
    direct_sign: bool,
    direct_sign_pipeline_name: str,
    direct_sign_pipeline_image: str,
    direct_sign_task_git_url: str,
    intention: str,
) -> None:
    """Sign Maven artifacts on RADAS or directly via internal-request."""
    try:
        # 0 - Setup logging
        log_level = logging.DEBUG if ctx.verbose else logging.INFO
        set_logging("sign", "slan-cuan", log_level, use_log_file=False)
        # Also set up logging for novabucks to propagate its logs
        set_logging("sign", "novabucks", log_level, use_log_file=False)

        with tempfile.TemporaryDirectory(
            prefix="slan-cuan-sign-url-"
        ) as tmp_dir_sign_url:
            # 1 - Sign the repository
            repo_url = repo_url.removeprefix("https://").removeprefix("http://")
            sign_artifact_dir = os.path.join(output_path, "signed", "repository")

            if direct_sign:
                click.echo(
                    "Signing the repository directly via internal-request..."
                )
                _sign_directly(
                    repo_url=repo_url,
                    signing_key=signing_key,
                    requester_id=requester_id,
                    ignore_patterns=ignore_patterns,
                    registry_auth_file=registry_auth_file,
                    direct_sign_pipeline_name=direct_sign_pipeline_name,
                    direct_sign_pipeline_image=direct_sign_pipeline_image,
                    direct_sign_task_git_url=direct_sign_task_git_url,
                    intention=intention,
                    sign_artifact_dir=sign_artifact_dir,
                )
            else:
                click.echo("Signing the repository in RADAS...")
                _sign_in_radas(
                    repo_url=repo_url,
                    signing_key=signing_key,
                    radas_umb_host=radas_umb_host,
                    radas_result_queue=radas_result_queue,
                    radas_request_channel=radas_request_channel,
                    radas_client_ca=radas_client_ca,
                    radas_client_key=radas_client_key,
                    radas_client_key_pass_file=radas_client_key_pass_file,
                    radas_root_ca=radas_root_ca,
                    radas_receiver_timeout=radas_receiver_timeout,
                    requester_id=requester_id,
                    ignore_patterns=ignore_patterns,
                    registry_auth_file=registry_auth_file,
                    tmp_dir_sign_url=tmp_dir_sign_url,
                    sign_artifact_dir=sign_artifact_dir,
                )

            # 2 - Find the signed JSON files in the output path
            click.echo("Finding the signed JSON files in the output path...")
            signed_json_files = list(Path(tmp_dir_sign_url).rglob("*.json"))
            if not signed_json_files:
                raise click.ClickException(
                    "No signed JSON file found in the output path"
                )
            signed_json_file = signed_json_files[0]

            # 3 - Sign the individual artifacts in RADAS
            click.echo("Signing the individual artifacts in RADAS...")
            click.echo(f"  - repos: [{repo_path}]")
            click.echo(f"  - prod key: [{product_key}]")
            click.echo(f"  - root path: [{zip_root_path}]")
            click.echo(f"  - signed file: [{signed_json_file}]")
            click.echo(f"  - output dir: [{sign_artifact_dir}]")
            with tempfile.TemporaryDirectory(prefix="slan-cuan-sign-") as tmp_dir:
                click.echo(f"  - tmp dir: [{tmp_dir}]")
                sign_individual_artifacts_workflow(
                    repos=[repo_path],
                    product_key=product_key,
                    root_path=zip_root_path,
                    sign_result_file=str(signed_json_file),
                    destination_dir=sign_artifact_dir,
                    temp_dir=tmp_dir,
                    ignore_patterns=list(ignore_patterns),
                )

        # 4 - Copy the whole content of the original directory to the output path
        original_dir = os.path.dirname(repo_path)
        shutil.copytree(original_dir, output_path, dirs_exist_ok=True)

        # 5. Adjust the EXTRACT_RESULT_FILENAME to point to the signed directory
        extract_result_path = os.path.join(output_path, EXTRACT_RESULT_FILENAME)
        with open(extract_result_path, "r") as f:
            extract_result = json.load(f)
        extract_result["deliverable_dir"] = "signed"
        with open(extract_result_path, "w") as f:
            json.dump(extract_result, f)
    except Exception as e:
        raise click.ClickException(f"Error signing artifacts: {e}") from e
    click.echo("Sign command completed successfully.")
