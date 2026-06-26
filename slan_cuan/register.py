"""Register subcommand for uploading SBOMs to Trustify."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import click

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    REGISTER_RESULT_FILENAME,
    BuildOutput,
    ExtractResult,
    RegisterResult,
)
from slan_cuan.trustify import (
    TrustifyClient,
    TrustifyConfig,
    TrustifyError,
)


@click.command()
@click.option(
    "--trustify-api-url",
    required=True,
    type=str,
    help=("Trustify instance API URL (e.g. https://trustify.example.com)."),
)
@click.option(
    "--sso-token-url",
    required=True,
    type=str,
    help=("OIDC token endpoint URL for SSO authentication."),
)
@click.option(
    "--sso-client-id",
    required=True,
    type=str,
    help=("OIDC client ID for Trustify authentication."),
)
@click.option(
    "--sso-client-secret",
    required=True,
    type=str,
    help=("OIDC client secret for Trustify authentication."),
)
@click.option(
    "--artifact-dir",
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help=(
        "Directory containing extracted artifacts (output of the extract stage)."
    ),
)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Disable TLS certificate verification.",
)
@click.option(
    "--retries",
    type=int,
    default=3,
    help="Number of retry attempts for transient errors.",
)
@click.pass_obj
def register(
    ctx: GlobalContext,
    trustify_api_url: str,
    sso_token_url: str,
    sso_client_id: str,
    sso_client_secret: str,
    artifact_dir: Path,
    insecure: bool,
    retries: int,
) -> None:
    """Register SBOM with Trustify for vulnerability cross-referencing."""
    try:
        ca_cert = ctx.ca_cert if ctx.ca_cert and ctx.ca_cert.exists() else None

        result_path = Path(os.path.join(artifact_dir, EXTRACT_RESULT_FILENAME))
        if not result_path.exists():
            raise click.ClickException(f"Extract result not found: {result_path}")

        extract_result = ExtractResult.from_file(result_path)
        if ctx.verbose:
            click.echo(f"Loaded extract result: {extract_result.deliverable_dir}")

        build = BuildOutput.from_extract_result(extract_result, artifact_dir, verbose=ctx.verbose)

        if build.sbom_path is None:
            raise click.ClickException(
                f"SBOM not found in deliverable: {build.deliverable_dir}"
            )

        if not build.sbom_path.exists():
            raise click.ClickException(f"SBOM file not found: {build.sbom_path}")

        sbom_size = build.sbom_path.stat().st_size

        if ctx.dry_run:
            click.echo(f"Trustify API URL: {trustify_api_url}")
            click.echo(f"SSO Token URL: {sso_token_url}")
            click.echo(f"SBOM file: {build.sbom_path}")
            click.echo(f"SBOM size: {sbom_size} bytes")
            click.echo(f"\ndry-run: would upload SBOM to {trustify_api_url}")
            return

        if ctx.verbose:
            click.echo(f"Acquiring OIDC token from {sso_token_url}")

        config = TrustifyConfig(
            api_url=trustify_api_url,
            sso_token_url=sso_token_url,
            sso_client_id=sso_client_id,
            sso_client_secret=sso_client_secret,
            verify_ssl=not insecure,
            ca_cert=ca_cert,
            retries=retries,
        )

        with TrustifyClient(config) as client:
            if ctx.verbose:
                click.echo(f"Uploading SBOM: {build.sbom_path}")

            upload_result = client.upload_sbom(build.sbom_path)

            if ctx.verbose:
                click.echo(f"  -> URN: {upload_result.sbom_urn}")

        register_result = RegisterResult(
            trustify_api_url=trustify_api_url,
            sbom_urn=upload_result.sbom_urn,
            sbom_file=str(build.sbom_path),
            sbom_size=upload_result.file_size,
            registered_at=datetime.now(timezone.utc).isoformat(),
        )
        register_result_path = Path(
            os.path.join(artifact_dir, REGISTER_RESULT_FILENAME)
        )
        register_result.save(register_result_path)

        # Write Tekton results
        write_tekton_result(
            ctx.tekton_results_dir, "SBOM_URN", upload_result.sbom_urn
        )

        click.echo(
            (
                f"Registered: SBOM uploaded to Trustify "
                f"(URN: {upload_result.sbom_urn})"
            )
        )

    except TrustifyError as e:
        raise click.ClickException(f"Trustify error: {e.message}") from e
