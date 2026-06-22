"""Publish subcommand for uploading Maven artifacts to Pulp."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import click

from slan_cuan.context import GlobalContext
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    PUBLISH_RESULT_FILENAME,
    BuildOutput,
    ExtractResult,
    PublishResult,
)
from slan_cuan.pulp import PulpConfig, PulpError, PulpMavenClient


@click.command()
@click.option(
    "--pulp-url",
    required=True,
    type=str,
    help=("Pulp instance base URL (e.g. https://pulp.example.com)."),
)
@click.option(
    "--pulp-repository",
    required=True,
    type=str,
    help=("Pulp Maven distribution name for artifact upload."),
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
@click.pass_obj
def publish(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
    artifact_dir: Path,
    insecure: bool,
) -> None:
    """Publish Maven artifacts to Pulp."""
    try:
        result_path = artifact_dir / EXTRACT_RESULT_FILENAME
        if not result_path.exists():
            raise click.ClickException(f"Extract result not found: {result_path}")

        extract_result = ExtractResult.from_file(result_path)
        if ctx.verbose:
            click.echo(f"Loaded extract result: {extract_result.deliverable_dir}")

        build = BuildOutput.from_extract_result(extract_result, artifact_dir)
        if ctx.verbose:
            click.echo(
                f"Discovered {len(build.artifacts)} "
                f"artifact(s) across "
                f"{len(build.coordinates)} "
                f"coordinate(s)"
            )

        if ctx.dry_run:
            click.echo(f"Distribution: {pulp_repository}")
            click.echo(f"Pulp URL: {pulp_url}")
            click.echo(f"Artifacts: {len(build.artifacts)}")
            click.echo(f"Coordinates: {len(build.coordinates)}")
            for artifact in build.artifacts:
                click.echo(f"  {artifact.relative_path}")
            click.echo(
                f"\ndry-run: would upload "
                f"{len(build.artifacts)} artifact(s) "
                f"to {pulp_url}"
            )
            return

        config = PulpConfig(
            base_url=pulp_url,
            verify_ssl=not insecure,
            ca_cert=ctx.ca_cert,
        )

        uploaded = 0
        skipped = 0

        with PulpMavenClient(config, pulp_repository) as client:
            for artifact in build.artifacts:
                if not artifact.file_path.exists():
                    click.echo(
                        f"Warning: skipping missing file: "
                        f"{artifact.relative_path}"
                    )
                    skipped += 1
                    continue

                if ctx.verbose:
                    click.echo(f"Uploading: {artifact.relative_path}")

                upload = client.upload_artifact(
                    artifact.file_path,
                    artifact.relative_path,
                )

                if ctx.verbose:
                    click.echo(f"  -> {upload.status_code} {upload.pulp_href}")

                uploaded += 1

        publish_result = PublishResult(
            pulp_url=pulp_url,
            distribution=pulp_repository,
            artifacts_uploaded=uploaded,
            artifacts_skipped=skipped,
            coordinates=tuple(build.coordinates),
            published_at=datetime.now(timezone.utc).isoformat(),
        )
        publish_result_path = artifact_dir / PUBLISH_RESULT_FILENAME
        publish_result.save(publish_result_path)

        click.echo(
            f"Published: {uploaded} artifact(s) "
            f"uploaded, {skipped} skipped, "
            f"{len(build.coordinates)} coordinate(s)"
        )

    except PulpError as e:
        raise click.ClickException(f"Pulp error: {e.message}") from e
