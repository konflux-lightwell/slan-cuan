"""Publish subcommand for uploading Maven artifacts to Pulp."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import click

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    PUBLISH_RESULT_FILENAME,
    BuildOutput,
    ExtractResult,
    PublishResult,
)
from slan_cuan.pulp import PulpConfig, PulpError, PulpMavenClient

_DIAG_MAX_ENTRIES = 50


def _list_entries(path: Path, recursive: bool = False) -> None:
    """List directory contents for diagnostics, capped."""
    try:
        if recursive:
            entries = sorted(e for e in path.rglob("*") if e.is_file())
            for entry in entries[:_DIAG_MAX_ENTRIES]:
                click.echo(f"    {entry.relative_to(path)}")
        else:
            entries = sorted(path.iterdir())
            for entry in entries[:_DIAG_MAX_ENTRIES]:
                kind = "dir" if entry.is_dir() else "file"
                click.echo(f"    {entry.name} ({kind})")
        if len(entries) > _DIAG_MAX_ENTRIES:
            click.echo(f"    ... and {len(entries) - _DIAG_MAX_ENTRIES} more")
    except (PermissionError, OSError) as e:
        click.echo(f"    (error reading directory: {e})")


def _diagnose_empty_build(artifact_dir: Path, deliverable_dir: str) -> None:
    """Print diagnostics when no artifacts are discovered."""
    deliverable_path = artifact_dir / deliverable_dir
    repo_dir = deliverable_path / "repository"

    if not deliverable_path.exists():
        click.echo(
            f"  WARNING: deliverable path does not exist: {deliverable_path}"
        )
        click.echo(f"  Contents of {artifact_dir}:")
        _list_entries(artifact_dir)
        return

    if deliverable_path.is_file():
        click.echo(
            f"  WARNING: deliverable path is a file, not a directory: "
            f"{deliverable_path}"
        )
        return

    if not repo_dir.exists():
        click.echo(
            f"  WARNING: repository/ subdirectory not found in: "
            f"{deliverable_path}"
        )
        click.echo(f"  Contents of {deliverable_path}:")
        _list_entries(deliverable_path)
        return

    click.echo("  WARNING: repository/ exists but contains no Maven artifacts")
    click.echo(f"  Contents of {repo_dir}:")
    _list_entries(repo_dir, recursive=True)


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
@click.option(
    "--pulp-auth-type",
    type=click.Choice(["tbr", "cert"], case_sensitive=False),
    default="tbr",
    help="Pulp authentication method.",
)
@click.option(
    "--pulp-username",
    type=str,
    default=None,
    help="Username for TBR basic auth.",
)
@click.option(
    "--pulp-password",
    type=str,
    default=None,
    help="Password for TBR basic auth.",
)
@click.option(
    "--pulp-client-cert",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client certificate path for entitlement cert auth.",
)
@click.option(
    "--pulp-client-key",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Client key path for entitlement cert auth.",
)
@click.option(
    "--pulp-domain",
    envvar="SLAN_CUAN_PUBLISH_PULP_DOMAIN",
    required=True,
    type=str,
    help="Pulp domain for hosted content API (e.g. 'lightwell').",
)
@click.pass_obj
def publish(
    ctx: GlobalContext,
    pulp_url: str,
    pulp_repository: str,
    artifact_dir: Path,
    insecure: bool,
    pulp_auth_type: str,
    pulp_username: str | None,
    pulp_password: str | None,
    pulp_client_cert: Path | None,
    pulp_client_key: Path | None,
    pulp_domain: str,
) -> None:
    """Publish Maven artifacts to Pulp."""
    try:
        result_path = artifact_dir / EXTRACT_RESULT_FILENAME
        if not result_path.exists():
            raise click.ClickException(f"Extract result not found: {result_path}")

        extract_result = ExtractResult.from_file(result_path)
        if ctx.verbose:
            click.echo(f"Extract result file: {result_path}")
            click.echo(f"Artifact directory: {artifact_dir.resolve()}")
            click.echo(f"Deliverable directory: {extract_result.deliverable_dir}")

        build = BuildOutput.from_extract_result(extract_result, artifact_dir)
        if ctx.verbose:
            click.echo(
                f"Discovered {len(build.artifacts)} "
                f"artifact(s) across "
                f"{len(build.coordinates)} "
                f"coordinate(s)"
            )
            click.echo(f"Repository root: {build.deliverable_dir}")
            if not build.artifacts:
                _diagnose_empty_build(
                    artifact_dir, extract_result.deliverable_dir
                )
            for artifact in build.artifacts:
                size = (
                    artifact.file_path.stat().st_size
                    if artifact.file_path.exists()
                    else -1
                )
                click.echo(f"  {artifact.relative_path} ({size} bytes)")
            coords = [
                f"{c.group_id}:{c.artifact_id}:{c.version}"
                for c in build.coordinates
            ]
            click.echo(f"Coordinates: {', '.join(coords)}")

        if ctx.dry_run:
            click.echo(f"Distribution: {pulp_repository}")
            click.echo(f"Pulp URL: {pulp_url}")
            click.echo(f"Auth type: {pulp_auth_type}")
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

        ca_cert = ctx.ca_cert if ctx.ca_cert and ctx.ca_cert.exists() else None
        if pulp_client_cert is not None and not pulp_client_cert.exists():
            pulp_client_cert = None
        if pulp_client_key is not None and not pulp_client_key.exists():
            pulp_client_key = None

        if pulp_auth_type == "tbr" and (not pulp_username or not pulp_password):
            raise click.UsageError(
                "--pulp-username and --pulp-password are required "
                "when --pulp-auth-type is 'tbr'."
            )
        if pulp_auth_type == "cert" and (
            pulp_client_cert is None or pulp_client_key is None
        ):
            raise click.UsageError(
                "--pulp-client-cert and --pulp-client-key are required "
                "when --pulp-auth-type is 'cert'."
            )

        config = PulpConfig(
            base_url=pulp_url,
            verify_ssl=not insecure,
            ca_cert=ca_cert,
            domain=pulp_domain,
            auth_type=pulp_auth_type,
            username=pulp_username,
            password=pulp_password,
            client_cert=pulp_client_cert,
            client_key=pulp_client_key,
        )

        if ctx.verbose:
            click.echo(f"Pulp URL: {pulp_url}")
            click.echo(f"Distribution: {pulp_repository}")
            click.echo(f"Auth type: {pulp_auth_type}")
            click.echo(f"TLS verification: {not insecure}")
            if ca_cert:
                click.echo(f"CA certificate: {ca_cert}")
            if pulp_domain:
                click.echo(f"Pulp domain: {pulp_domain}")
            if pulp_client_cert:
                click.echo(f"Client certificate: {pulp_client_cert}")
            if pulp_client_key:
                click.echo(f"Client key: {pulp_client_key}")

        uploaded = 0
        skipped = 0
        repository_version = None
        content_unit_hrefs: list[str] = []

        pulp_labels: dict[str, str] = {
            "build_id": build.build_id,
            "source_image_digest": extract_result.image.digest or "",
        }
        if ctx.verbose:
            click.echo(f"Pulp labels: {json.dumps(pulp_labels)}")

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

                upload = (
                    client.upload_metadata
                    if artifact.is_metadata
                    else client.upload_content
                )
                content_unit = upload(
                    file_path=artifact.file_path,
                    relative_path=artifact.relative_path,
                    group_id=artifact.group_id,
                    artifact_id=artifact.artifact_id,
                    version=artifact.version,
                    filename=artifact.file_path.name,
                    labels=pulp_labels,
                )

                if ctx.verbose:
                    click.echo(f"  -> {content_unit.pulp_href}")

                content_unit_hrefs.append(content_unit.pulp_href)
                uploaded += 1

            if content_unit_hrefs:
                if ctx.verbose:
                    click.echo(f"Resolving repository: {pulp_repository}")
                repo_href = client.resolve_repository(pulp_repository)

                if ctx.verbose:
                    click.echo(
                        f"Adding {len(content_unit_hrefs)} content unit(s) "
                        f"to repository"
                    )
                modify_result = client.modify_repository(
                    repo_href, content_unit_hrefs
                )
                repository_version = modify_result.repository_version

                if ctx.verbose:
                    click.echo(f"  -> repository version: {repository_version}")

        publish_result = PublishResult(
            pulp_url=pulp_url,
            distribution=pulp_repository,
            artifacts_uploaded=uploaded,
            artifacts_skipped=skipped,
            coordinates=tuple(build.coordinates),
            published_at=datetime.now(timezone.utc).isoformat(),
            repository_version=repository_version,
            content_unit_hrefs=tuple(content_unit_hrefs),
            pulp_labels=pulp_labels,
        )
        publish_result_path = artifact_dir / PUBLISH_RESULT_FILENAME
        publish_result.save(publish_result_path)
        if ctx.verbose:
            click.echo(f"Publish result saved: {publish_result_path}")

        # Write Tekton results
        write_tekton_result(
            ctx.tekton_results_dir, "ARTIFACTS_UPLOADED", str(uploaded)
        )
        write_tekton_result(
            ctx.tekton_results_dir, "ARTIFACTS_SKIPPED", str(skipped)
        )
        artifact_outputs = {
            "uri": f"{pulp_url}/pulp/maven/{pulp_repository}/",
            "digest": "",
        }
        write_tekton_result(
            ctx.tekton_results_dir,
            "PUBLISHED_ARTIFACT_OUTPUTS",
            json.dumps(artifact_outputs),
        )
        write_tekton_result(
            ctx.tekton_results_dir,
            "PULP_LABELS",
            json.dumps(pulp_labels),
        )

        click.echo(
            f"Published: {uploaded} artifact(s) "
            f"uploaded, {skipped} skipped, "
            f"{len(build.coordinates)} coordinate(s)"
        )

    except PulpError as e:
        raise click.ClickException(f"Pulp error: {e.message}") from e
