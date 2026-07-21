"""Extract subcommand for pulling artifacts from PNC container images."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

import click

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.models import (
    EXTRACT_RESULT_FILENAME,
    ExtractResult,
    ImageReference,
    OCIManifest,
)
from slan_cuan.oci import OrasError, manifest_fetch, pull


@click.command()
@click.option(
    "--image",
    required=True,
    type=str,
    help="Container image reference to extract artifacts from.",
)
@click.option(
    "--output-dir",
    required=True,
    type=click.Path(path_type=Path),
    help="Directory to extract artifacts to.",
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to container registry authentication file.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite existing output directory.",
)
@click.pass_obj
def extract(
    ctx: GlobalContext,
    image: str,
    output_dir: Path,
    registry_auth_file: Path | None,
    force: bool,
) -> None:
    """Extract artifacts from a PNC container image."""
    try:
        # Parse image reference
        img_ref = ImageReference.parse(image)
        if ctx.verbose:
            click.echo(f"Parsed image reference: {img_ref}")

        # Validate/create output directory
        if output_dir.exists():
            if not force:
                raise click.ClickException(
                    f"Output directory {output_dir} already exists. "
                    "Use --force to overwrite."
                )
            if ctx.verbose:
                click.echo(f"Removing existing directory: {output_dir}")
            shutil.rmtree(output_dir)

        # Fetch manifest for metadata
        if ctx.verbose:
            click.echo(f"Fetching manifest for {img_ref}...")

        raw_manifest = manifest_fetch(
            img_ref,
            auth_file=registry_auth_file,
            verbose=ctx.verbose,
        )

        # Parse manifest using OCIManifest model
        manifest = OCIManifest.from_dict(raw_manifest)
        deliverable_name = manifest.deliverable_name
        layers = list(manifest.layers)
        annotations = manifest.annotations

        # Extract manifest digest
        # For digest-based refs, use the digest from the ref
        # Otherwise, calculate from manifest JSON (canonical form)
        if img_ref.digest:
            manifest_digest = img_ref.digest
        else:
            # Calculate SHA256 digest of the manifest JSON
            manifest_bytes = json.dumps(
                raw_manifest, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            digest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            manifest_digest = f"sha256:{digest_hash}"

        # Dry-run path: display metadata and exit
        if ctx.dry_run:
            total_size = sum(layer.size for layer in layers)
            click.echo(f"Image: {img_ref}")
            click.echo(f"Manifest digest: {manifest_digest}")
            click.echo(f"Layers: {len(layers)}")
            click.echo(f"Total size: {total_size:,} bytes")
            click.echo(f"Deliverable: {deliverable_name}")
            if annotations:
                click.echo("Annotations:")
                for key, value in annotations.items():
                    click.echo(f"  {key}: {value}")
            click.echo(
                f"\ndry-run: would extract {len(layers)} layer(s) "
                f"({total_size:,} bytes) to {output_dir}"
            )
            return

        # Normal path: extract the artifact
        if ctx.verbose:
            click.echo(f"Creating output directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create metadata directory
        metadata_dir = output_dir / "metadata"
        metadata_dir.mkdir(exist_ok=True)

        # Save manifest
        manifest_path = metadata_dir / "manifest.json"
        if ctx.verbose:
            click.echo(f"Saving manifest to {manifest_path}")
        with manifest_path.open("w") as f:
            json.dump(manifest.to_dict(), f, indent=2)

        # Pull the artifact
        if ctx.verbose:
            click.echo(f"Pulling artifact to {output_dir}...")

        pull(
            img_ref,
            output_dir,
            auth_file=registry_auth_file,
            verbose=ctx.verbose,
        )

        # Discover extracted files
        deliverable_path = output_dir / deliverable_name
        if not deliverable_path.exists():
            raise click.ClickException(
                f"Deliverable directory not found: {deliverable_path}"
            )

        # Walk the directory tree and collect file paths
        files = []
        for item in deliverable_path.rglob("*"):
            if item.is_file():
                # Store relative path from output_dir
                rel_path = item.relative_to(output_dir)
                files.append(str(rel_path))

        # Sort for deterministic output
        files.sort()

        # Build and save ExtractResult
        result = ExtractResult(
            image=img_ref,
            manifest_digest=manifest_digest,
            layers=layers,
            annotations=annotations,
            deliverable_dir=deliverable_name,
            files=files,
            extracted_at=datetime.now(timezone.utc).isoformat(),
        )

        result_path = output_dir / EXTRACT_RESULT_FILENAME
        if ctx.verbose:
            click.echo(f"Writing result manifest to {result_path}")
        result.save(result_path)

        # Write Tekton results
        write_tekton_result(
            ctx.tekton_results_dir, "MANIFEST_DIGEST", manifest_digest
        )
        write_tekton_result(
            ctx.tekton_results_dir, "DELIVERABLE_DIR", deliverable_name
        )

        # Log summary
        jar_count = sum(
            1
            for f in files
            if f.endswith(".jar")
            and "-sources.jar" not in f
            and "-javadoc.jar" not in f
        )
        pom_count = sum(1 for f in files if f.endswith(".pom"))
        has_sbom = any("cyclonedx.json" in f for f in files)
        has_provenance = any("provenance.json" in f for f in files)
        total_size = sum(
            (output_dir / f).stat().st_size
            for f in files
            if (output_dir / f).exists()
        )

        click.echo(
            f"Extracted: {jar_count} artifact(s), {pom_count} POM(s), "
            f"{'SBOM, ' if has_sbom else ''}"
            f"{'provenance, ' if has_provenance else ''}"
            f"{len(files)} total files ({total_size:,} bytes)"
        )

        if ctx.verbose:
            click.echo(f"\nExtracted files ({len(files)}):")
            for file_path in files:
                size = (output_dir / file_path).stat().st_size
                click.echo(f"  {file_path} ({size:,} bytes)")

    except OrasError as e:
        raise click.ClickException(f"OCI error: {e.message}") from e
    except ValueError as e:
        raise click.ClickException(str(e)) from e
