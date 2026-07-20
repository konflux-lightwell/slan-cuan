"""Generate the OSV and VEX attestations for a given build index."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import click
from fath_cuan.workflow import process_osv

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.extract import pull_image_to_file


@click.command()
@click.option(
    "--build-index",
    type=str,
    required=True,
    help="The pullspec of the build index to attest.",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to output the attestations to.",
)
@click.option(
    "--registry-auth-file",
    type=click.Path(exists=True, path_type=Path),
    help="Path to container registry authentication file.",
)
@click.pass_obj
def attest(
    ctx: GlobalContext,
    build_index: str,
    output_dir: Path,
    registry_auth_file: Path | None,
) -> None:
    """Generate the OSV and VEX attestations for a given build."""
    with tempfile.TemporaryDirectory() as temp_dir:
        index_props = pull_image_to_file(
            build_index,
            registry_auth_file,
            Path(temp_dir),
            dry_run=ctx.dry_run,
            verbose=ctx.verbose,
        )
        if index_props is None:
            return

        for file_path in Path(temp_dir).rglob("*.json"):
            file_name = file_path.stem
            click.echo(f"Processing {file_name}...")
            with open(file_path) as f:
                data = json.load(f)

            osv_records = process_osv(data)
            osv_output_path = output_dir / f"{file_name}.osv.json"
            click.echo(f"Writing OSV document to {osv_output_path}")
            with open(osv_output_path, "w") as f:
                json.dump(osv_records, f, indent=2)

            # TODO: Generate VEX document

    write_tekton_result(
        ctx.tekton_results_dir,
        "ATTESTATION_DIR",
        str(output_dir),
    )
    click.echo("Attestation command completed successfully.")
