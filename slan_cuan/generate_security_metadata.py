"""Generate the OSV and VEX attestations for a given build index."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import click
from fath_cuan.workflow import process_osv

from slan_cuan.context import GlobalContext, write_tekton_result
from slan_cuan.models import EXTRACT_RESULT_FILENAME, ExtractResult


@click.command()
@click.option(
    "--index-basedir",
    type=str,
    required=True,
    help="The base directory of the build index JSON file.",
)
@click.option(
    "--index-filename",
    type=str,
    required=True,
    help="The filename of the build index JSON file "
    "relative to the base directory.",
    default="gav-index.json",
)
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to output the attestations to.",
)
@click.option(
    "--workdir",
    type=click.Path(path_type=Path),
    required=True,
    help="The directory to work in, which is the extracted directory.",
)
@click.pass_obj
def generate_security_metadata(
    ctx: GlobalContext,
    index_basedir: str,
    index_filename: str,
    output_dir: Path,
    workdir: Path,
) -> None:
    """Generate the OSV and VEX attestations for a given build index."""
    index_full_path = os.path.join(index_basedir, index_filename)
    file_name = Path(index_filename).stem
    click.echo(f"Processing {index_full_path} to generate OSV and VEX...")
    with open(index_full_path, "r") as f:
        index_data = json.load(f)

    osv_records = process_osv(index_data)
    osv_output_path = output_dir / f"{file_name}.osv.json"
    click.echo(f"Writing OSV document to {osv_output_path}")
    with open(osv_output_path, "w") as f:
        json.dump(osv_records, f, indent=2)

    # TODO: Generate VEX document

    # Save the updated extract result
    result = ExtractResult.from_file(workdir / EXTRACT_RESULT_FILENAME)
    result = dataclasses.replace(result, security_metadata_dir=str(output_dir))
    result.save(workdir / EXTRACT_RESULT_FILENAME)

    write_tekton_result(
        ctx.tekton_results_dir,
        "SECURITY_METADATA_DIR",
        str(output_dir),
    )
    click.echo("Security metadata generation completed successfully.")
