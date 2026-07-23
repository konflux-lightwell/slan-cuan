"""Unit tests for the generate-security-metadata subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.context import GlobalContext
from slan_cuan.generate_security_metadata import generate_security_metadata
from slan_cuan.models import EXTRACT_RESULT_FILENAME


@pytest.fixture
def ctx() -> GlobalContext:
    """Default non-verbose, non-dry-run context."""
    return GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=None,
    )


@pytest.fixture
def fake_osv_records() -> list[dict]:
    """Sample OSV records as returned by process_osv."""
    return [
        {
            "id": "OSV-2024-001",
            "summary": "Buffer overflow in example-lib",
            "affected": [
                {
                    "package": {
                        "ecosystem": "Maven",
                        "name": "org.example:example-lib",
                    },
                    "versions": ["1.0.0"],
                }
            ],
        }
    ]


def _create_index_file(directory: Path, name: str = "gav-index.json") -> Path:
    """Write a minimal build-index JSON file into *directory*."""
    data = {
        "buildId": "12345",
        "artifacts": [
            {
                "groupId": "org.example",
                "artifactId": "lib",
                "version": "1.0.0",
            }
        ],
    }
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def _create_extract_result(workdir: Path) -> None:
    """Write a minimal extract-result.json into *workdir*."""
    data = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": None,
            "digest": "sha256:abc123",
        },
        "manifest_digest": "sha256:manifest123",
        "layers": [],
        "annotations": {},
        "deliverable_dir": "TEST-build-output",
        "files": [],
        "extracted_at": "2026-06-19T12:00:00Z",
    }
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / EXTRACT_RESULT_FILENAME).write_text(json.dumps(data, indent=2))


def _invoke(
    runner, index_basedir, output_dir, ctx, index_filename=None, workdir=None
):
    args = [
        "--index-basedir",
        str(index_basedir),
        "--output-dir",
        str(output_dir),
    ]
    if workdir is not None:
        args += ["--workdir", str(workdir)]
    if index_filename is not None:
        args += ["--index-filename", index_filename]
    return runner.invoke(generate_security_metadata, args, obj=ctx)


@patch("slan_cuan.generate_security_metadata.process_osv")
def test_generate_security_metadata_creates_osv_output(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Successful attestation writes an OSV file from the index."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    assert "Processing" in result.output
    assert "Security metadata generation completed" in result.output

    osv_file = output_dir / "gav-index.osv.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records


@patch("slan_cuan.generate_security_metadata.process_osv")
def test_generate_security_metadata_custom_filename(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A custom --index-filename produces an OSV file named after the stem."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir, name="cve-report.json")

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(
        runner,
        index_dir,
        output_dir,
        ctx,
        index_filename="cve-report.json",
        workdir=workdir,
    )

    assert result.exit_code == 0, result.output

    osv_file = output_dir / "cve-report.osv.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records


@patch("slan_cuan.generate_security_metadata.process_osv")
def test_generate_security_metadata_passes_index_data_to_process_osv(
    mock_process_osv: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """process_osv receives the parsed JSON data from the index file."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    index_data = {"buildId": "99", "artifacts": []}
    (index_dir / "gav-index.json").write_text(json.dumps(index_data))

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_process_osv.return_value = []

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, ctx, workdir=workdir)

    assert result.exit_code == 0, result.output
    mock_process_osv.assert_called_once_with(index_data)


@patch("slan_cuan.generate_security_metadata.process_osv")
def test_generate_security_metadata_writes_tekton_results(
    mock_process_osv: Mock,
    fake_osv_records: list[dict],
    tmp_path: Path,
) -> None:
    """SECURITY_METADATA_DIR Tekton result is written when results dir is set."""
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    _create_index_file(index_dir)

    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = tmp_path / "output"
    output_dir.mkdir()
    results_dir = tmp_path / "results"

    mock_process_osv.return_value = fake_osv_records

    tekton_ctx = GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=results_dir,
    )

    runner = CliRunner()
    result = _invoke(runner, index_dir, output_dir, tekton_ctx, workdir=workdir)

    assert result.exit_code == 0, result.output

    security_metadata_dir_file = results_dir / "SECURITY_METADATA_DIR"
    assert security_metadata_dir_file.exists()
    assert security_metadata_dir_file.read_text() == str(output_dir)


def test_generate_security_metadata_missing_required_options() -> None:
    """Missing --index-basedir or --output-dir produces an error."""
    runner = CliRunner()

    result = runner.invoke(
        generate_security_metadata, ["--output-dir", "/tmp/out"]
    )
    assert result.exit_code != 0

    result = runner.invoke(
        generate_security_metadata, ["--index-basedir", "/tmp/idx"]
    )
    assert result.exit_code != 0


def test_generate_security_metadata_file_not_found(
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """A missing index file produces an error."""
    workdir = tmp_path / "workdir"
    _create_extract_result(workdir)

    output_dir = tmp_path / "output"
    output_dir.mkdir()

    runner = CliRunner()
    result = _invoke(
        runner, tmp_path / "nonexistent", output_dir, ctx, workdir=workdir
    )

    assert result.exit_code != 0
