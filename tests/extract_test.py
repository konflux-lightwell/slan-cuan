"""End-to-end tests for the extract subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.oci import OrasError


@pytest.fixture
def fake_manifest() -> dict:
    """Create a fake OCI manifest response."""
    return {
        "layers": [
            {
                "digest": "sha256:layer1abc",
                "mediaType": (
                    "application/vnd.lightwell.build-output.layer.v1+tar"
                ),
                "size": 1000,
            }
        ],
        "annotations": {
            "org.opencontainers.image.title": "TEST-build-output",
            "deliverable.name": "TEST-build-output",
            "deliverable.type": "lightwell-build-output",
        },
    }


def create_mock_deliverable(output_dir: Path) -> None:
    """Create a mock deliverable directory with test files.

    Simulates what oras pull would extract.
    """
    deliverable_dir = output_dir / "TEST-build-output"
    deliverable_dir.mkdir(parents=True)

    # Create repository structure
    repo_dir = deliverable_dir / "repository" / "org" / "example" / "artifact"
    version_dir = repo_dir / "1.0.0"
    version_dir.mkdir(parents=True)

    # Create JAR files
    (version_dir / "artifact-1.0.0.jar").write_text("jar content")
    (version_dir / "artifact-1.0.0-sources.jar").write_text("sources")
    (version_dir / "artifact-1.0.0-javadoc.jar").write_text("javadoc")
    (version_dir / "artifact-1.0.0.pom").write_text("<project/>")

    # Create checksums
    (version_dir / "artifact-1.0.0.jar.md5").write_text("md5hash")
    (version_dir / "artifact-1.0.0.jar.sha1").write_text("sha1hash")
    (version_dir / "artifact-1.0.0.jar.sha256").write_text("sha256hash")

    # Create SBOM and provenance
    (deliverable_dir / "cyclonedx.json").write_text('{"bomFormat": "CycloneDX"}')
    (deliverable_dir / "provenance.json").write_text('{"_type": "in-toto"}')

    # Create logs
    logs_dir = deliverable_dir / "logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "build.log").write_text("build log content")
    (logs_dir / "alignment.log").write_text("alignment log content")


@patch("slan_cuan.extract.manifest_fetch")
@patch("slan_cuan.extract.pull")
def test_extract_successful_extraction(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Successful extraction creates all expected files."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        """Create deliverable directory when pull is called."""
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify extract-result.json was created
    result_file = output_dir / "extract-result.json"
    assert result_file.exists()

    # Verify metadata/manifest.json was created
    manifest_file = output_dir / "metadata" / "manifest.json"
    assert manifest_file.exists()

    # Verify extract-result.json content
    with result_file.open() as f:
        result_data = json.load(f)

    assert result_data["image"]["registry"] == "quay.io"
    assert result_data["image"]["digest"] == "sha256:abc123"
    assert result_data["deliverable_dir"] == "TEST-build-output"
    assert len(result_data["layers"]) == 1
    assert result_data["layers"][0]["digest"] == "sha256:layer1abc"

    # Verify files list
    assert "TEST-build-output/cyclonedx.json" in result_data["files"]
    assert "TEST-build-output/provenance.json" in result_data["files"]
    assert any(
        "artifact-1.0.0.jar" in f and "sources" not in f
        for f in result_data["files"]
    )

    # Verify summary output
    assert "Extracted:" in result.output
    assert "artifact(s)" in result.output
    assert "POM(s)" in result.output


@patch("slan_cuan.extract.manifest_fetch")
def test_extract_dry_run_mode(
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Dry-run mode displays metadata without creating output directory."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify output directory was NOT created
    assert not output_dir.exists()

    # Verify metadata displayed
    assert "Image:" in result.output
    assert "Manifest digest:" in result.output
    assert "Layers:" in result.output
    assert "Deliverable: TEST-build-output" in result.output
    assert "dry-run:" in result.output
    assert "would extract 1 layer(s)" in result.output

    # Verify annotations displayed
    assert "Annotations:" in result.output
    assert "deliverable.name" in result.output


@patch("slan_cuan.extract.manifest_fetch")
@patch("slan_cuan.extract.pull")
def test_extract_force_overwrite(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Force flag allows overwriting existing output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    (output_dir / "existing.txt").write_text("existing content")

    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--force",
        ],
    )

    assert result.exit_code == 0
    assert (output_dir / "extract-result.json").exists()
    assert not (output_dir / "existing.txt").exists()


@patch("slan_cuan.extract.manifest_fetch")
def test_extract_output_dir_conflict(
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Existing output directory without --force raises error."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_manifest_fetch.return_value = fake_manifest

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert "Use --force to overwrite" in result.output


def test_extract_invalid_image_reference(tmp_path: Path) -> None:
    """Invalid image reference produces error message."""
    output_dir = tmp_path / "output"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "invalid-reference",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Error:" in result.output


@patch("slan_cuan.extract.manifest_fetch")
@patch("slan_cuan.extract.pull")
def test_extract_oras_error_handling(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """OrasError from pull is caught and converted to ClickException."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest
    mock_pull.side_effect = OrasError(
        "Authentication failed",
        stderr="401 Unauthorized",
        returncode=1,
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "OCI error:" in result.output
    assert "Authentication failed" in result.output


@patch("slan_cuan.extract.manifest_fetch")
@patch("slan_cuan.extract.pull")
def test_extract_with_registry_auth_file(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Registry auth file is passed to oras commands."""
    output_dir = tmp_path / "output"
    auth_file = tmp_path / "auth.json"
    auth_file.write_text('{"auths": {}}')

    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
            "--registry-auth-file",
            str(auth_file),
        ],
    )

    assert result.exit_code == 0
    mock_manifest_fetch.assert_called_once()
    mock_pull.assert_called_once()

    # Verify auth_file was passed
    manifest_call_kwargs = mock_manifest_fetch.call_args.kwargs
    pull_call_kwargs = mock_pull.call_args.kwargs
    assert manifest_call_kwargs["auth_file"] == auth_file
    assert pull_call_kwargs["auth_file"] == auth_file


@patch("slan_cuan.extract.manifest_fetch")
@patch("slan_cuan.extract.pull")
def test_extract_verbose_mode(
    mock_pull: Mock,
    mock_manifest_fetch: Mock,
    fake_manifest: dict,
    tmp_path: Path,
) -> None:
    """Verbose mode displays additional information."""
    output_dir = tmp_path / "output"
    mock_manifest_fetch.return_value = fake_manifest

    def side_effect_pull(img, out_dir, **kwargs):
        create_mock_deliverable(out_dir)

    mock_pull.side_effect = side_effect_pull

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Parsed image reference:" in result.output
    assert "Fetching manifest" in result.output
    assert "Creating output directory:" in result.output
    assert "Saving manifest" in result.output
    assert "Pulling artifact" in result.output
    assert "Extracted files" in result.output


@patch("slan_cuan.extract.manifest_fetch")
def test_extract_missing_deliverable_annotation(
    mock_manifest_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Missing deliverable name annotation produces error."""
    output_dir = tmp_path / "output"
    manifest_without_title = {
        "layers": [
            {
                "digest": "sha256:layer1",
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 1000,
            }
        ],
        "annotations": {},
    }
    mock_manifest_fetch.return_value = manifest_without_title

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "extract",
            "--image",
            "quay.io/light-castle/tmp-pnc@sha256:abc123",
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Could not determine deliverable name" in result.output
