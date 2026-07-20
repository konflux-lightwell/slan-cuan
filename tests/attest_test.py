"""Unit tests for the attest subcommand."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.attest import attest
from slan_cuan.context import GlobalContext

IMAGE = "quay.io/test/idx@sha256:aaa"


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
def fake_image_props() -> Mock:
    """Minimal ImageProperties mock — attest only checks for None."""
    return Mock()


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


def _create_build_index_json(directory: Path, name: str = "build") -> Path:
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
    path = directory / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def _invoke(runner, output_dir, ctx, **extra):
    return runner.invoke(
        attest,
        [
            "--build-index",
            IMAGE,
            "--output-dir",
            str(output_dir),
        ],
        obj=ctx,
        **extra,
    )


@patch("slan_cuan.attest.process_osv")
@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_generates_osv_output(
    mock_pull: Mock,
    mock_process_osv: Mock,
    fake_image_props: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Successful attestation writes one OSV file per input JSON."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    def pull_side_effect(image, auth, out_dir, **kwargs):
        _create_build_index_json(out_dir, "cve-report")
        return fake_image_props

    mock_pull.side_effect = pull_side_effect
    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, output_dir, ctx)

    assert result.exit_code == 0, result.output
    assert "Processing cve-report..." in result.output
    assert "Attestation command completed" in result.output

    osv_file = output_dir / "cve-report.osv.json"
    assert osv_file.exists()

    written = json.loads(osv_file.read_text())
    assert written == fake_osv_records


@patch("slan_cuan.attest.process_osv")
@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_handles_multiple_json_files(
    mock_pull: Mock,
    mock_process_osv: Mock,
    fake_image_props: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Each JSON file in the build index produces its own OSV output."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    def pull_side_effect(image, auth, out_dir, **kwargs):
        _create_build_index_json(out_dir, "alpha")
        _create_build_index_json(out_dir, "beta")
        return fake_image_props

    mock_pull.side_effect = pull_side_effect
    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = _invoke(runner, output_dir, ctx)

    assert result.exit_code == 0, result.output
    assert (output_dir / "alpha.osv.json").exists()
    assert (output_dir / "beta.osv.json").exists()


@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_dry_run_exits_early(
    mock_pull: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """When pull returns None (dry-run), attest exits without processing."""
    mock_pull.return_value = None
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    dry_ctx = GlobalContext(
        verbose=False,
        dry_run=True,
        ca_cert=None,
        tekton_results_dir=None,
    )

    runner = CliRunner()
    result = _invoke(runner, output_dir, dry_ctx)

    assert result.exit_code == 0
    assert "Attestation command completed" not in result.output
    osv_files = list(output_dir.glob("*.osv.json"))
    assert len(osv_files) == 0


@patch("slan_cuan.attest.process_osv")
@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_no_json_files(
    mock_pull: Mock,
    mock_process_osv: Mock,
    fake_image_props: Mock,
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """No JSON files in the build index means nothing is processed."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    mock_pull.return_value = fake_image_props

    runner = CliRunner()
    result = _invoke(runner, output_dir, ctx)

    assert result.exit_code == 0
    assert "Attestation command completed" in result.output
    mock_process_osv.assert_not_called()


@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_passes_correct_args_to_pull(
    mock_pull: Mock,
    fake_image_props: Mock,
    tmp_path: Path,
) -> None:
    """pull_image_to_file receives the right arguments."""
    mock_pull.return_value = fake_image_props
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    test_ctx = GlobalContext(
        verbose=True,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=None,
    )

    runner = CliRunner()
    _invoke(runner, output_dir, test_ctx)

    mock_pull.assert_called_once()
    call_args = mock_pull.call_args
    assert call_args[0][0] == IMAGE
    assert call_args[0][1] is None
    assert isinstance(call_args[0][2], Path)
    assert call_args[1]["dry_run"] is False
    assert call_args[1]["verbose"] is True


@patch("slan_cuan.attest.process_osv")
@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_with_registry_auth_file(
    mock_pull: Mock,
    mock_process_osv: Mock,
    fake_image_props: Mock,
    fake_osv_records: list[dict],
    ctx: GlobalContext,
    tmp_path: Path,
) -> None:
    """Registry auth file is forwarded to pull_image_to_file."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    auth_file = tmp_path / "auth.json"
    auth_file.write_text('{"auths": {}}')

    def pull_side_effect(image, auth, out_dir, **kwargs):
        _create_build_index_json(out_dir, "report")
        return fake_image_props

    mock_pull.side_effect = pull_side_effect
    mock_process_osv.return_value = fake_osv_records

    runner = CliRunner()
    result = runner.invoke(
        attest,
        [
            "--build-index",
            IMAGE,
            "--output-dir",
            str(output_dir),
            "--registry-auth-file",
            str(auth_file),
        ],
        obj=ctx,
    )

    assert result.exit_code == 0, result.output
    mock_pull.assert_called_once()
    assert mock_pull.call_args[0][1] == auth_file


@patch("slan_cuan.attest.process_osv")
@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_writes_tekton_results(
    mock_pull: Mock,
    mock_process_osv: Mock,
    fake_image_props: Mock,
    fake_osv_records: list[dict],
    tmp_path: Path,
) -> None:
    """ATTESTATION_DIR Tekton result is written when results dir is set."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    results_dir = tmp_path / "results"

    def pull_side_effect(image, auth, out_dir, **kwargs):
        _create_build_index_json(out_dir, "report")
        return fake_image_props

    mock_pull.side_effect = pull_side_effect
    mock_process_osv.return_value = fake_osv_records

    tekton_ctx = GlobalContext(
        verbose=False,
        dry_run=False,
        ca_cert=None,
        tekton_results_dir=results_dir,
    )

    runner = CliRunner()
    result = _invoke(runner, output_dir, tekton_ctx)

    assert result.exit_code == 0, result.output

    attestation_dir_file = results_dir / "ATTESTATION_DIR"
    assert attestation_dir_file.exists()
    assert attestation_dir_file.read_text() == str(output_dir)


@patch("slan_cuan.attest.pull_image_to_file")
def test_attest_dry_run_skips_tekton_results(
    mock_pull: Mock,
    tmp_path: Path,
) -> None:
    """In dry-run mode, no Tekton result files are written."""
    mock_pull.return_value = None
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    results_dir = tmp_path / "results"

    dry_ctx = GlobalContext(
        verbose=False,
        dry_run=True,
        ca_cert=None,
        tekton_results_dir=results_dir,
    )

    runner = CliRunner()
    result = _invoke(runner, output_dir, dry_ctx)

    assert result.exit_code == 0
    assert not results_dir.exists()


def test_attest_missing_required_options() -> None:
    """Missing --build-index or --output-dir produces an error."""
    runner = CliRunner()

    result = runner.invoke(attest, ["--output-dir", "/tmp/out"])
    assert result.exit_code != 0

    result = runner.invoke(attest, ["--build-index", IMAGE])
    assert result.exit_code != 0
