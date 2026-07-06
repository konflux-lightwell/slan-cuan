"""Tests for register subcommand (slan_cuan/register.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.trustify import SBOMUploadResult, TrustifyError


def _make_ctx_mock() -> Mock:
    """Create a Mock that supports the context manager protocol."""
    m = Mock()
    m.__enter__ = Mock(return_value=m)
    m.__exit__ = Mock(return_value=False)
    return m


def create_test_artifact_dir_with_sbom(base_dir: Path) -> Path:
    """Create artifact dir with extract-result.json and SBOM in repo tree."""
    deliverable_dir = base_dir / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)

    # Create a CycloneDX SBOM in the Maven repository tree
    (repo_dir / "artifact-1.0.0.cyclonedx.json").write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [],
            }
        )
    )

    # Create extract-result.json (same as publish_test.py)
    extract_result = {
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
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    (base_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )
    return base_dir


def test_register_help_output() -> None:
    """Verify --help shows all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["register", "--help"])

    assert result.exit_code == 0
    assert "--trustify-api-url" in result.output
    assert "--sso-token-url" in result.output
    assert "--sso-client-id" in result.output
    assert "--sso-client-secret" in result.output
    assert "--artifact-dir" in result.output
    assert "--insecure" in result.output
    assert "--retries" in result.output


def test_register_subcommand_is_reachable() -> None:
    """Verify register subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["register", "--help"])

    assert result.exit_code == 0
    assert "Register SBOM with Trustify" in result.output


def test_register_requires_trustify_api_url() -> None:
    """Missing --trustify-api-url fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "register",
                "--sso-token-url",
                "https://sso.example.com/token",
                "--sso-client-id",
                "client-id",
                "--sso-client-secret",
                "client-secret",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert (
        "--trustify-api-url" in result.output or "Missing option" in result.output
    )


def test_register_requires_sso_token_url() -> None:
    """Missing --sso-token-url fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "register",
                "--trustify-api-url",
                "https://trustify.example.com",
                "--sso-client-id",
                "client-id",
                "--sso-client-secret",
                "client-secret",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert "--sso-token-url" in result.output or "Missing option" in result.output


def test_register_requires_artifact_dir() -> None:
    """Missing --artifact-dir fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
        ],
    )

    assert result.exit_code != 0
    assert "--artifact-dir" in result.output or "Missing option" in result.output


def test_register_dry_run(tmp_path: Path) -> None:
    """With --dry-run, shows SBOM info, does NOT create TrustifyClient."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Trustify API URL: https://trustify.example.com" in result.output
    assert "SSO Token URL: https://sso.example.com/token" in result.output
    assert "cyclonedx.json" in result.output
    assert "SBOM size:" in result.output
    assert "dry-run: would upload SBOM" in result.output


def test_register_missing_extract_result(tmp_path: Path) -> None:
    """artifact-dir exists but has no extract-result.json → error."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Extract result not found" in result.output


def test_register_missing_sbom(tmp_path: Path) -> None:
    """Has extract-result.json but deliverable has no cyclonedx.json → error."""
    deliverable_dir = tmp_path / "TEST-build-output"
    deliverable_dir.mkdir(parents=True)

    # Create extract-result.json without SBOM
    extract_result = {
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
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code != 0
    assert "SBOM not found" in result.output


@patch("slan_cuan.register.TrustifyClient")
def test_register_successful_upload(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock TrustifyClient, verify upload_sbom called."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:test-123",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify TrustifyClient was created
    mock_client_cls.assert_called_once()

    # Verify upload_sbom was called
    mock_client.upload_sbom.assert_called_once()

    # Verify context manager was used
    mock_client.__exit__.assert_called_once()

    # Verify summary output
    assert "Registered: SBOM uploaded to Trustify" in result.output
    assert "urn:uuid:test-123" in result.output

    # Verify register-result.json was created
    register_result_path = artifact_dir / "register-result.json"
    assert register_result_path.exists()

    with register_result_path.open() as f:
        register_result = json.load(f)

    assert register_result["trustify_api_url"] == "https://trustify.example.com"
    assert register_result["sbom_urn"] == "urn:uuid:test-123"
    assert register_result["sbom_size"] == 123
    assert "registered_at" in register_result


@patch("slan_cuan.register.TrustifyClient")
def test_register_trustify_error_handling(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client raises TrustifyError, verify ClickException output."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.side_effect = TrustifyError(
        message="SBOM upload failed (500)",
        status_code=500,
        response_body="Internal Server Error",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Trustify error:" in result.output
    assert "SBOM upload failed" in result.output


@patch("slan_cuan.register.TrustifyClient")
def test_register_verbose_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --verbose, shows upload details."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:verbose-test",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Loaded extract result:" in result.output
    assert "Acquiring OIDC token" in result.output
    assert "Uploading SBOM:" in result.output
    assert "-> URN:" in result.output
    assert "urn:uuid:verbose-test" in result.output

    # Verify credentials are NOT in output
    assert "client-secret" not in result.output


@patch("slan_cuan.register.TrustifyClient")
def test_register_insecure_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --insecure, verify_ssl=False is passed to TrustifyConfig."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:test-insecure",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
            "--insecure",
        ],
    )

    assert result.exit_code == 0

    # Verify TrustifyConfig was created with verify_ssl=False
    call_args = mock_client_cls.call_args
    config = call_args[0][0]  # First positional argument is config
    assert config.verify_ssl is False


@patch("slan_cuan.register.TrustifyClient")
def test_register_ca_cert_propagates(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Global --ca-cert is forwarded to TrustifyConfig."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)
    ca_cert = tmp_path / "custom-ca.crt"
    ca_cert.write_text("PEM data")

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:test-ca-cert",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--ca-cert",
            str(ca_cert),
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0

    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.ca_cert == ca_cert
    assert config.verify_ssl is True


@patch("slan_cuan.register.TrustifyClient")
def test_register_retries_option(mock_client_cls: Mock, tmp_path: Path) -> None:
    """--retries is passed to TrustifyConfig."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:test-retries",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
            "--retries",
            "5",
        ],
    )

    assert result.exit_code == 0

    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.retries == 5


@patch("slan_cuan.register.TrustifyClient")
def test_register_writes_tekton_results(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """When --tekton-results-dir is set, register writes SBOM_URN file."""
    artifact_dir = create_test_artifact_dir_with_sbom(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_sbom.return_value = SBOMUploadResult(
        file_path=str(artifact_dir / "TEST-build-output" / "cyclonedx.json"),
        file_size=123,
        sbom_urn="urn:uuid:test-tekton-results",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "register",
            "--trustify-api-url",
            "https://trustify.example.com",
            "--sso-token-url",
            "https://sso.example.com/token",
            "--sso-client-id",
            "client-id",
            "--sso-client-secret",
            "client-secret",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0

    # Verify Tekton result file was created
    sbom_urn_file = results_dir / "SBOM_URN"
    assert sbom_urn_file.exists()
    assert sbom_urn_file.read_text() == "urn:uuid:test-tekton-results"
