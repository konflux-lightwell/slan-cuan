"""Tests for publish subcommand (slan_cuan/publish.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.pulp import PulpError, UploadResult


def _make_ctx_mock() -> Mock:
    """Create a Mock that supports the context manager protocol."""
    m = Mock()
    m.__enter__ = Mock(return_value=m)
    m.__exit__ = Mock(return_value=False)
    return m


def create_test_artifact_dir(base_dir: Path) -> Path:
    """Create a directory that mimics the extract stage output."""
    deliverable_dir = base_dir / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    # Create extract-result.json
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


def test_publish_help_output() -> None:
    """Verify --help shows all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-url" in result.output
    assert "--pulp-repository" in result.output
    assert "--artifact-dir" in result.output
    assert "--insecure" in result.output


def test_publish_subcommand_is_reachable() -> None:
    """Verify publish subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "Publish Maven artifacts to Pulp" in result.output


def test_publish_requires_pulp_url() -> None:
    """Missing --pulp-url fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert "--pulp-url" in result.output or "Missing option" in result.output


def test_publish_requires_pulp_repository() -> None:
    """Missing --pulp-repository fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert (
        "--pulp-repository" in result.output or "Missing option" in result.output
    )


def test_publish_requires_artifact_dir() -> None:
    """Missing --artifact-dir fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
        ],
    )

    assert result.exit_code != 0
    assert "--artifact-dir" in result.output or "Missing option" in result.output


def test_publish_dry_run(tmp_path: Path) -> None:
    """With --dry-run, shows artifact list, does NOT create client."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code == 0
    assert "Distribution: test-repo" in result.output
    assert "Pulp URL: https://pulp.example.com" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.jar" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.pom" in result.output
    assert "dry-run: would upload" in result.output


def test_publish_missing_extract_result(tmp_path: Path) -> None:
    """artifact-dir exists but has no extract-result.json → error."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
        ],
    )

    assert result.exit_code != 0
    assert "Extract result not found" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_successful_upload(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Mock PulpMavenClient, verify upload_artifact called."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PulpMavenClient was created
    mock_client_cls.assert_called_once()

    # Verify upload_artifact was called for each artifact (jar + pom)
    assert mock_client.upload_artifact.call_count == 2

    # Verify context manager was used (close via __exit__)
    mock_client.__exit__.assert_called_once()

    # Verify summary output
    assert "Published: 2 artifact(s) uploaded" in result.output

    # Verify publish-result.json was created
    publish_result_path = artifact_dir / "publish-result.json"
    assert publish_result_path.exists()

    with publish_result_path.open() as f:
        publish_result = json.load(f)

    assert publish_result["pulp_url"] == "https://pulp.example.com"
    assert publish_result["distribution"] == "test-repo"
    assert publish_result["artifacts_uploaded"] == 2
    assert publish_result["artifacts_skipped"] == 0


def test_publish_env_var_precedence(tmp_path: Path) -> None:
    """SLAN_CUAN_PUBLISH_PULP_URL sets --pulp-url."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        mock_client.upload_artifact.return_value = UploadResult(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            status_code=200,
            pulp_href="/api/v3/content/maven/artifact/abc/",
        )

        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                str(artifact_dir),
                "--pulp-username",
                "testuser",
                "--pulp-password",
                "testpass",
            ],
            env={"SLAN_CUAN_PUBLISH_PULP_URL": "https://env.pulp.com"},
        )

    assert result.exit_code == 0


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_verbose_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --verbose, shows upload details."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Loaded extract result:" in result.output
    assert "Discovered" in result.output
    assert "Uploading:" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_pulp_error_handling(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client raises PulpError, verify ClickException output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.side_effect = PulpError(
        message="Distribution 'test-repo' not found",
        status_code=404,
        response_body="",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "not found" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_insecure_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --insecure, verify_ssl=False is passed to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--insecure",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PulpConfig was created with verify_ssl=False
    call_args = mock_client_cls.call_args
    config = call_args[0][0]  # First positional argument is config
    assert config.verify_ssl is False


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_ca_cert_propagates(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Global --ca-cert is forwarded to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    ca_cert = tmp_path / "custom-ca.crt"
    ca_cert.write_text("PEM data")

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--ca-cert",
            str(ca_cert),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.ca_cert == ca_cert
    assert config.verify_ssl is True


@patch("slan_cuan.publish.PulpMavenClient")
@patch("slan_cuan.publish.BuildOutput.from_extract_result")
def test_publish_skips_missing_files(
    mock_from_extract: Mock,
    mock_client_cls: Mock,
    tmp_path: Path,
) -> None:
    """Files that don't exist on disk are skipped."""
    from slan_cuan.models import BuildOutput, MavenArtifact

    artifact_dir = create_test_artifact_dir(tmp_path)

    missing = tmp_path / "nonexistent.jar"
    existing_pom = (
        artifact_dir
        / "TEST-build-output"
        / "repository"
        / "org"
        / "example"
        / "artifact"
        / "1.0.0"
        / "artifact-1.0.0.pom"
    )
    mock_from_extract.return_value = BuildOutput(
        build_id="TEST",
        deliverable_dir=artifact_dir / "TEST-build-output",
        artifacts=(
            MavenArtifact(
                relative_path=("org/example/artifact/1.0.0/artifact-1.0.0.jar"),
                file_path=missing,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="jar",
                md5=None,
                sha1=None,
                sha256=None,
            ),
            MavenArtifact(
                relative_path=("org/example/artifact/1.0.0/artifact-1.0.0.pom"),
                file_path=existing_pom,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="pom",
                md5=None,
                sha1=None,
                sha256=None,
            ),
        ),
        sbom_path=None,
        provenance_path=None,
        source_archive_path=None,
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path=("org/example/artifact/1.0.0/artifact-1.0.0.pom"),
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Warning: skipping missing file:" in result.output
    assert "1 artifact(s) uploaded, 1 skipped" in result.output
    assert mock_client.upload_artifact.call_count == 1


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_writes_tekton_results(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """When --tekton-results-dir is set, publish writes result files."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--tekton-results-dir",
            str(results_dir),
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify Tekton result files were created
    uploaded_file = results_dir / "ARTIFACTS_UPLOADED"
    skipped_file = results_dir / "ARTIFACTS_SKIPPED"
    outputs_file = results_dir / "PUBLISHED_ARTIFACT_OUTPUTS"

    assert uploaded_file.exists()
    assert skipped_file.exists()
    assert outputs_file.exists()

    # Verify content
    assert uploaded_file.read_text() == "2"
    assert skipped_file.read_text() == "0"

    # Verify JSON format for artifact outputs
    outputs_data = json.loads(outputs_file.read_text())
    assert outputs_data["uri"] == "https://pulp.example.com/pulp/maven/test-repo/"
    assert "digest" in outputs_data


def test_publish_tbr_without_credentials(tmp_path: Path) -> None:
    """TBR auth without username/password raises UsageError."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-auth-type",
            "tbr",
        ],
    )

    assert result.exit_code != 0
    assert "--pulp-username and --pulp-password" in result.output


def test_publish_cert_without_files(tmp_path: Path) -> None:
    """Certificate auth without cert/key files raises UsageError."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-auth-type",
            "cert",
        ],
    )

    assert result.exit_code != 0
    assert "--pulp-client-cert and --pulp-client-key" in result.output


def test_publish_default_auth_type() -> None:
    """Help output shows default auth type is tbr."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-auth-type" in result.output
    assert "tbr" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_env_var_auth_type(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Auth type via environment variable works."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("cert content")
    key_file = tmp_path / "client.key"
    key_file.write_text("key content")

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-client-cert",
            str(cert_file),
            "--pulp-client-key",
            str(key_file),
        ],
        env={"SLAN_CUAN_PUBLISH_PULP_AUTH_TYPE": "cert"},
    )

    assert result.exit_code == 0
    call_args = mock_client_cls.call_args
    config = call_args[0][0]
    assert config.auth_type == "cert"


def test_publish_help_shows_new_options() -> None:
    """Help output includes all authentication options."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-auth-type" in result.output
    assert "--pulp-username" in result.output
    assert "--pulp-password" in result.output
    assert "--pulp-client-cert" in result.output
    assert "--pulp-client-key" in result.output


def test_publish_dry_run_shows_auth_type(tmp_path: Path) -> None:
    """Dry run output shows auth type."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    cert_file = tmp_path / "client.crt"
    cert_file.write_text("cert content")
    key_file = tmp_path / "client.key"
    key_file.write_text("key content")

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-auth-type",
            "cert",
            "--pulp-client-cert",
            str(cert_file),
            "--pulp-client-key",
            str(key_file),
        ],
    )

    assert result.exit_code == 0
    assert "Auth type: cert" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_with_domain(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --pulp-domain, PulpConfig.domain is set and deploy is used."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=201,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert mock_client.upload_artifact.call_count == 2

    config = mock_client_cls.call_args[0][0]
    assert config.domain == "lightwell"


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_without_domain(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Without --pulp-domain, PulpConfig.domain is None."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=200,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert mock_client.upload_artifact.call_count == 2

    config = mock_client_cls.call_args[0][0]
    assert config.domain is None


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_verbose_with_domain(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --verbose and --pulp-domain, shows upload progress."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
        status_code=201,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "Uploading:" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
@patch("slan_cuan.publish.BuildOutput.from_extract_result")
def test_publish_skips_missing_with_domain(
    mock_from_extract: Mock,
    mock_client_cls: Mock,
    tmp_path: Path,
) -> None:
    """With --pulp-domain, one artifact missing on disk is skipped."""
    from slan_cuan.models import BuildOutput, MavenArtifact

    artifact_dir = create_test_artifact_dir(tmp_path)

    missing = tmp_path / "nonexistent.jar"
    existing_pom = (
        artifact_dir
        / "TEST-build-output"
        / "repository"
        / "org"
        / "example"
        / "artifact"
        / "1.0.0"
        / "artifact-1.0.0.pom"
    )

    mock_from_extract.return_value = BuildOutput(
        build_id="TEST",
        deliverable_dir=artifact_dir / "TEST-build-output",
        artifacts=(
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
                file_path=missing,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="jar",
                md5=None,
                sha1=None,
                sha256=None,
            ),
            MavenArtifact(
                relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
                file_path=existing_pom,
                group_id="org.example",
                artifact_id="artifact",
                version="1.0.0",
                classifier=None,
                extension="pom",
                md5=None,
                sha1=None,
                sha256=None,
            ),
        ),
        sbom_path=None,
        provenance_path=None,
        source_archive_path=None,
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_artifact.return_value = UploadResult(
        relative_path="org/example/artifact/1.0.0/artifact-1.0.0.pom",
        status_code=201,
        pulp_href="/api/v3/content/maven/artifact/abc/",
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0
    assert "skipping missing file" in result.output
    assert mock_client.upload_artifact.call_count == 1
    assert "1 artifact(s) uploaded, 1 skipped" in result.output


def test_publish_dry_run_with_domain(tmp_path: Path) -> None:
    """With --dry-run and --pulp-domain, no crash."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--dry-run",
            "publish",
            "--pulp-url",
            "https://pulp.example.com",
            "--pulp-repository",
            "test-repo",
            "--artifact-dir",
            str(artifact_dir),
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "Distribution: test-repo" in result.output
    assert "Pulp URL: https://pulp.example.com" in result.output


def test_publish_help_shows_pulp_domain() -> None:
    """Verify --pulp-domain appears in help output."""
    runner = CliRunner()
    result = runner.invoke(main, ["publish", "--help"])

    assert result.exit_code == 0
    assert "--pulp-domain" in result.output


def test_publish_env_var_pulp_domain(tmp_path: Path) -> None:
    """Set SLAN_CUAN_PUBLISH_PULP_DOMAIN env var, verify it propagates."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        mock_client.upload_artifact.return_value = UploadResult(
            relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
            status_code=201,
            pulp_href="/api/v3/content/maven/artifact/abc/",
        )

        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                str(artifact_dir),
                "--pulp-username",
                "testuser",
                "--pulp-password",
                "testpass",
            ],
            env={"SLAN_CUAN_PUBLISH_PULP_DOMAIN": "testdomain"},
        )

    assert result.exit_code == 0

    config = mock_client_cls.call_args[0][0]
    assert config.domain == "testdomain"
