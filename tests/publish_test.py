"""Tests for publish subcommand (slan_cuan/publish.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.pulp import ContentUnit, ModifyResult, PulpError

_CONTENT_UNIT = ContentUnit(
    pulp_href="/api/v3/content/maven/artifact/abc/",
    relative_path="org/example/artifact/1.0.0/artifact-1.0.0.jar",
    group_id="org.example",
    artifact_id="artifact",
    version="1.0.0",
    filename="artifact-1.0.0.jar",
)

_REPO_HREF = "/api/v3/repositories/maven/maven/abc/"

_MODIFY_RESULT = ModifyResult(
    task_href="/api/v3/tasks/abc/",
    state="completed",
    repository_version="/api/v3/repositories/maven/maven/abc/versions/1/",
    content_units_added=2,
)


def _make_ctx_mock() -> Mock:
    """Create a Mock that supports the context manager protocol."""
    m = Mock()
    m.__enter__ = Mock(return_value=m)
    m.__exit__ = Mock(return_value=False)
    return m


def _setup_client_mock(mock_client: Mock) -> None:
    """Configure mock client with upload_content, resolve, and modify."""
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.return_value = _MODIFY_RESULT


def create_test_artifact_dir(
    base_dir: Path, *, include_metadata: bool = False
) -> Path:
    """Create a directory that mimics the extract stage output."""
    deliverable_dir = base_dir / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    if include_metadata:
        metadata_dir = (
            deliverable_dir / "repository" / "org" / "example" / "artifact"
        )
        (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")

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
                "--pulp-domain",
                "lightwell",
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
                "--pulp-domain",
                "lightwell",
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
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code != 0
    assert "--artifact-dir" in result.output or "Missing option" in result.output


def test_publish_requires_pulp_domain() -> None:
    """Missing --pulp-domain fails."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main,
            [
                "publish",
                "--pulp-url",
                "https://pulp.example.com",
                "--pulp-repository",
                "test-repo",
                "--artifact-dir",
                ".",
            ],
        )

    assert result.exit_code != 0
    assert "--pulp-domain" in result.output or "Missing option" in result.output


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
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code == 0
    assert "Distribution: test-repo" in result.output
    assert "Pulp URL: https://pulp.example.com" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.jar" in result.output
    assert "org/example/artifact/1.0.0/artifact-1.0.0.pom" in result.output
    assert "dry-run: would upload" in result.output


def test_publish_missing_extract_result(tmp_path: Path) -> None:
    """artifact-dir exists but has no extract-result.json -> error."""
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
            "--pulp-domain",
            "lightwell",
        ],
    )

    assert result.exit_code != 0
    assert "Extract result not found" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_successful_upload(mock_client_cls: Mock, tmp_path: Path) -> None:
    """Mock client, verify upload_content and modify_repository."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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

    # Verify PulpMavenClient was created
    mock_client_cls.assert_called_once()

    # Verify upload_content was called for each artifact (jar + pom)
    assert mock_client.upload_content.call_count == 2

    # Verify resolve_repository and modify_repository were called
    mock_client.resolve_repository.assert_called_once_with("test-repo")
    mock_client.modify_repository.assert_called_once()

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
    assert publish_result["repository_version"] == (
        "/api/v3/repositories/maven/maven/abc/versions/1/"
    )
    assert len(publish_result["content_unit_hrefs"]) == 2


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_routes_metadata_to_upload_metadata(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """maven-metadata.xml routed to upload_metadata, others to upload_content."""
    artifact_dir = create_test_artifact_dir(tmp_path, include_metadata=True)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)
    mock_client.upload_metadata = Mock(return_value=_CONTENT_UNIT)

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

    # jar + pom go to upload_content
    assert mock_client.upload_content.call_count == 2

    # maven-metadata.xml goes to upload_metadata
    assert mock_client.upload_metadata.call_count == 1
    metadata_call = mock_client.upload_metadata.call_args
    assert metadata_call.kwargs["filename"] == "maven-metadata.xml"

    assert "Published: 3 artifact(s) uploaded" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_routes_metadata_checksums(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Route metadata checksums to upload_metadata, artifact to upload_content."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)

    # Create primary artifact
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")
    (repo_dir / "artifact-1.0.0.pom").write_text("<project/>")

    # Create artifact checksum
    (repo_dir / "artifact-1.0.0.jar.md5").write_text("jarmd5")

    # Create maven-metadata.xml and its checksums at artifact level
    metadata_dir = deliverable_dir / "repository" / "org" / "example" / "artifact"
    (metadata_dir / "maven-metadata.xml").write_text("<metadata/>")
    (metadata_dir / "maven-metadata.xml.md5").write_text("metamd5")
    (metadata_dir / "maven-metadata.xml.sha1").write_text("metasha1")

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
        "extracted_at": "2026-06-29T12:00:00Z",
    }
    (tmp_path / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)
    mock_client.upload_metadata = Mock(return_value=_CONTENT_UNIT)

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
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify upload_content: jar + pom + jar.md5 = 3
    assert mock_client.upload_content.call_count == 3

    # Verify upload_metadata: maven-metadata.xml + .md5 + .sha1 = 3
    assert mock_client.upload_metadata.call_count == 3

    # Verify metadata checksum files went to upload_metadata
    metadata_calls = mock_client.upload_metadata.call_args_list
    metadata_filenames = {call.kwargs["filename"] for call in metadata_calls}
    assert metadata_filenames == {
        "maven-metadata.xml",
        "maven-metadata.xml.md5",
        "maven-metadata.xml.sha1",
    }

    assert "Published: 6 artifact(s) uploaded" in result.output


def test_publish_env_var_precedence(tmp_path: Path) -> None:
    """SLAN_CUAN_PUBLISH_PULP_URL sets --pulp-url."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        _setup_client_mock(mock_client)

        result = runner.invoke(
            main,
            [
                "publish",
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
            env={"SLAN_CUAN_PUBLISH_PULP_URL": "https://env.pulp.com"},
        )

    assert result.exit_code == 0


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_verbose_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --verbose, shows upload details."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
    assert "Extract result file:" in result.output
    assert "Artifact directory:" in result.output
    assert "Deliverable directory:" in result.output
    assert "Discovered" in result.output
    assert "Repository root:" in result.output
    assert "Pulp URL:" in result.output
    assert "Distribution:" in result.output
    assert "Uploading:" in result.output
    assert "Resolving repository:" in result.output
    assert "repository version:" in result.output
    assert "Publish result saved:" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_pulp_error_handling(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client raises PulpError, verify ClickException output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.side_effect = PulpError(
        message="Content upload failed",
        status_code=400,
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
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_insecure_mode(mock_client_cls: Mock, tmp_path: Path) -> None:
    """With --insecure, verify_ssl=False is passed to PulpConfig."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
            "--pulp-domain",
            "lightwell",
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
    _setup_client_mock(mock_client)

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
            "--pulp-domain",
            "lightwell",
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
    _setup_client_mock(mock_client)

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
    assert "Warning: skipping missing file:" in result.output
    assert "1 artifact(s) uploaded, 1 skipped" in result.output
    assert mock_client.upload_content.call_count == 1


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_writes_tekton_results(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """When --tekton-results-dir is set, publish writes result files."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
            "--pulp-domain",
            "lightwell",
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
            "--pulp-domain",
            "lightwell",
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
            "--pulp-domain",
            "lightwell",
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
    _setup_client_mock(mock_client)

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
            "--pulp-domain",
            "lightwell",
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
    """With --pulp-domain, PulpConfig.domain is set."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
    assert mock_client.upload_content.call_count == 2

    config = mock_client_cls.call_args[0][0]
    assert config.domain == "lightwell"


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_verbose_with_domain(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --verbose and --pulp-domain, shows upload progress."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
    """One artifact missing on disk is skipped."""
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
    _setup_client_mock(mock_client)

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
    assert mock_client.upload_content.call_count == 1
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


def test_publish_verbose_diagnoses_missing_deliverable(tmp_path: Path) -> None:
    """Verbose mode warns when deliverable_dir does not exist."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
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
        "deliverable_dir": "MISSING-build-output",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
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
    assert "deliverable path does not exist" in result.output
    assert "Contents of" in result.output


def test_publish_verbose_diagnoses_file_deliverable(tmp_path: Path) -> None:
    """Verbose mode warns when deliverable_dir is a file, not a directory."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
    (artifact_dir / "build-output.zip").write_text("not a directory")
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
        "deliverable_dir": "build-output.zip",
        "files": [],
        "extracted_at": "2026-06-22T12:00:00Z",
    }
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
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
    assert "deliverable path is a file, not a directory" in result.output


def test_publish_verbose_diagnoses_missing_repo_dir(tmp_path: Path) -> None:
    """Verbose mode warns when repository/ subdir is missing."""
    artifact_dir = tmp_path / "output"
    artifact_dir.mkdir()
    deliverable = artifact_dir / "TEST-build-output"
    deliverable.mkdir()
    (deliverable / "cyclonedx.json").write_text("{}")
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
    (artifact_dir / "extract-result.json").write_text(
        json.dumps(extract_result, indent=2)
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "--verbose",
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
    assert "repository/ subdirectory not found" in result.output
    assert "cyclonedx.json" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_passes_labels_to_upload(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Mock client, verify upload_content receives labels kwarg."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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

    # Verify upload_content was called with labels
    assert mock_client.upload_content.call_count == 2
    for call in mock_client.upload_content.call_args_list:
        labels = call.kwargs.get("labels")
        assert labels is not None
        assert "build_id" not in labels
        assert labels["source_image"] == "quay.io/test/image@sha256:abc123"


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_labels_with_none_digest(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Extract result with None digest uses tag-only image reference."""
    deliverable_dir = tmp_path / "TEST-build-output"
    repo_dir = (
        deliverable_dir / "repository" / "org" / "example" / "artifact" / "1.0.0"
    )
    repo_dir.mkdir(parents=True)
    (repo_dir / "artifact-1.0.0.jar").write_text("jar content")

    # Create extract-result.json with digest=None
    extract_result = {
        "image": {
            "registry": "quay.io",
            "repository": "test/image",
            "tag": "latest",
            "digest": None,
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

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
            str(tmp_path),
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    for call in mock_client.upload_content.call_args_list:
        labels = call.kwargs.get("labels")
        assert labels is not None
        assert "build_id" not in labels
        assert labels["source_image"] == "quay.io/test/image:latest"


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_labels_in_publish_result(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """After publish, publish-result.json contains pulp_labels."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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

    # Read publish-result.json
    publish_result_path = artifact_dir / "publish-result.json"
    assert publish_result_path.exists()

    with publish_result_path.open() as f:
        publish_result = json.load(f)

    assert "pulp_labels" in publish_result
    assert "build_id" not in publish_result["pulp_labels"]
    assert (
        publish_result["pulp_labels"]["source_image"]
        == "quay.io/test/image@sha256:abc123"
    )


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_shows_labels_in_output(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """Labels appear in regular (non-verbose) output."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
    assert "Pulp labels:" in result.output
    assert "source_image" in result.output
    assert "quay.io/test/image@sha256:abc123" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_writes_pulp_labels_tekton_result(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """With --tekton-results-dir, verify PULP_LABELS file is created."""
    artifact_dir = create_test_artifact_dir(tmp_path)
    results_dir = tmp_path / "results"

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    _setup_client_mock(mock_client)

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
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code == 0

    # Verify PULP_LABELS file was created
    labels_file = results_dir / "PULP_LABELS"
    assert labels_file.exists()

    # Verify content is valid JSON
    labels_data = json.loads(labels_file.read_text())
    assert "build_id" not in labels_data
    assert labels_data["source_image"] == "quay.io/test/image@sha256:abc123"


def test_publish_env_var_pulp_domain(tmp_path: Path) -> None:
    """Set SLAN_CUAN_PUBLISH_PULP_DOMAIN env var, verify it propagates."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    runner = CliRunner()
    with patch("slan_cuan.publish.PulpMavenClient") as mock_client_cls:
        mock_client = _make_ctx_mock()
        mock_client_cls.return_value = mock_client
        _setup_client_mock(mock_client)

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


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_modify_repository_error(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """PulpError from modify_repository is reported as ClickException."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.return_value = _REPO_HREF
    mock_client.modify_repository.side_effect = PulpError(
        message="Task failed: conflict",
        status_code=409,
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
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output


@patch("slan_cuan.publish.PulpMavenClient")
def test_publish_resolve_repository_error(
    mock_client_cls: Mock, tmp_path: Path
) -> None:
    """PulpError from resolve_repository is reported as ClickException."""
    artifact_dir = create_test_artifact_dir(tmp_path)

    mock_client = _make_ctx_mock()
    mock_client_cls.return_value = mock_client
    mock_client.upload_content.return_value = _CONTENT_UNIT
    mock_client.resolve_repository.side_effect = PulpError(
        message="Repository 'test-repo' not found",
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
            "--pulp-domain",
            "lightwell",
            "--pulp-username",
            "testuser",
            "--pulp-password",
            "testpass",
        ],
    )

    assert result.exit_code != 0
    assert "Pulp error:" in result.output
    assert "not found" in result.output
