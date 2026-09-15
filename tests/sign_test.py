"""Tests for sign subcommand (slan_cuan/sign.py) and maven utilities."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.maven import (
    VersionCompareKey,
    apply_signatures,
    ensure_artifact_checksums,
    extract_repository,
    format_maven_metadata,
    generate_maven_metadata,
    sign_individual_artifacts,
)


def _setup_repo_dir(tmp_path: Path) -> str:
    """Create a repo directory with an artifact, POM, and extract-result.json."""
    repos_dir = tmp_path / "repos"
    repo_dir = repos_dir / "repository" / "org" / "example" / "my-app" / "1.0.0"
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "my-app-1.0.0.jar").write_bytes(b"dummy jar content")
    (repo_dir / "my-app-1.0.0.pom").write_text(
        "<project><groupId>org.example</groupId><artifactId>my-app</artifactId>"
        "<version>1.0.0</version></project>",
        encoding="utf-8",
    )
    (repos_dir / "extract-result.json").write_text(
        json.dumps({"deliverable_dir": "original"})
    )
    return str(repos_dir / "repository")


def _setup_repo_zip(tmp_path: Path) -> str:
    """Create a repo ZIP with an artifact, POM, and extract-result.json."""
    repos_dir = tmp_path / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    zip_path = repos_dir / "maven-repo.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "repository/org/example/my-app/1.0.0/my-app-1.0.0.jar",
            b"dummy jar content",
        )
        zf.writestr(
            "repository/org/example/my-app/1.0.0/my-app-1.0.0.pom",
            "<project><groupId>org.example</groupId><artifactId>my-app</artifactId>"
            "<version>1.0.0</version></project>",
        )
    (repos_dir / "extract-result.json").write_text(
        json.dumps({"deliverable_dir": "original"})
    )
    return str(zip_path)


def _make_signed_tarball(
    results: list[dict[str, str]] | None = None,
) -> bytes:
    """Create a tar.gz containing results.json with signed results."""
    if results is None:
        results = [
            {
                "file": (
                    "repository/org/example/my-app/1.0.0/my-app-1.0.0.jar"
                ),
                "signature": (
                    "-----BEGIN PGP SIGNATURE-----\n"
                    "fake-jar-sig\n"
                    "-----END PGP SIGNATURE-----"
                ),
            },
            {
                "file": (
                    "repository/org/example/my-app/1.0.0/my-app-1.0.0.pom"
                ),
                "signature": (
                    "-----BEGIN PGP SIGNATURE-----\n"
                    "fake-pom-sig\n"
                    "-----END PGP SIGNATURE-----"
                ),
            },
        ]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = json.dumps({"results": results}).encode("utf-8")
        info = tarfile.TarInfo(name="results.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _base_sign_args(
    output_path: Path, repo_path: str = "/repos/maven-repo.zip"
) -> list[str]:
    """Return the minimum required args for the sign subcommand."""
    return [
        "sign",
        "--repo-url",
        "quay.io/someorg/maven:latest",
        "--repo-path",
        repo_path,
        "--signing-key",
        "/keys/signing.key",
        "--output-path",
        str(output_path),
    ]


def test_sign_help_output() -> None:
    """Verify --help shows all options and no deprecated RADAS UMB options."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert "--repo-url" in result.output
    assert "--repo-path" in result.output
    assert "--signing-key" in result.output
    assert "--output-path" in result.output
    assert "--requester-id" in result.output
    assert "--zip-root-path" in result.output
    assert "--product-key" in result.output
    assert "--ignore-patterns" in result.output
    assert "--direct-sign" in result.output
    assert "--direct-sign-pipeline-name" in result.output
    assert "--direct-sign-task-git-url" in result.output
    assert "--direct-sign-task-git-revision" in result.output
    assert "--intention" in result.output

    # Deprecated RADAS UMB options must NOT be present
    assert "--radas-umb-host" not in result.output
    assert "--radas-result-queue" not in result.output
    assert "--radas-request-channel" not in result.output
    assert "--radas-client-ca" not in result.output
    assert "--radas-client-key" not in result.output
    assert "--radas-root-ca" not in result.output
    assert "--radas-receiver-timeout" not in result.output


def test_sign_subcommand_is_reachable() -> None:
    """Verify sign subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert "Sign Maven artifacts directly via internal-request" in result.output


def test_sign_requires_repo_url(tmp_path: Path) -> None:
    """Missing --repo-url fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "sign",
            "--repo-path",
            "/repos/maven-repo.zip",
            "--signing-key",
            "/keys/signing.key",
            "--output-path",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code != 0
    assert "--repo-url" in result.output or "Missing option" in result.output


def test_sign_requires_repo_path(tmp_path: Path) -> None:
    """Missing --repo-path fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "sign",
            "--repo-url",
            "quay.io/someorg/maven:latest",
            "--signing-key",
            "/keys/signing.key",
            "--output-path",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code != 0
    assert "--repo-path" in result.output or "Missing option" in result.output


def test_sign_requires_signing_key(tmp_path: Path) -> None:
    """Missing --signing-key fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "sign",
            "--repo-url",
            "quay.io/someorg/maven:latest",
            "--repo-path",
            "/repos/maven-repo.zip",
            "--output-path",
            str(tmp_path / "out"),
        ],
    )

    assert result.exit_code != 0
    assert "--signing-key" in result.output or "Missing option" in result.output


def test_sign_requires_output_path() -> None:
    """Missing --output-path fails."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "sign",
            "--repo-url",
            "quay.io/someorg/maven:latest",
            "--repo-path",
            "/repos/maven-repo.zip",
            "--signing-key",
            "/keys/signing.key",
        ],
    )

    assert result.exit_code != 0
    assert "--output-path" in result.output or "Missing option" in result.output


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_successful_signing(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Successful signing calls direct signing and runs native processing."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "middleware-signing-test123"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:12345"
    }

    tarball_data = _make_signed_tarball()

    def blob_fetch_side_effect(reference, output_file, **kwargs):
        Path(output_file).write_bytes(tarball_data)

    mock_blob_fetch.side_effect = blob_fetch_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    mock_create_ir.assert_called_once()
    assert (
        mock_create_ir.call_args.kwargs["params"]["verbose"] == "false"
    )
    mock_fetch_results.assert_called_once_with("middleware-signing-test123")
    mock_blob_fetch.assert_called_once()

    # Verify signed repository output structure
    signed_repo = output_path / "signed" / "repository"
    app_dir = signed_repo / "org" / "example" / "my-app" / "1.0.0"
    assert (app_dir / "my-app-1.0.0.jar").exists()
    assert (app_dir / "my-app-1.0.0.jar.asc").exists()
    assert (app_dir / "my-app-1.0.0.jar.md5").exists()
    assert (app_dir / "my-app-1.0.0.jar.sha1").exists()
    assert (app_dir / "my-app-1.0.0.jar.sha256").exists()

    assert (app_dir / "my-app-1.0.0.pom").exists()
    assert (app_dir / "my-app-1.0.0.pom.asc").exists()

    # Verify maven-metadata.xml and its sidecars
    meta_dir = signed_repo / "org" / "example" / "my-app"
    meta_file = meta_dir / "maven-metadata.xml"
    assert meta_file.exists()
    assert (meta_dir / "maven-metadata.xml.md5").exists()
    assert (meta_dir / "maven-metadata.xml.sha1").exists()
    assert (meta_dir / "maven-metadata.xml.sha256").exists()

    meta_text = meta_file.read_text()
    assert "<groupId>org.example</groupId>" in meta_text
    assert "<artifactId>my-app</artifactId>" in meta_text
    assert "<version>1.0.0</version>" in meta_text

    # Verify extract-result.json update
    extract_result_path = output_path / "extract-result.json"
    assert extract_result_path.exists()
    extract_data = json.loads(extract_result_path.read_text())
    assert extract_data["deliverable_dir"] == "signed"


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_with_repo_zip(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Signing unpacks a ZIP archive safely and signs it."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_zip_path = _setup_repo_zip(tmp_path)

    mock_create_ir.return_value = "middleware-signing-zip456"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:67890"
    }

    tarball_data = _make_signed_tarball()

    def blob_fetch_side_effect(reference, output_file, **kwargs):
        Path(output_file).write_bytes(tarball_data)

    mock_blob_fetch.side_effect = blob_fetch_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_zip_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    signed_repo = output_path / "signed" / "repository"
    app_dir = signed_repo / "org" / "example" / "my-app" / "1.0.0"
    assert (app_dir / "my-app-1.0.0.jar.asc").exists()
    assert (app_dir / "my-app-1.0.0.jar.sha256").exists()


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_no_signed_json_found(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Error when no JSON files are found after direct signing blob fetch."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    mock_create_ir.return_value = "ir-1"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/empty@sha256:000"
    }

    # Empty tar.gz without any json file
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    mock_blob_fetch.side_effect = lambda ref, out, **kw: Path(out).write_bytes(
        buf.getvalue()
    )

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code != 0
    assert "No signed JSON file found" in result.output


@patch("internal_request.create")
def test_sign_direct_sign_create_error(
    mock_create_ir: Mock,
    tmp_path: Path,
) -> None:
    """InternalRequest creation failure is wrapped in ClickException."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    mock_create_ir.side_effect = RuntimeError("InternalRequest failed")

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code != 0
    assert "Error signing artifacts" in result.output
    assert "InternalRequest failed" in result.output


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_custom_pipeline_options(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Custom direct-sign pipeline options are forwarded to create()."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "custom-pipeline-123"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:111"
    }
    tarball_data = _make_signed_tarball()
    mock_blob_fetch.side_effect = lambda ref, out, **kw: Path(out).write_bytes(
        tarball_data
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path)
        + [
            "--direct-sign-pipeline-name",
            "custom-signing",
            "--direct-sign-task-git-url",
            "https://gitlab.example.com/custom-signing.git",
            "--direct-sign-task-git-revision",
            "release-v1",
            "--direct-sign-verbose",
            "--intention",
            "staging",
        ],
    )

    assert result.exit_code == 0
    call_kwargs = mock_create_ir.call_args
    assert call_kwargs.args[0] == "custom-signing"
    params = call_kwargs.kwargs["params"]
    assert params["taskGitUrl"] == "https://gitlab.example.com/custom-signing.git"
    assert params["taskGitRevision"] == "release-v1"
    assert params["verbose"] == "true"
    labels = call_kwargs.kwargs["labels"]
    intention_label = (
        labels["internal-services.appstudio.openshift.io/intention"]
    )
    assert intention_label == "staging"


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_ignore_patterns_forwarded(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Multiple --ignore-patterns are forwarded to direct signing."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "ir-ignore"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:222"
    }
    tarball_data = _make_signed_tarball()
    mock_blob_fetch.side_effect = lambda ref, out, **kw: Path(out).write_bytes(
        tarball_data
    )

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path)
        + [
            "--ignore-patterns",
            ".*-sources\\.jar$",
            "--ignore-patterns",
            ".*-javadoc\\.jar$",
        ],
    )

    assert result.exit_code == 0
    params = mock_create_ir.call_args.kwargs["params"]
    assert ".*-sources" in params["ignorePatterns"]
    assert ".*-javadoc" in params["ignorePatterns"]


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_ignore_patterns_from_env_var(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Comma-separated SLAN_CUAN_SIGN_IGNORE_PATTERNS works correctly."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "ir-ignore-env"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:333"
    }
    tarball_data = _make_signed_tarball()
    mock_blob_fetch.side_effect = lambda ref, out, **kw: Path(out).write_bytes(
        tarball_data
    )

    runner = CliRunner()
    pattern_val = ".*-sources\\.jar$,.*-javadoc\\.jar$"
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path),
        env={"SLAN_CUAN_SIGN_IGNORE_PATTERNS": pattern_val},
    )

    assert result.exit_code == 0
    params = mock_create_ir.call_args.kwargs["params"]
    assert ".*-sources" in params["ignorePatterns"]
    assert ".*-javadoc" in params["ignorePatterns"]


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("internal_request.create")
def test_sign_falls_back_to_extracted_directory(
    mock_create_ir: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """When repo_path is a .zip that doesn't exist, fall back to directory."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repos_dir = tmp_path / "repos"
    repos_dir.mkdir()
    (repos_dir / "extract-result.json").write_text(
        json.dumps({"deliverable_dir": "original"})
    )
    # Create the directory matching the zip basename
    build_output = repos_dir / "build-output"
    build_output.mkdir()
    app_dir = build_output / "repository" / "org" / "example" / "my-app" / "1.0.0"
    app_dir.mkdir(parents=True)
    (app_dir / "my-app-1.0.0.jar").write_bytes(b"jar")
    (app_dir / "my-app-1.0.0.pom").write_text(
        "<project><groupId>org.example</groupId><artifactId>my-app</artifactId>"
        "<version>1.0.0</version></project>",
        encoding="utf-8",
    )
    zip_path = str(repos_dir / "build-output.zip")

    mock_create_ir.return_value = "ir-fallback"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": "oci:quay.io/test/blob@sha256:444"
    }
    tarball_data = _make_signed_tarball()
    mock_blob_fetch.side_effect = lambda ref, out, **kw: Path(out).write_bytes(
        tarball_data
    )

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, zip_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output


# ---------------------------------------------------------------------------
# Unit tests for slan_cuan.maven
# ---------------------------------------------------------------------------


def test_version_compare_key() -> None:
    """Test VersionCompareKey correctly sorts semantic and maven versions."""
    versions = [
        "1.0.0",
        "2.0.0",
        "1.1.0",
        "1.10.0",
        "1.2.0",
        "1.0.0.Alpha1",
        "1.0.0.Beta1",
    ]
    sorted_vers = sorted(versions, key=VersionCompareKey)
    assert sorted_vers == [
        "1.0.0",
        "1.0.0.Alpha1",
        "1.0.0.Beta1",
        "1.1.0",
        "1.2.0",
        "1.10.0",
        "2.0.0",
    ]


def test_extract_repository_zip_slip(tmp_path: Path) -> None:
    """extract_repository rejects zip files attempting zip-slip traversal."""
    bad_zip = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../../etc/passwd", "malicious")

    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    with pytest.raises(ValueError, match="Zip-slip path traversal attempt"):
        extract_repository(bad_zip, dest_dir)


def test_apply_signatures_missing_file_raises(tmp_path: Path) -> None:
    """apply_signatures raises error when sign result file is missing."""
    with pytest.raises(FileNotFoundError):
        apply_signatures(tmp_path, tmp_path / "nonexistent.json")


def test_apply_signatures_no_signatures_raises(tmp_path: Path) -> None:
    """apply_signatures raises RuntimeError when no signatures are generated."""
    json_file = tmp_path / "empty_results.json"
    json_file.write_text('{"results": []}')

    with pytest.raises(RuntimeError, match="No signature files were generated"):
        apply_signatures(tmp_path, json_file)


def test_format_maven_metadata() -> None:
    """format_maven_metadata formats valid XML with correct elements."""
    xml_str = format_maven_metadata(
        group_id="org.example",
        artifact_id="test-art",
        versions=["1.0.0", "1.1.0"],
        last_updated="20260915120000",
    )
    assert "<groupId>org.example</groupId>" in xml_str
    assert "<artifactId>test-art</artifactId>" in xml_str
    assert "<latest>1.1.0</latest>" in xml_str
    assert "<release>1.1.0</release>" in xml_str
    assert "<version>1.0.0</version>" in xml_str
    assert "<version>1.1.0</version>" in xml_str
    assert "<lastUpdated>20260915120000</lastUpdated>" in xml_str


def test_generate_maven_metadata_merges_existing(tmp_path: Path) -> None:
    """generate_maven_metadata merges newly discovered versions with existing."""
    top_level = tmp_path / "repo"
    art_dir = top_level / "com" / "test" / "foo"
    (art_dir / "2.0.0").mkdir(parents=True)
    (art_dir / "2.0.0" / "foo-2.0.0.pom").write_text("<project/>")

    # Write existing metadata with older version 1.0.0
    existing_meta = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<metadata>\n"
        "  <groupId>com.test</groupId>\n"
        "  <artifactId>foo</artifactId>\n"
        "  <versioning>\n"
        "    <versions>\n"
        "      <version>1.0.0</version>\n"
        "    </versions>\n"
        "  </versioning>\n"
        "</metadata>\n"
    )
    (art_dir / "maven-metadata.xml").write_text(existing_meta)

    created = generate_maven_metadata(top_level)
    assert any("maven-metadata.xml" in str(p) for p in created)

    updated_meta = (art_dir / "maven-metadata.xml").read_text()
    assert "<version>1.0.0</version>" in updated_meta
    assert "<version>2.0.0</version>" in updated_meta
    assert "<latest>2.0.0</latest>" in updated_meta

    # Check sidecars were created
    assert (art_dir / "maven-metadata.xml.md5").exists()
    assert (art_dir / "maven-metadata.xml.sha1").exists()
    assert (art_dir / "maven-metadata.xml.sha256").exists()


def test_generate_maven_metadata_merges_namespaced_existing(
    tmp_path: Path,
) -> None:
    """generate_maven_metadata handles existing metadata with XML namespace."""
    top_level = tmp_path / "repo"
    art_dir = top_level / "com" / "test" / "foo"
    (art_dir / "2.0.0").mkdir(parents=True)
    (art_dir / "2.0.0" / "foo-2.0.0.pom").write_text("<project/>")

    existing_meta = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<metadata xmlns="http://maven.apache.org/METADATA/1.1.0">\n'
        "  <groupId>com.test</groupId>\n"
        "  <artifactId>foo</artifactId>\n"
        "  <versioning>\n"
        "    <versions>\n"
        "      <version>1.0.0</version>\n"
        "    </versions>\n"
        "  </versioning>\n"
        "</metadata>\n"
    )
    (art_dir / "maven-metadata.xml").write_text(existing_meta)

    created = generate_maven_metadata(top_level)
    assert any("maven-metadata.xml" in str(p) for p in created)

    updated_meta = (art_dir / "maven-metadata.xml").read_text()
    assert "<version>1.0.0</version>" in updated_meta
    assert "<version>2.0.0</version>" in updated_meta
    assert "<latest>2.0.0</latest>" in updated_meta


def test_ensure_artifact_checksums(tmp_path: Path) -> None:
    """ensure_artifact_checksums creates .md5, .sha1, .sha256 sidecars."""
    jar_file = tmp_path / "sample.jar"
    jar_file.write_bytes(b"hello world")

    created = ensure_artifact_checksums(tmp_path)
    assert len(created) == 3
    assert (tmp_path / "sample.jar.md5").exists()
    assert (tmp_path / "sample.jar.sha1").exists()
    assert (tmp_path / "sample.jar.sha256").exists()

    # Ensure sidecars are not re-checksummed if called again
    created_again = ensure_artifact_checksums(tmp_path)
    # Updates existing sidecars without chaining e.g. sample.jar.md5.md5
    assert len(created_again) == 3


def test_sign_individual_artifacts_end_to_end(tmp_path: Path) -> None:
    """End-to-end test of sign_individual_artifacts workflow."""
    repo_dir = tmp_path / "source_repo"
    art_path = repo_dir / "repository" / "org" / "example" / "lib" / "1.2.3"
    art_path.mkdir(parents=True)
    jar = art_path / "lib-1.2.3.jar"
    jar.write_bytes(b"some binary jar content")
    pom = art_path / "lib-1.2.3.pom"
    pom.write_text("<project/>")

    sign_result = tmp_path / "results.json"
    sign_result.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "file": "repository/org/example/lib/1.2.3/lib-1.2.3.jar",
                        "signature": "JAR_SIGNATURE",
                    },
                    {
                        "file": "repository/org/example/lib/1.2.3/lib-1.2.3.pom",
                        "signature": "POM_SIGNATURE",
                    },
                ]
            }
        )
    )

    dest_dir = tmp_path / "destination"
    sign_individual_artifacts(
        repo_path=repo_dir,
        sign_result_file=sign_result,
        destination_dir=dest_dir,
        root_path="repository",
        product_key="test-product",
    )

    dest_art = dest_dir / "org" / "example" / "lib" / "1.2.3"
    assert (dest_art / "lib-1.2.3.jar").exists()
    assert (dest_art / "lib-1.2.3.jar.asc").read_text() == "JAR_SIGNATURE"
    assert (dest_art / "lib-1.2.3.jar.md5").exists()
    assert (dest_art / "lib-1.2.3.jar.sha1").exists()
    assert (dest_art / "lib-1.2.3.jar.sha256").exists()

    assert (dest_art / "lib-1.2.3.pom").exists()
    assert (dest_art / "lib-1.2.3.pom.asc").read_text() == "POM_SIGNATURE"

    meta = dest_dir / "org" / "example" / "lib" / "maven-metadata.xml"
    assert meta.exists()
    assert "<version>1.2.3</version>" in meta.read_text()
    meta_sha256 = (
        dest_dir / "org" / "example" / "lib" / "maven-metadata.xml.sha256"
    )
    assert meta_sha256.exists()

    # Manifest file
    manifest = dest_dir / "test-product.txt"
    assert manifest.exists()
    assert "org/example/lib/1.2.3/lib-1.2.3.jar" in manifest.read_text()


def test_apply_signatures_path_traversal_rejected(tmp_path: Path) -> None:
    """Path traversal sequences in sign result are safely skipped."""
    top_level = tmp_path / "repo"
    top_level.mkdir()
    valid_jar = top_level / "valid.jar"
    valid_jar.write_bytes(b"content")

    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("critical secret")

    sign_result = tmp_path / "results.json"
    sign_result.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "file": "../../outside.txt",
                        "signature": "MALICIOUS_SIG",
                    },
                    {
                        "file": "valid.jar",
                        "signature": "VALID_SIG",
                    },
                ]
            }
        )
    )
    generated = apply_signatures(top_level, sign_result)
    assert len(generated) == 1
    assert generated[0] == top_level / "valid.jar.asc"
    assert not (tmp_path / "outside.txt.asc").exists()


def test_ensure_artifact_checksums_ignores_txt_and_sidecars(
    tmp_path: Path,
) -> None:
    """Text files like manifests are not given checksum sidecars."""
    (tmp_path / "artifact.jar").write_bytes(b"jar")
    (tmp_path / "slan-cuan.txt").write_text("manifest")

    created = ensure_artifact_checksums(tmp_path)
    assert len(created) == 3
    assert (tmp_path / "artifact.jar.md5").exists()
    assert not (tmp_path / "slan-cuan.txt.md5").exists()
    assert not (tmp_path / "slan-cuan.txt.sha256").exists()
