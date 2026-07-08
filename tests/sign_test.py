"""Tests for sign subcommand (slan_cuan/sign.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main
from slan_cuan.sign import _build_radas_config_from_env

# Common RADAS CLI args used across multiple tests
_RADAS_ARGS = [
    "--radas-umb-host",
    "umb.example.com",
    "--radas-result-queue",
    "42",
    "--radas-request-channel",
    "test-channel",
    "--radas-client-ca",
    "/certs/ca.pem",
    "--radas-client-key",
    "/certs/key.pem",
    "--radas-client-key-pass-file",
    "/certs/key.pw",
    "--radas-root-ca",
    "/certs/root.pem",
]


def _setup_repo_dir(tmp_path: Path) -> str:
    """Create a repo directory with extract-result.json, return repo_path."""
    repos_dir = tmp_path / "repos"
    repos_dir.mkdir(exist_ok=True)
    (repos_dir / "extract-result.json").write_text(
        json.dumps({"deliverable_dir": "original"})
    )
    return str(repos_dir / "maven-repo.zip")


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
        *_RADAS_ARGS,
    ]


def test_sign_help_output() -> None:
    """Verify --help shows all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert "--repo-url" in result.output
    assert "--repo-path" in result.output
    assert "--signing-key" in result.output
    assert "--output-path" in result.output
    assert "--radas-umb-host" in result.output
    assert "--radas-result-queue" in result.output
    assert "--radas-request-channel " in result.output
    assert "--radas-client-ca" in result.output
    assert "--radas-client-key " in result.output
    assert "--radas-client-key-pass-file" in result.output
    assert "--radas-root-ca" in result.output
    assert "--radas-receiver-timeout" in result.output
    assert "--requester-id" in result.output
    assert "--zip-root-path" in result.output
    assert "--product-key" in result.output
    assert "--ignore-patterns" in result.output
    assert "--direct-sign" in result.output
    assert "--direct-sign-pipeline-name" in result.output
    assert "--direct-sign-task-git-url" in result.output
    assert "--direct-sign-task-git-revision" in result.output
    assert "--intention" in result.output


def test_sign_subcommand_is_reachable() -> None:
    """Verify sign subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert (
        "Sign Maven artifacts on RADAS or directly via internal-request"
        in result.output
    )


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
            *_RADAS_ARGS,
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
            *_RADAS_ARGS,
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
            *_RADAS_ARGS,
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
            *_RADAS_ARGS,
        ],
    )

    assert result.exit_code != 0
    assert "--output-path" in result.output or "Missing option" in result.output


def test_sign_requires_radas_umb_host() -> None:
    """Missing --radas-umb-host fails."""
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
            "--output-path",
            "/tmp/out",
            "--radas-result-queue",
            "42",
            "--radas-request-channel",
            "test-channel",
            "--radas-client-ca",
            "/certs/ca.pem",
            "--radas-client-key",
            "/certs/key.pem",
            "--radas-client-key-pass-file",
            "/certs/key.pw",
            "--radas-root-ca",
            "/certs/root.pem",
        ],
    )

    assert result.exit_code != 0
    assert (
        "--radas-umb-host" in result.output or "Missing option" in result.output
    )


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_successful_signing(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Successful signing calls both workflows and reports success."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"]) / "results"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    assert mock_set_logging.call_count == 2
    mock_sign_radas.assert_called_once()
    mock_sign_individual.assert_called_once()

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert radas_kwargs["repo_url"] == "quay.io/someorg/maven:latest"
    assert radas_kwargs["sign_key"] == "/keys/signing.key"
    radas_config = json.load(radas_kwargs["radas_config"])
    assert radas_config["umb_host"] == "umb.example.com"

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert individual_kwargs["repos"] == [repo_path]
    assert individual_kwargs["product_key"] == "slan-cuan"
    assert individual_kwargs["root_path"] == "repository"


@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_no_signed_json_found(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    tmp_path: Path,
) -> None:
    """Error when no JSON files are found after RADAS signing."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code != 0
    assert "No signed JSON file found" in result.output


@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_radas_workflow_error(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    tmp_path: Path,
) -> None:
    """Exception from sign_in_radas_workflow is wrapped in ClickException."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    mock_sign_radas.side_effect = RuntimeError("RADAS connection refused")

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code != 0
    assert "RADAS connection refused" in result.output


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_individual_workflow_error(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """sign_individual_artifacts_workflow error is wrapped in ClickException."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"])
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect
    mock_sign_individual.side_effect = ValueError("Invalid artifact format")

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code != 0
    assert "Invalid artifact format" in result.output


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_custom_options(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Custom requester-id, zip-root-path, and product-key are forwarded."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path)
        + [
            "--requester-id",
            "custom@redhat.com",
            "--zip-root-path",
            "custom-root",
            "--product-key",
            "custom-product",
        ],
    )

    assert result.exit_code == 0

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert radas_kwargs["requester"] == "custom@redhat.com"

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert individual_kwargs["root_path"] == "custom-root"
    assert individual_kwargs["product_key"] == "custom-product"


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_ignore_patterns(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Multiple --ignore-patterns are forwarded to both workflows."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

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

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert ".*-sources\\.jar$" in radas_kwargs["ignore_patterns"]
    assert ".*-javadoc\\.jar$" in radas_kwargs["ignore_patterns"]

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert ".*-sources\\.jar$" in individual_kwargs["ignore_patterns"]
    assert ".*-javadoc\\.jar$" in individual_kwargs["ignore_patterns"]


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_verbose_sets_debug_logging(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """With --verbose, set_logging is called with DEBUG level."""
    import logging

    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main, ["--verbose"] + _base_sign_args(output_path, repo_path)
    )

    assert result.exit_code == 0
    assert mock_set_logging.call_count == 2
    # Verify both loggers are configured with DEBUG level
    calls = mock_set_logging.call_args_list
    assert calls[0] == (
        ("sign", "slan-cuan", logging.DEBUG),
        {"use_log_file": False},
    )
    assert calls[1] == (
        ("sign", "novabucks", logging.DEBUG),
        {"use_log_file": False},
    )


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_default_logging_level(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Without --verbose, set_logging is called with INFO level."""
    import logging

    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    assert mock_set_logging.call_count == 2
    # Verify both loggers are configured with INFO level
    calls = mock_set_logging.call_args_list
    assert calls[0] == (
        ("sign", "slan-cuan", logging.INFO),
        {"use_log_file": False},
    )
    assert calls[1] == (
        ("sign", "novabucks", logging.INFO),
        {"use_log_file": False},
    )


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_radas_options_from_env_vars(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """RADAS env vars set the corresponding --radas-* options."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "sign",
            "--repo-url",
            "quay.io/someorg/maven:latest",
            "--repo-path",
            repo_path,
            "--signing-key",
            "/keys/signing.key",
            "--output-path",
            str(output_path),
        ],
        env={
            "SLAN_CUAN_RADAS_UMB_HOST": "umb.example.com",
            "SLAN_CUAN_RADAS_RESULT_QUEUE": "42",
            "SLAN_CUAN_RADAS_REQUEST_CHANNEL": "test-channel",
            "SLAN_CUAN_RADAS_CLIENT_CA": "/certs/ca.pem",
            "SLAN_CUAN_RADAS_CLIENT_KEY": "/certs/key.pem",
            "SLAN_CUAN_RADAS_CLIENT_KEY_PASS_FILE": "/certs/key.pw",
            "SLAN_CUAN_RADAS_ROOT_CA": "/certs/root.pem",
        },
    )

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_temp_dir_cleaned_up(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Temporary directory is cleaned up after signing completes."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    captured_tmp_dir = []

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    def individual_side_effect(**kwargs):
        captured_tmp_dir.append(kwargs["temp_dir"])
        assert Path(kwargs["temp_dir"]).exists()

    mock_sign_radas.side_effect = radas_side_effect
    mock_sign_individual.side_effect = individual_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    assert len(captured_tmp_dir) == 1
    assert not Path(captured_tmp_dir[0]).exists()


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_ignore_patterns_from_env_var_comma_separated(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Comma-separated SLAN_CUAN_SIGN_IGNORE_PATTERNS produces patterns."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path),
        env={
            "SLAN_CUAN_SIGN_IGNORE_PATTERNS": (
                ".*-sources\\.jar$,.*-javadoc\\.jar$"
            )
        },
    )

    assert result.exit_code == 0

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert ".*-sources\\.jar$" in radas_kwargs["ignore_patterns"]
    assert ".*-javadoc\\.jar$" in radas_kwargs["ignore_patterns"]

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert ".*-sources\\.jar$" in individual_kwargs["ignore_patterns"]
    assert ".*-javadoc\\.jar$" in individual_kwargs["ignore_patterns"]


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_ignore_patterns_single_from_env_var(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """Single pattern from SLAN_CUAN_SIGN_IGNORE_PATTERNS works correctly."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path, repo_path),
        env={"SLAN_CUAN_SIGN_IGNORE_PATTERNS": ".*-sources\\.jar$"},
    )

    assert result.exit_code == 0

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert ".*-sources\\.jar$" in radas_kwargs["ignore_patterns"]
    assert len(radas_kwargs["ignore_patterns"]) == 1

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert ".*-sources\\.jar$" in individual_kwargs["ignore_patterns"]
    assert len(individual_kwargs["ignore_patterns"]) == 1


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_falls_back_to_extracted_directory(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """When repo_path is a .zip that doesn't exist, fall back to the directory."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repos_dir = tmp_path / "repos"
    repos_dir.mkdir()
    (repos_dir / "extract-result.json").write_text(
        json.dumps({"deliverable_dir": "original"})
    )
    # Create the extracted directory (no zip file)
    (repos_dir / "build-output").mkdir()
    zip_path = str(repos_dir / "build-output.zip")

    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"]) / "results"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, zip_path))

    assert result.exit_code == 0

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert individual_kwargs["repos"] == [str(repos_dir / "build-output")]


def test_build_radas_config_from_env() -> None:
    """_build_radas_config_from_env returns a file-like JSON object."""
    config_io = _build_radas_config_from_env(
        radas_umb_host="umb.example.com",
        radas_result_queue=42,
        radas_request_channel="test-channel",
        radas_client_ca="/certs/ca.pem",
        radas_client_key="/certs/key.pem",
        radas_client_key_pass_file="/certs/key.pw",
        radas_root_ca="/certs/root.pem",
        radas_receiver_timeout=3600,
    )

    config = json.load(config_io)
    assert config["umb_host"] == "umb.example.com"
    assert config["result_queue"] == 42
    assert config["request_channel"] == "test-channel"
    assert config["client_ca"] == "/certs/ca.pem"
    assert config["client_key"] == "/certs/key.pem"
    assert config["client_key_pass_file"] == "/certs/key.pw"
    assert config["root_ca"] == "/certs/root.pem"
    assert config["radas_receiver_timeout"] == 3600


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_radas_config_passed_as_file_like(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """RADAS config is passed as a file-like JSON object."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    radas_kwargs = mock_sign_radas.call_args.kwargs
    config = json.load(radas_kwargs["radas_config"])
    assert config["umb_host"] == "umb.example.com"
    assert config["request_channel"] == "test-channel"


# ---------------------------------------------------------------------------
# Direct signing tests
# ---------------------------------------------------------------------------


def _fake_tmpdir(path: Path) -> MagicMock:
    """Mock TemporaryDirectory context manager yielding the given path."""
    cm = MagicMock()
    cm.__enter__ = Mock(return_value=str(path))
    cm.__exit__ = Mock(return_value=False)
    return cm


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("internal_request.create")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_direct_sign_successful(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_create_ir: Mock,
    mock_sign_individual: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Direct signing calls internal_request.create and skips RADAS."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "middleware-signing-abc123"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": (
            "oci:quay.io/konflux-ci/trusted-artifacts"
            "@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ),
    }

    def blob_fetch_side_effect(reference, output_file, **kwargs):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b'{"signed": true}'
            info = tarfile.TarInfo(name="results.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        Path(output_file).write_bytes(buf.getvalue())

    mock_blob_fetch.side_effect = blob_fetch_side_effect

    sign_url_dir = tmp_path / "sign_url"
    sign_url_dir.mkdir()

    sign_work_dir = tmp_path / "sign_work"
    sign_work_dir.mkdir()

    with patch(
        "slan_cuan.sign.tempfile.TemporaryDirectory",
        side_effect=[_fake_tmpdir(sign_url_dir), _fake_tmpdir(sign_work_dir)],
    ):
        runner = CliRunner()
        result = runner.invoke(
            main,
            _base_sign_args(output_path, repo_path) + ["--direct-sign"],
        )

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    mock_sign_radas.assert_not_called()
    mock_create_ir.assert_called_once()
    mock_sign_individual.assert_called_once()

    call_kwargs = mock_create_ir.call_args
    assert call_kwargs.args[0] == "middleware-signing"
    assert call_kwargs.kwargs["sync"] is True


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("internal_request.create")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_direct_sign_create_error(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_create_ir: Mock,
    mock_sign_individual: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """InternalRequest creation failure is wrapped in ClickException."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    mock_create_ir.side_effect = RuntimeError("signing failed")

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path) + ["--direct-sign"],
    )

    assert result.exit_code != 0
    assert "Error signing artifacts" in result.output
    mock_sign_radas.assert_not_called()
    mock_sign_individual.assert_not_called()


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("internal_request.create")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_direct_sign_custom_pipeline_options(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_create_ir: Mock,
    mock_sign_individual: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Custom direct-sign pipeline options are forwarded to create()."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "custom-pipeline-abc123"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": (
            "oci:quay.io/konflux-ci/trusted-artifacts"
            "@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ),
    }

    def blob_fetch_side_effect(reference, output_file, **kwargs):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b'{"signed": true}'
            info = tarfile.TarInfo(name="results.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        Path(output_file).write_bytes(buf.getvalue())

    mock_blob_fetch.side_effect = blob_fetch_side_effect

    sign_url_dir = tmp_path / "sign_url"
    sign_url_dir.mkdir()

    sign_work_dir = tmp_path / "sign_work"
    sign_work_dir.mkdir()

    with patch(
        "slan_cuan.sign.tempfile.TemporaryDirectory",
        side_effect=[_fake_tmpdir(sign_url_dir), _fake_tmpdir(sign_work_dir)],
    ):
        runner = CliRunner()
        result = runner.invoke(
            main,
            _base_sign_args(output_path, repo_path)
            + [
                "--direct-sign",
                "--direct-sign-pipeline-name",
                "custom-pipeline",
                "--direct-sign-task-git-url",
                "gitlab.example.com/signing.git",
                "--direct-sign-task-git-revision",
                "release-v2",
                "--intention",
                "staging",
            ],
        )

    assert result.exit_code == 0

    call_kwargs = mock_create_ir.call_args
    assert call_kwargs.args[0] == "custom-pipeline"
    params = call_kwargs.kwargs["params"]
    assert params["taskGitUrl"] == "gitlab.example.com/signing.git"
    assert params["taskGitRevision"] == "release-v2"
    labels = call_kwargs.kwargs["labels"]
    assert (
        labels["internal-services.appstudio.openshift.io/intention"] == "staging"
    )


@patch("slan_cuan.sign.blob_fetch")
@patch("internal_request.fetch_results")
@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("internal_request.create")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_direct_sign_default_options(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_create_ir: Mock,
    mock_sign_individual: Mock,
    mock_fetch_results: Mock,
    mock_blob_fetch: Mock,
    tmp_path: Path,
) -> None:
    """Default direct-sign pipeline options are used when not specified."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    mock_create_ir.return_value = "middleware-signing-abc123"
    mock_fetch_results.return_value = {
        "sourceDataArtifact": (
            "oci:quay.io/konflux-ci/trusted-artifacts"
            "@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ),
    }

    def blob_fetch_side_effect(reference, output_file, **kwargs):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b'{"signed": true}'
            info = tarfile.TarInfo(name="results.json")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        Path(output_file).write_bytes(buf.getvalue())

    mock_blob_fetch.side_effect = blob_fetch_side_effect

    sign_url_dir = tmp_path / "sign_url"
    sign_url_dir.mkdir()

    sign_work_dir = tmp_path / "sign_work"
    sign_work_dir.mkdir()

    with patch(
        "slan_cuan.sign.tempfile.TemporaryDirectory",
        side_effect=[_fake_tmpdir(sign_url_dir), _fake_tmpdir(sign_work_dir)],
    ):
        runner = CliRunner()
        result = runner.invoke(
            main,
            _base_sign_args(output_path, repo_path) + ["--direct-sign"],
        )

    assert result.exit_code == 0

    call_kwargs = mock_create_ir.call_args
    assert call_kwargs.args[0] == "middleware-signing"
    params = call_kwargs.kwargs["params"]
    assert (
        params["taskGitUrl"]
        == "https://gitlab.cee.redhat.com/signing/signing.git"
    )
    assert params["taskGitRevision"] == "main"
    labels = call_kwargs.kwargs["labels"]
    assert (
        labels["internal-services.appstudio.openshift.io/intention"]
        == "production"
    )


@patch("internal_request.create")
@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_without_direct_sign_uses_radas(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    mock_create_ir: Mock,
    tmp_path: Path,
) -> None:
    """Without --direct-sign, the RADAS workflow is used."""
    output_path = tmp_path / "output"
    output_path.mkdir()
    repo_path = _setup_repo_dir(tmp_path)

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path, repo_path))

    assert result.exit_code == 0
    mock_sign_radas.assert_called_once()
    mock_create_ir.assert_not_called()
