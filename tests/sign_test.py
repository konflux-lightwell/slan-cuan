"""Tests for sign subcommand (slan_cuan/sign.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, patch

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


def _base_sign_args(output_path: Path) -> list[str]:
    """Return the minimum required args for the sign subcommand."""
    return [
        "sign",
        "--repo-url",
        "quay.io/someorg/maven:latest",
        "--repo-path",
        "/repos/maven-repo.zip",
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


def test_sign_subcommand_is_reachable() -> None:
    """Verify sign subcommand responds to --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert "Sign Maven artifacts on RADAS" in result.output


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

    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"]) / "results"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    mock_set_logging.assert_called_once()
    mock_sign_radas.assert_called_once()
    mock_sign_individual.assert_called_once()

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert radas_kwargs["repo_url"] == "quay.io/someorg/maven:latest"
    assert radas_kwargs["sign_key"] == "/keys/signing.key"
    radas_config = json.load(radas_kwargs["radas_config"])
    assert radas_config["umb_host"] == "umb.example.com"

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert individual_kwargs["repos"] == ["/repos/maven-repo.zip"]
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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path)
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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path)
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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, ["--verbose"] + _base_sign_args(output_path))

    assert result.exit_code == 0
    mock_set_logging.assert_called_once_with(
        "sign", "slan-cuan", logging.DEBUG, use_log_file=False
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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code == 0
    mock_set_logging.assert_called_once_with(
        "sign", "slan-cuan", logging.INFO, use_log_file=False
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
            "/repos/maven-repo.zip",
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

    captured_tmp_dir = []

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    def individual_side_effect(**kwargs):
        captured_tmp_dir.append(kwargs["temp_dir"])
        assert Path(kwargs["temp_dir"]).exists()

    mock_sign_radas.side_effect = radas_side_effect
    mock_sign_individual.side_effect = individual_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path),
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

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(output_path),
        env={"SLAN_CUAN_SIGN_IGNORE_PATTERNS": ".*-sources\\.jar$"},
    )

    assert result.exit_code == 0

    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert ".*-sources\\.jar$" in radas_kwargs["ignore_patterns"]
    assert len(radas_kwargs["ignore_patterns"]) == 1

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert ".*-sources\\.jar$" in individual_kwargs["ignore_patterns"]
    assert len(individual_kwargs["ignore_patterns"]) == 1


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
    """RADAS config is passed as a file-like JSON object to sign_in_radas_workflow."""
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(output_path))

    assert result.exit_code == 0
    radas_kwargs = mock_sign_radas.call_args.kwargs
    config = json.load(radas_kwargs["radas_config"])
    assert config["umb_host"] == "umb.example.com"
    assert config["request_channel"] == "test-channel"
