"""Tests for sign subcommand (slan_cuan/sign.py)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from slan_cuan.cli import main


def _base_sign_args(
    radas_config: Path,
    output_path: Path,
) -> list[str]:
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
        "--radas-config",
        str(radas_config),
    ]


def _create_radas_config(tmp_path: Path) -> Path:
    """Create a dummy RADAS config file (--radas-config requires exists=True)."""
    cfg = tmp_path / "radas.json"
    cfg.write_text("{}")
    return cfg


def test_sign_help_output() -> None:
    """Verify --help shows all options."""
    runner = CliRunner()
    result = runner.invoke(main, ["sign", "--help"])

    assert result.exit_code == 0
    assert "--repo-url" in result.output
    assert "--repo-path" in result.output
    assert "--signing-key" in result.output
    assert "--output-path" in result.output
    assert "--radas-config" in result.output
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
    cfg = _create_radas_config(tmp_path)

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
            "--radas-config",
            str(cfg),
        ],
    )

    assert result.exit_code != 0
    assert "--repo-url" in result.output or "Missing option" in result.output


def test_sign_requires_repo_path(tmp_path: Path) -> None:
    """Missing --repo-path fails."""
    cfg = _create_radas_config(tmp_path)

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
            "--radas-config",
            str(cfg),
        ],
    )

    assert result.exit_code != 0
    assert "--repo-path" in result.output or "Missing option" in result.output


def test_sign_requires_signing_key(tmp_path: Path) -> None:
    """Missing --signing-key fails."""
    cfg = _create_radas_config(tmp_path)

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
            "--radas-config",
            str(cfg),
        ],
    )

    assert result.exit_code != 0
    assert "--signing-key" in result.output or "Missing option" in result.output


def test_sign_requires_output_path(tmp_path: Path) -> None:
    """Missing --output-path fails."""
    cfg = _create_radas_config(tmp_path)

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
            "--radas-config",
            str(cfg),
        ],
    )

    assert result.exit_code != 0
    assert "--output-path" in result.output or "Missing option" in result.output


def test_sign_requires_radas_config() -> None:
    """Missing --radas-config fails."""
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
        ],
    )

    assert result.exit_code != 0
    assert "--radas-config" in result.output or "Missing option" in result.output


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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    # sign_in_radas_workflow creates a JSON result file as a side effect
    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"]) / "results"
        result_dir.mkdir(parents=True, exist_ok=True)
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

    assert result.exit_code == 0
    assert "Sign command completed successfully" in result.output

    mock_set_logging.assert_called_once()
    mock_sign_radas.assert_called_once()
    mock_sign_individual.assert_called_once()

    # Verify workflow arguments
    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert radas_kwargs["repo_url"] == "quay.io/someorg/maven:latest"
    assert radas_kwargs["sign_key"] == "/keys/signing.key"
    assert radas_kwargs["radas_config"] == cfg

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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    mock_sign_radas.side_effect = RuntimeError("RADAS connection refused")

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

    assert result.exit_code != 0
    assert "Error signing artifacts" in result.output
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        result_dir = Path(kwargs["result_path"])
        (result_dir / "sign-result.json").write_text('{"signed": true}')

    mock_sign_radas.side_effect = radas_side_effect
    mock_sign_individual.side_effect = ValueError("Invalid artifact format")

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

    assert result.exit_code != 0
    assert "Error signing artifacts" in result.output
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(cfg, output_path)
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(cfg, output_path)
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

    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main, ["--verbose"] + _base_sign_args(cfg, output_path)
    )

    assert result.exit_code == 0
    mock_set_logging.assert_called_once_with(
        "sign", "slan-cuan", logging.DEBUG, use_logfile=False
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

    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

    assert result.exit_code == 0
    mock_set_logging.assert_called_once_with(
        "sign", "slan-cuan", logging.INFO, use_logfile=False
    )


@patch("slan_cuan.sign.sign_individual_artifacts_workflow")
@patch("slan_cuan.sign.sign_in_radas_workflow")
@patch("slan_cuan.sign.set_logging")
def test_sign_env_var_for_radas_config(
    mock_set_logging: Mock,
    mock_sign_radas: Mock,
    mock_sign_individual: Mock,
    tmp_path: Path,
) -> None:
    """RADAS_CONFIG_PATH env var sets --radas-config."""
    cfg = _create_radas_config(tmp_path)
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
        env={"RADAS_CONFIG_PATH": str(cfg)},
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    captured_tmp_dir = []

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    def individual_side_effect(**kwargs):
        captured_tmp_dir.append(kwargs["tmp_dir"])
        # Verify the temp dir exists while workflow runs
        assert Path(kwargs["tmp_dir"]).exists()

    mock_sign_radas.side_effect = radas_side_effect
    mock_sign_individual.side_effect = individual_side_effect

    runner = CliRunner()
    result = runner.invoke(main, _base_sign_args(cfg, output_path))

    assert result.exit_code == 0
    assert len(captured_tmp_dir) == 1
    # Temp dir should be cleaned up after the context manager exits
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(cfg, output_path),
        env={
            "SLAN_CUAN_SIGN_IGNORE_PATTERNS": (
                ".*-sources\\.jar$,.*-javadoc\\.jar$"
            )
        },
    )

    assert result.exit_code == 0

    # Verify both patterns forwarded to workflows
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
    cfg = _create_radas_config(tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    def radas_side_effect(**kwargs):
        (Path(kwargs["result_path"]) / "result.json").write_text("{}")

    mock_sign_radas.side_effect = radas_side_effect

    runner = CliRunner()
    result = runner.invoke(
        main,
        _base_sign_args(cfg, output_path),
        env={"SLAN_CUAN_SIGN_IGNORE_PATTERNS": ".*-sources\\.jar$"},
    )

    assert result.exit_code == 0

    # Verify single pattern forwarded to workflows
    radas_kwargs = mock_sign_radas.call_args.kwargs
    assert ".*-sources\\.jar$" in radas_kwargs["ignore_patterns"]
    assert len(radas_kwargs["ignore_patterns"]) == 1

    individual_kwargs = mock_sign_individual.call_args.kwargs
    assert ".*-sources\\.jar$" in individual_kwargs["ignore_patterns"]
    assert len(individual_kwargs["ignore_patterns"]) == 1
