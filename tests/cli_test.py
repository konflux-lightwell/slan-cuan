"""Tests for CLI group wiring, subcommand reachability, and env-var precedence."""

from click.testing import CliRunner

from slan_cuan.cli import main


def test_extract_subcommand_is_reachable() -> None:
    """Extract subcommand responds to --help and shows --image option."""
    runner = CliRunner()
    result = runner.invoke(main, ["extract", "--help"])

    assert result.exit_code == 0
    assert "--image" in result.output


def test_help_lists_extract_subcommand() -> None:
    """slan-cuan --help includes extract in subcommand list."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "extract" in result.output


def test_env_var_override_for_global_option() -> None:
    """SLAN_CUAN_VERBOSE sets --verbose via environment variable."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["extract", "--image", "test"],
        env={"SLAN_CUAN_VERBOSE": "true"},
    )

    assert result.exit_code == 0
    assert "verbose=True" in result.output


def test_env_var_override_for_subcommand_option() -> None:
    """SLAN_CUAN_EXTRACT_IMAGE sets --image via environment variable."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["extract"],
        env={"SLAN_CUAN_EXTRACT_IMAGE": "registry.example.com/image:latest"},
    )

    assert result.exit_code == 0
    assert "registry.example.com/image:latest" in result.output


def test_cli_flag_overrides_env_var() -> None:
    """CLI flag value takes precedence over env var when both are set."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["extract", "--image", "flag-value"],
        env={"SLAN_CUAN_EXTRACT_IMAGE": "env-value"},
    )

    assert result.exit_code == 0
    assert "flag-value" in result.output
    assert "env-value" not in result.output
