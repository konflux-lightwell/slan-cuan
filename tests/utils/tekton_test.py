"""Tests for Tekton Task result file utilities."""

from __future__ import annotations

from slan_cuan.utils.tekton import write_tekton_result


def test_write_tekton_result_creates_file(tmp_path) -> None:
    """write_tekton_result creates a file with the given name and value."""
    results_dir = tmp_path / "results"
    write_tekton_result(results_dir, "TEST_RESULT", "test-value")

    result_file = results_dir / "TEST_RESULT"
    assert result_file.exists()
    assert result_file.read_text() == "test-value"


def test_write_tekton_result_creates_directory(tmp_path) -> None:
    """write_tekton_result creates parent directories if they don't exist."""
    results_dir = tmp_path / "nested" / "results"
    write_tekton_result(results_dir, "TEST_RESULT", "test-value")

    result_file = results_dir / "TEST_RESULT"
    assert result_file.exists()
    assert result_file.read_text() == "test-value"


def test_write_tekton_result_noop_when_none() -> None:
    """write_tekton_result does nothing when results_dir is None."""
    write_tekton_result(None, "TEST_RESULT", "test-value")
