"""Tekton Task result file utilities."""

from __future__ import annotations

from pathlib import Path


def write_tekton_result(results_dir: Path | None, name: str, value: str) -> None:
    """Write a Tekton result file if results_dir is configured."""
    if results_dir is None:
        return
    results_dir.mkdir(parents=True, exist_ok=True)
    result_file = results_dir / name
    result_file.write_text(value)
