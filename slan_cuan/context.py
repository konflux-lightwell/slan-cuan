"""Shared context objects for the CLI group."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GlobalContext:
    """Immutable context passed from the Click group to all subcommands."""

    verbose: bool
    dry_run: bool
    ca_cert: Path | None
    tekton_results_dir: Path | None


def write_tekton_result(results_dir: Path | None, name: str, value: str) -> None:
    """Write a Tekton result file if results_dir is configured."""
    if results_dir is None:
        return
    results_dir.mkdir(parents=True, exist_ok=True)
    result_file = results_dir / name
    result_file.write_text(value)
