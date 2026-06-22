"""Shared context objects for the CLI group."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GlobalContext:
    """Immutable context passed from the Click group to all subcommands."""

    verbose: bool
    dry_run: bool
    ca_cert: Path | None
