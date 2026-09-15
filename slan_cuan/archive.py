"""Archive utilities with path traversal protection."""

from __future__ import annotations

import zipfile
from pathlib import Path


def extract_zip_safely(zip_path: str | Path, dest_dir: str | Path) -> None:
    """Extract a zip archive safely, preventing zip-slip path traversal.

    Raises ValueError if any archive member targets outside dest_dir.
    """
    dest = Path(dest_dir).resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target_path = (dest / member.filename).resolve()
            if not (target_path == dest or target_path.is_relative_to(dest)):
                raise ValueError(
                    "Zip-slip path traversal attempt detected: "
                    + member.filename
                )
        zf.extractall(dest)
