"""Tests for archive utilities and zip-slip path traversal prevention."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from slan_cuan.archive import extract_zip_safely


def test_extract_zip_safely_valid(tmp_path: Path) -> None:
    """Valid zip archives extract cleanly into the destination directory."""
    zip_path = tmp_path / "valid.zip"
    dest_path = tmp_path / "dest"
    dest_path.mkdir()

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("sub/dir/file.txt", "sample content")

    extract_zip_safely(zip_path, dest_path)
    extracted = dest_path / "sub" / "dir" / "file.txt"
    assert extracted.exists()
    assert extracted.read_text() == "sample content"


def test_extract_zip_safely_zip_slip(tmp_path: Path) -> None:
    """Archives with directory traversal sequences are rejected."""
    bad_zip = tmp_path / "malicious.zip"
    dest_path = tmp_path / "dest"
    dest_path.mkdir()

    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0")

    with pytest.raises(ValueError, match="Zip-slip path traversal attempt"):
        extract_zip_safely(bad_zip, dest_path)
