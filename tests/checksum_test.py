"""Tests for checksum calculation and sidecar file generation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from slan_cuan.checksum import compute_checksum, write_checksum_sidecars


def test_compute_checksum_algorithms(tmp_path: Path) -> None:
    """compute_checksum matches hashlib output across standard algorithms."""
    test_file = tmp_path / "data.bin"
    content = b"test artifact binary content 123456"
    test_file.write_bytes(content)

    assert compute_checksum(test_file, "md5") == hashlib.md5(
        content, usedforsecurity=False
    ).hexdigest()
    assert compute_checksum(test_file, "sha1") == hashlib.sha1(
        content, usedforsecurity=False
    ).hexdigest()
    assert compute_checksum(test_file, "sha256") == hashlib.sha256(
        content
    ).hexdigest()


def test_write_checksum_sidecars(tmp_path: Path) -> None:
    """write_checksum_sidecars creates valid .md5, .sha1, and .sha256 files."""
    test_file = tmp_path / "lib.jar"
    test_file.write_bytes(b"sample jar content")

    created = write_checksum_sidecars(test_file)
    assert len(created) == 3
    assert (tmp_path / "lib.jar.md5").exists()
    assert (tmp_path / "lib.jar.sha1").exists()
    assert (tmp_path / "lib.jar.sha256").exists()

    expected_sha256 = hashlib.sha256(b"sample jar content").hexdigest()
    assert (tmp_path / "lib.jar.sha256").read_text() == expected_sha256
