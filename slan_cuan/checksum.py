"""Digest and checksum file utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_checksum(file_path: Path | str, algorithm: str) -> str:
    """Compute hex digest for a file using the given algorithm."""
    buf_size = 65536
    if algorithm == "md5":
        h = hashlib.md5(usedforsecurity=False)
    elif algorithm == "sha1":
        h = hashlib.sha1(usedforsecurity=False)
    elif algorithm == "sha256":
        h = hashlib.sha256()
    else:
        h = hashlib.new(algorithm)

    with open(file_path, "rb") as f:
        while chunk := f.read(buf_size):
            h.update(chunk)
    return h.hexdigest()


def write_checksum_sidecars(
    file_path: Path, algorithms: tuple[str, ...] = ("md5", "sha1", "sha256")
) -> list[Path]:
    """Write .md5, .sha1, .sha256 checksum sidecars next to file_path."""
    created: list[Path] = []
    for algo in algorithms:
        sidecar = file_path.with_name(f"{file_path.name}.{algo}")
        digest_val = compute_checksum(file_path, algo)
        sidecar.write_text(digest_val, encoding="utf-8")
        created.append(sidecar)
    return created
