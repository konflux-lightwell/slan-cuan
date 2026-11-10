"""Run the slan-cuan-inject-sboms Task script against real zip files.

The script is taken verbatim from the Task YAML (LWLP-4822), so these tests
exercise exactly what runs in the pipeline.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from tests.integrity._yaml_helpers import load_task_yaml

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("bash", "zip", "unzip")),
    reason="bash, zip and unzip are required",
)

_GAV = "org/apache/zookeeper/zookeeper/3.8.3.rhlw-00015"
_SBOM_REL = f"{_GAV}/zookeeper-3.8.3.rhlw-00015.bom.json"
_JUTE_REL = (
    "org/apache/zookeeper/zookeeper-jute/3.8.3.rhlw-00015/"
    "zookeeper-jute-3.8.3.rhlw-00015.bom.json"
)
_PREFIX = "build-output/repository/"
_ENRICHED = b'{"bomFormat": "CycloneDX", "enriched": true}\n'


def _script() -> str:
    task = load_task_yaml("slan-cuan-inject-sboms.yaml")
    step = next(
        s for s in task["spec"]["steps"] if s["name"] == "inject-enriched-sboms"
    )
    return step["script"]


def _make_zip(path: Path, extra: dict[str, bytes] | None = None) -> None:
    entries = {
        f"{_PREFIX}{_SBOM_REL}": b'{"bomFormat": "CycloneDX", "pnc": true}',
        f"{_PREFIX}{_SBOM_REL}.sha256": b"stale",
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015.jar": os.urandom(4096),
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015-cyclonedx.json": b"{}",
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015.pom": b"<project/>",
        f"{_PREFIX}{_JUTE_REL}": b'{"bomFormat": "CycloneDX", "jute": true}',
        **(extra or {}),
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def _run(tmp_path: Path, zip_path: Path, enriched_dir: Path):
    script = tmp_path / "inject.sh"
    script.write_text(_script())
    env = {**os.environ, "ZIP": str(zip_path), "ENRICHED_DIR": str(enriched_dir)}
    return subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True
    )


def _write_enriched(enriched_dir: Path, rel: str, data: bytes = _ENRICHED):
    target = enriched_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _contents(zip_path: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(zip_path) as zf:
        return [(i.filename, zf.read(i)) for i in zf.infolist()]


def test_replaces_only_the_matching_entry(tmp_path: Path) -> None:
    """The PNC SBOM entry is replaced in place; all else is unchanged."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    before = _contents(zip_path)
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 0, result.stderr
    assert "Injected 1 enriched SBOM(s)" in result.stdout
    after = _contents(zip_path)
    # Same entries, same order, no additions (no directory entries either).
    assert [n for n, _ in after] == [n for n, _ in before]
    for (name, old), (_, new) in zip(before, after, strict=True):
        if name == f"{_PREFIX}{_SBOM_REL}":
            assert new == _ENRICHED
        else:
            assert new == old, name
    with zipfile.ZipFile(zip_path) as zf:
        assert zf.testzip() is None


@pytest.mark.parametrize("prefix", ["", "x-maven-repository/maven-repository/"])
def test_any_zip_layout(tmp_path: Path, prefix: str) -> None:
    """The entry is found by GAV suffix, whatever the zip root is."""
    zip_path = tmp_path / "build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(f"{prefix}{_SBOM_REL}", b"pnc")
        zf.writestr(f"{prefix}{_GAV}/zookeeper-3.8.3.rhlw-00015.jar", b"jar")
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 0, result.stderr
    assert dict(_contents(zip_path))[f"{prefix}{_SBOM_REL}"] == _ENRICHED


def test_no_enriched_sboms_passes_through(tmp_path: Path) -> None:
    """Without enriched SBOMs the zip file is untouched (byte-identical)."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    original = zip_path.read_bytes()

    result = _run(tmp_path, zip_path, tmp_path / "missing")

    assert result.returncode == 0, result.stderr
    assert "passing through" in result.stdout
    assert zip_path.read_bytes() == original


def test_sbom_without_zip_entry_is_not_added(tmp_path: Path) -> None:
    """An enriched SBOM with no PNC entry in the zip is never added."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(
        enriched_dir,
        "org/example/other/1.0.rhlw-00001/other-1.0.rhlw-00001.bom.json",
    )

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 0, result.stderr
    assert "not injected" in result.stderr
    assert zip_path.read_bytes() == original


def test_vex_documents_are_never_injected(tmp_path: Path) -> None:
    """VEX files (.bom.json, not GAV-shaped) are skipped."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(
        enriched_dir, f"{_GAV}/CVE-2026-0001-2026-11-10T00:00:00Z.bom.json"
    )
    _write_enriched(enriched_dir, f"{_GAV}/2026-11-10T00:00:00Z.bom.json")

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 0, result.stderr
    assert zip_path.read_bytes() == original


def test_ambiguous_entries_fail(tmp_path: Path) -> None:
    """Two zip entries for one GAV fail instead of guessing."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path, extra={f"other/repository/{_SBOM_REL}": b"pnc"})
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 1
    assert "matches 2 zip entries" in result.stderr
    assert zip_path.read_bytes() == original


def test_suffix_match_is_on_path_boundaries(tmp_path: Path) -> None:
    """A longer group (xorg/apache/...) is not mistaken for org/apache/..."""
    zip_path = tmp_path / "build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(f"repository/x{_SBOM_REL}", b"pnc")
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(tmp_path, zip_path, enriched_dir)

    assert result.returncode == 0, result.stderr
    assert zip_path.read_bytes() == original
