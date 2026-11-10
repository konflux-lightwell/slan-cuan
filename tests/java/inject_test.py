"""Tests for the inject-sboms subcommand (LWLP-4822)."""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from slan_cuan.cli import main
from tests.integrity._yaml_helpers import get_run_step, load_task_yaml

_GAV = "org/apache/zookeeper/zookeeper/3.8.3.rhlw-00015"
_SBOM_REL = f"{_GAV}/zookeeper-3.8.3.rhlw-00015.bom.json"
_JUTE_REL = (
    "org/apache/zookeeper/zookeeper-jute/3.8.3.rhlw-00015/"
    "zookeeper-jute-3.8.3.rhlw-00015.bom.json"
)
_PREFIX = "build-output/repository/"
_ENRICHED = b'{"bomFormat": "CycloneDX", "enriched": true}\n'


def _make_zip(path: Path, extra: dict[str, bytes] | None = None) -> None:
    """Write a zip modelled on the zookeeper release (mixed methods/attrs)."""
    entries = {
        f"{_PREFIX}{_SBOM_REL}": b'{"bomFormat": "CycloneDX", "pnc": true}',
        f"{_PREFIX}{_SBOM_REL}.sha256": b"stale",
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015.jar": os.urandom(4096),
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015-cyclonedx.json": b"{}",
        f"{_PREFIX}{_GAV}/zookeeper-3.8.3.rhlw-00015.pom": b"<project/>",
        f"{_PREFIX}{_JUTE_REL}": b'{"bomFormat": "CycloneDX", "jute": true}',
        **(extra or {}),
    }
    with zipfile.ZipFile(path, "w") as zf:
        zf.comment = b"pnc build-output"
        dir_info = zipfile.ZipInfo(_PREFIX, date_time=(2026, 11, 9, 0, 49, 30))
        dir_info.external_attr = 0o40755 << 16 | 0x10
        zf.writestr(dir_info, b"")
        for i, (name, data) in enumerate(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 9, 0, 49, i))
            info.compress_type = (
                zipfile.ZIP_STORED
                if name.endswith(".jar")
                else zipfile.ZIP_DEFLATED
            )
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)


def _write_enriched(
    enriched_dir: Path, rel: str, data: bytes = _ENRICHED
) -> None:
    target = enriched_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _contents(zip_path: Path) -> list[tuple[str, bytes]]:
    with zipfile.ZipFile(zip_path) as zf:
        return [(i.filename, zf.read(i)) for i in zf.infolist()]


def _meta(zip_path: Path) -> list[tuple]:
    with zipfile.ZipFile(zip_path) as zf:
        return [
            (i.filename, i.date_time, i.compress_type, i.external_attr)
            for i in zf.infolist()
        ]


def _run(zip_path: Path, enriched_dir: Path, *global_opts: str):
    return CliRunner().invoke(
        main,
        [
            *global_opts,
            "inject-sboms",
            "--zip-path",
            str(zip_path),
            "--enriched-dir",
            str(enriched_dir),
        ],
    )


def test_replaces_only_the_matching_entry(tmp_path: Path) -> None:
    """The PNC SBOM entry gets the enriched content; all else is kept."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    before, before_meta = _contents(zip_path), _meta(zip_path)
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert "Injected 1 enriched SBOM(s)" in result.output
    after = _contents(zip_path)
    # Same entries in the same order, with the same name, timestamp,
    # compression method and attributes; nothing added or removed.
    assert _meta(zip_path) == before_meta
    for (name, old), (_, new) in zip(before, after, strict=True):
        if name == f"{_PREFIX}{_SBOM_REL}":
            assert new == _ENRICHED
        else:
            assert new == old, name
    with zipfile.ZipFile(zip_path) as zf:
        assert zf.testzip() is None
        assert zf.comment == b"pnc build-output"
    assert not list(tmp_path.glob(".*inject-tmp"))


@pytest.mark.parametrize("prefix", ["", "x-maven-repository/maven-repository/"])
def test_any_zip_layout(tmp_path: Path, prefix: str) -> None:
    """The entry is found by GAV suffix, whatever the zip root is."""
    zip_path = tmp_path / "build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(f"{prefix}{_SBOM_REL}", b"pnc")
        zf.writestr(f"{prefix}{_GAV}/zookeeper-3.8.3.rhlw-00015.jar", b"jar")
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert dict(_contents(zip_path))[f"{prefix}{_SBOM_REL}"] == _ENRICHED


def test_no_enriched_sboms_passes_through(tmp_path: Path) -> None:
    """Without enriched SBOMs the zip file is untouched (byte-identical)."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    original = zip_path.read_bytes()

    result = _run(zip_path, tmp_path / "missing")

    assert result.exit_code == 0, result.output
    assert "unchanged" in result.output
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

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert "not injected" in result.output
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

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert zip_path.read_bytes() == original


def test_ambiguous_entries_fail(tmp_path: Path) -> None:
    """Two zip entries for one GAV fail instead of guessing."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path, extra={f"other/repository/{_SBOM_REL}": b"pnc"})
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 1
    assert "matches 2 zip entries" in result.output
    assert zip_path.read_bytes() == original


def test_suffix_match_is_on_path_boundaries(tmp_path: Path) -> None:
    """A longer group (xorg/apache/...) is not mistaken for org/apache/..."""
    zip_path = tmp_path / "build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(f"repository/x{_SBOM_REL}", b"pnc")
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert zip_path.read_bytes() == original


def test_dry_run_leaves_the_zip_untouched(tmp_path: Path) -> None:
    """--dry-run reports the replacement without writing."""
    zip_path = tmp_path / "build-output.zip"
    _make_zip(zip_path)
    original = zip_path.read_bytes()
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir, "--dry-run")

    assert result.exit_code == 0, result.output
    assert "would inject 1" in result.output
    assert zip_path.read_bytes() == original


def test_zip64_entries_are_preserved(tmp_path: Path) -> None:
    """A zip whose entries carry ZIP64 records is rewritten correctly."""
    zip_path = tmp_path / "build-output.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in ((f"repository/{_SBOM_REL}", b"pnc"), ("big", b"x")):
            with zf.open(name, "w", force_zip64=True) as dst:
                dst.write(data)
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 0, result.output
    assert _contents(zip_path) == [
        (f"repository/{_SBOM_REL}", _ENRICHED),
        ("big", b"x"),
    ]


def test_bad_zip_is_a_clean_error(tmp_path: Path) -> None:
    """A corrupt build-output.zip fails with a message, not a traceback."""
    zip_path = tmp_path / "build-output.zip"
    zip_path.write_bytes(b"not a zip")
    enriched_dir = tmp_path / "enriched-sboms"
    _write_enriched(enriched_dir, _SBOM_REL)

    result = _run(zip_path, enriched_dir)

    assert result.exit_code == 1
    assert "Cannot inject SBOMs" in result.output


def test_task_runs_the_cli_on_the_trusted_artifact_paths() -> None:
    """The Task step is a plain CLI call on the artifacts it unpacks."""
    task = load_task_yaml("slan-cuan-inject-sboms.yaml")
    run = get_run_step(task)
    assert run["args"] == ["inject-sboms"]
    assert "script" not in run
    env = {e["name"]: e["value"] for e in run["env"]}
    unpack = {
        s["name"]: next(p["value"] for p in s["params"] if p["name"] == "workDir")
        for s in task["spec"]["steps"]
        if s["name"].startswith("use-")
    }
    assert env["SLAN_CUAN_INJECT_SBOMS_ZIP_PATH"] == (
        f"{unpack['use-signing-artifact']}/build-output.zip"
    )
    assert env["SLAN_CUAN_INJECT_SBOMS_ENRICHED_DIR"] == (
        f"{unpack['use-security-metadata-artifact']}/enriched-sboms"
    )
