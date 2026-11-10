"""inject-sboms subcommand: put enriched SBOMs into build-output.zip (LWLP-4822).

Runs between generate-security-metadata and sign. Each enriched SBOM
(``<group path>/<artifactId>/<version>/<artifactId>-<version>.bom.json``)
replaces the PNC SBOM entry at the same GAV path inside the zip, wherever the
zip roots its repository. No entry is ever added or removed, so sign sees the
same archive with only the SBOM content changed.
"""

from __future__ import annotations

import os
import shutil
import struct
import zipfile
from pathlib import Path, PurePosixPath

import click

from slan_cuan.models import GlobalContext

_COPY_CHUNK = 1024 * 1024
_ZIP64_EXTRA_ID = 0x0001


def find_enriched_sboms(enriched_dir: Path) -> dict[str, Path]:
    """Return the GAV-shaped enriched SBOMs under *enriched_dir*, by rel path.

    CycloneDX VEX documents share the ``.bom.json`` suffix but are named
    ``CVE-<id>-<datetime>.bom.json`` / ``<datetime>.bom.json``; they never
    match ``<artifactId>-<version>.bom.json`` and are skipped.
    """
    if not enriched_dir.is_dir():
        return {}
    found: dict[str, Path] = {}
    for path in sorted(enriched_dir.rglob("*.bom.json")):
        rel = PurePosixPath(path.relative_to(enriched_dir).as_posix())
        if path.is_symlink() or not path.is_file():
            continue
        parts = rel.parts
        if len(parts) >= 4 and parts[-1] == f"{parts[-3]}-{parts[-2]}.bom.json":
            found[rel.as_posix()] = path
        else:
            click.echo(f"  Skipping non-SBOM {rel}")
    return found


def match_entry(names: list[str], rel: str) -> list[str]:
    """Return the zip entries holding *rel*, whatever prefix the zip uses.

    The match is on whole path segments: ``build-output/repository/<rel>``
    matches, ``.../xorg/apache/...`` does not match ``org/apache/...``.
    """
    return [n for n in names if n == rel or n.endswith(f"/{rel}")]


def _strip_zip64_extra(extra: bytes) -> bytes:
    """Drop the ZIP64 extra record; zipfile writes a fresh one when needed."""
    out = bytearray()
    i = 0
    while i + 4 <= len(extra):
        header_id, size = struct.unpack("<HH", extra[i : i + 4])
        record = extra[i : i + 4 + size]
        if header_id != _ZIP64_EXTRA_ID:
            out += record
        i += 4 + size
    return bytes(out)


def _clone_info(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    """Copy an entry's metadata: name, timestamp, method, attributes."""
    clone = zipfile.ZipInfo(info.filename, date_time=info.date_time)
    clone.compress_type = info.compress_type
    clone.comment = info.comment
    clone.extra = _strip_zip64_extra(info.extra)
    clone.create_system = info.create_system
    clone.create_version = info.create_version
    clone.external_attr = info.external_attr
    clone.internal_attr = info.internal_attr
    return clone


def _rewrite(source: Path, target: Path, replacements: dict[str, bytes]) -> None:
    """Write *source* to *target*, replacing the content of some entries.

    Every entry keeps its name, order, timestamp, compression method and
    attributes; only the entries in *replacements* get new content.
    """
    with zipfile.ZipFile(source) as zin, zipfile.ZipFile(target, "w") as zout:
        zout.comment = zin.comment
        for info in zin.infolist():
            clone = _clone_info(info)
            if info.is_dir():
                zout.writestr(clone, b"")
            elif info.filename in replacements:
                zout.writestr(clone, replacements[info.filename])
            else:
                with (
                    zin.open(info) as src,
                    zout.open(
                        clone,
                        "w",
                        force_zip64=info.file_size > zipfile.ZIP64_LIMIT,
                    ) as dst,
                ):
                    shutil.copyfileobj(src, dst, _COPY_CHUNK)


def _verify(
    original_names: list[str], target: Path, replacements: dict[str, bytes]
) -> None:
    """Check the rewritten zip: same entries in order, CRCs, new content."""
    with zipfile.ZipFile(target) as zf:
        if zf.namelist() != original_names:
            raise click.ClickException(
                "Rewritten build-output.zip does not have the original entries"
            )
        bad = zf.testzip()
        if bad is not None:
            raise click.ClickException(f"Rewritten zip entry is corrupt: {bad}")
        for name, data in replacements.items():
            if zf.read(name) != data:
                raise click.ClickException(f"Injected entry mismatch: {name}")


def inject_enriched_sboms(
    zip_path: Path, enriched_dir: Path, dry_run: bool = False
) -> int:
    """Replace PNC SBOM entries in *zip_path* with the enriched SBOMs.

    An enriched SBOM without a matching entry is skipped (never added); an
    SBOM matching several entries is an error. Returns the number of
    entries replaced; the zip is untouched when nothing matches.
    """
    sboms = find_enriched_sboms(enriched_dir)
    if not sboms:
        click.echo("No enriched SBOMs to inject; build-output.zip unchanged")
        return 0

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()

    replacements: dict[str, bytes] = {}
    for rel, path in sboms.items():
        matches = match_entry(names, rel)
        if not matches:
            click.echo(
                f"WARNING: no {rel} entry in build-output.zip; not injected",
                err=True,
            )
            continue
        if len(matches) > 1:
            raise click.ClickException(
                f"{rel} matches {len(matches)} zip entries: {', '.join(matches)}"
            )
        entry = matches[0]
        entry_path = PurePosixPath(entry)
        if entry_path.is_absolute() or ".." in entry_path.parts:
            raise click.ClickException(f"Unsafe zip entry name: {entry}")
        replacements[entry] = path.read_bytes()
        click.echo(f"  Replacing {entry}")

    if not replacements:
        click.echo("No matching SBOM entries; build-output.zip unchanged")
        return 0
    if dry_run:
        click.echo(f"Dry run: would inject {len(replacements)} enriched SBOM(s)")
        return len(replacements)

    tmp = zip_path.with_name(f".{zip_path.name}.inject-tmp")
    try:
        _rewrite(zip_path, tmp, replacements)
        _verify(names, tmp, replacements)
        os.replace(tmp, zip_path)
    finally:
        tmp.unlink(missing_ok=True)

    click.echo(
        f"Injected {len(replacements)} enriched SBOM(s) into {zip_path.name}"
    )
    return len(replacements)


@click.command(name="inject-sboms")
@click.option(
    "--zip-path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="build-output.zip from extract (updated in place).",
)
@click.option(
    "--enriched-dir",
    required=True,
    type=click.Path(file_okay=False, path_type=Path),
    help=(
        "enriched-sboms/ directory written by generate-security-metadata. "
        "A missing directory means nothing to inject."
    ),
)
@click.pass_obj
def inject_sboms(ctx: GlobalContext, zip_path: Path, enriched_dir: Path) -> None:
    """Inject enriched SBOMs into build-output.zip before signing."""
    try:
        inject_enriched_sboms(zip_path, enriched_dir, dry_run=ctx.dry_run)
    except (zipfile.BadZipFile, OSError) as e:
        raise click.ClickException(f"Cannot inject SBOMs: {e}") from e
